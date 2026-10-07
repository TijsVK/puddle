// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  cleanCheck,
  dirtyCheck,
  workspace,
} from "#lib/testing/fake-workspaces.ts";
import {
  MAX_NAME_LENGTH,
  canAttach,
  canDelete,
  canReclaim,
  canStart,
  canStop,
  diskLabel,
  formatMib,
  isDown,
  losses,
  nameProblem,
  operationLabel,
  parseMemoryGib,
  repoUrlProblem,
  sortWorkspaces,
  statusLabel,
  operationOfStep,
  statusTone,
  stepLabel,
  stepPosition,
  suggestName,
  type Status,
  type Step,
} from "./model.ts";

const STATUSES: Status[] = [
  "created",
  "starting",
  "running",
  "draining",
  "paused",
  "stopped",
  "crashed",
];

describe("what can be done in each state", () => {
  it("down states can start and delete, running can stop and attach, nothing else", () => {
    const table = STATUSES.map((status) => {
      const w = workspace("w", { status });
      return [
        status,
        canStart(w),
        canStop(w),
        canAttach(w),
        canDelete(w),
        canReclaim(w),
      ];
    });
    expect(table).toEqual([
      ["created", true, false, false, true, false],
      ["starting", false, false, false, false, false],
      ["running", false, true, true, false, true],
      ["draining", false, false, false, false, false],
      ["paused", false, false, false, false, false],
      ["stopped", true, false, false, true, true],
      ["crashed", true, false, false, true, false],
    ]);
    expect(STATUSES.filter(isDown)).toEqual(["created", "stopped", "crashed"]);
  });

  it("nothing is allowed while an operation runs", () => {
    for (const status of STATUSES) {
      const w = workspace("w", { status, busy: "reclaiming" });
      expect([
        canStart(w),
        canStop(w),
        canAttach(w),
        canDelete(w),
        canReclaim(w),
      ]).toEqual([false, false, false, false, false]);
    }
  });
});

describe("words", () => {
  it("has a label and a tone for every status", () => {
    for (const status of STATUSES) {
      expect(statusLabel(status)).not.toBe("");
      expect(["ok", "busy", "warn", "bad", "idle"]).toContain(
        statusTone(status),
      );
    }
    expect(statusLabel("created")).toBe("Not started");
    expect(statusTone("running")).toBe("ok");
    expect(statusTone("crashed")).toBe("bad");
  });

  it("has a label for every step and operation", () => {
    const steps: Step[] = [
      "preparing_volume",
      "pulling_image",
      "cloning",
      "starting",
      "syncing",
      "checking",
      "reclaiming",
      "stopping",
      "removing",
      "done",
      "failed",
    ];
    for (const step of steps) expect(stepLabel(step)).not.toBe("");
    expect(operationLabel("deleting")).toBe("Deleting");
  });

  it("tells the operation from a step alone", () => {
    expect(operationOfStep("cloning")).toBe("creating");
    expect(operationOfStep("syncing")).toBe("starting");
    expect(operationOfStep("stopping")).toBe("stopping");
    expect(operationOfStep("removing")).toBe("deleting");
    expect(operationOfStep("reclaiming")).toBe("reclaiming");
    expect(operationOfStep("done")).toBeNull();
    expect(operationOfStep("failed")).toBeNull();
  });

  it("places a step in its operation", () => {
    expect(stepPosition("creating", "cloning")).toEqual({ index: 3, of: 3 });
    expect(stepPosition("starting", "starting")).toEqual({ index: 1, of: 2 });
    expect(stepPosition("deleting", "removing")).toEqual({ index: 2, of: 2 });
    expect(stepPosition("reclaiming", "reclaiming")).toEqual({
      index: 1,
      of: 1,
    });
    expect(stepPosition("creating", "stopping")).toBeNull();
  });
});

describe("names", () => {
  it.each([
    ["web-shop", null],
    ["a", null],
    ["a1-b2", null],
    ["", "Give the workspace a name."],
    ["Web", "Use only lowercase letters, digits and hyphens."],
    ["a b", "Use only lowercase letters, digits and hyphens."],
    ["a_b", "Use only lowercase letters, digits and hyphens."],
    ["-a", "Start and end with a letter or digit."],
    ["a-", "Start and end with a letter or digit."],
    ["m--x", "Names starting with m-- are reserved for puddle's own use."],
    ["tauri", '"tauri" is reserved; pick another.'],
    ["ipc", '"ipc" is reserved; pick another.'],
    ["asset", '"asset" is reserved; pick another.'],
  ])("%j -> %j", (name, problem) => {
    expect(nameProblem(name)).toBe(problem);
  });

  it("allows the longest and refuses one more", () => {
    expect(nameProblem("a".repeat(MAX_NAME_LENGTH))).toBeNull();
    expect(nameProblem("a".repeat(MAX_NAME_LENGTH + 1))).toMatch(/at most 60/);
  });

  it("suggests a name from a repository URL", () => {
    expect(suggestName("https://github.com/acme/Ledger_Service.git")).toBe(
      "ledger-service",
    );
    expect(suggestName("https://github.com/acme/web-shop/")).toBe("web-shop");
    expect(suggestName("https://example.org/a/b.git?x=1#y")).toBe("b");
    expect(suggestName("")).toBe("");
    expect(suggestName("https://github.com/acme/___")).toBe("");
    expect(suggestName("https://github.com/acme/tauri.git")).toBe("");
    // Runs of punctuation collapse to one hyphen, so a suggestion never starts with the reserved m--.
    expect(suggestName("https://github.com/acme/m--x.git")).toBe("m-x");
    expect(suggestName(`https://h/${"x".repeat(80)}`)).toHaveLength(
      MAX_NAME_LENGTH,
    );
    expect(
      nameProblem(suggestName("https://github.com/acme/Ledger_Service.git")),
    ).toBeNull();
  });
});

describe("repository URLs", () => {
  const ssh =
    "SSH remotes are not supported yet; use the repository's HTTPS URL instead.";
  it.each([
    ["https://github.com/acme/web-shop.git", null],
    ["  https://github.com/acme/web-shop.git  ", null],
    ["HTTPS://GitHub.com/acme/x", null],
    ["https://host:8443/x.git", null],
    ["", "Enter the repository's HTTPS URL."],
    ["git@github.com:acme/web-shop.git", ssh],
    ["ssh://git@github.com/acme/x.git", ssh],
    ["github.com:acme/x.git", ssh],
    ["http://github.com/x.git", "Use an https:// URL."],
    ["ftp://x/y", "Use an https:// URL."],
    ["github.com/acme/x", "Use an https:// URL."],
    ["https://github.com/a b", "The URL must not contain spaces."],
    [
      "https://user:pw@github.com/x.git",
      "Remove the user name and password from the URL; puddle supplies credentials itself.",
    ],
    ["https://", "The URL has no host."],
    ["https:///x", "The URL has no host."],
    ["https://:8443/x", "The URL has no host."],
  ])("%j -> %j", (url, problem) => {
    expect(repoUrlProblem(url)).toBe(problem);
  });

  it("does not take a Windows drive letter for an SSH host", () => {
    expect(repoUrlProblem("C:/repos/x")).toBe("Use an https:// URL.");
  });
});

describe("memory", () => {
  it("reads GiB, rounding to MiB; empty means the default", () => {
    expect(parseMemoryGib("")).toEqual({ ok: true, mib: null });
    expect(parseMemoryGib("  ")).toEqual({ ok: true, mib: null });
    expect(parseMemoryGib("8")).toEqual({ ok: true, mib: 8192 });
    expect(parseMemoryGib("0.5")).toEqual({ ok: true, mib: 512 });
    expect(parseMemoryGib("1.5")).toEqual({ ok: true, mib: 1536 });
  });

  it("refuses text and sizes the API would refuse", () => {
    expect(parseMemoryGib("lots")).toEqual({
      ok: false,
      message: "Enter a number of GiB.",
    });
    expect(parseMemoryGib("0.1")).toEqual({
      ok: false,
      message: "Use between 0.25 GiB and 1024 GiB.",
    });
    expect(parseMemoryGib("2000").ok).toBe(false);
  });

  it("formats sizes", () => {
    expect(formatMib(512)).toBe("512 MiB");
    expect(formatMib(8192)).toBe("8 GiB");
    expect(formatMib(1536)).toBe("1.5 GiB");
  });

  it("says what the disk holds, or only its size when unknown", () => {
    expect(diskLabel(workspace("w", { disk_used_mib: 6144 }))).toBe(
      "6 GiB of 32 GiB used",
    );
    expect(diskLabel(workspace("w", { disk_used_mib: null }))).toBe(
      "32 GiB disk",
    );
  });
});

describe("the list", () => {
  it("sorts by name without touching the input", () => {
    const input = [workspace("b"), workspace("a"), workspace("c")];
    expect(sortWorkspaces(input).map((w) => w.name)).toEqual(["a", "b", "c"]);
    expect(input.map((w) => w.name)).toEqual(["b", "a", "c"]);
  });
});

describe("what a delete would lose", () => {
  it("is nothing for a clean check", () => {
    expect(losses(cleanCheck("w"))).toEqual([]);
  });

  it("lists each kind per repository, with how many more there are", () => {
    expect(losses(dirtyCheck("w"))).toEqual([
      {
        where: "w",
        what: "Uncommitted changes",
        items: [" M a.md", "?? b.md"],
        more: 3,
      },
      {
        where: "w",
        what: "Commits that are on no remote branch",
        items: ["abc123 Fix it"],
        more: 0,
      },
      {
        where: "Outside any repository",
        what: "Files",
        items: ["scratch"],
        more: 0,
      },
    ]);
  });

  it("counts a list that has only a remainder", () => {
    const check = cleanCheck("w", {
      clean: false,
      repos: [
        {
          dir: "r",
          clean: false,
          uncommitted: { items: [], more: 0 },
          unpushed: { items: [], more: 0 },
          stashes: { items: [], more: 2 },
        },
      ],
    });
    expect(losses(check)).toEqual([
      { where: "r", what: "Stashes", items: [], more: 2 },
    ]);
  });
});
