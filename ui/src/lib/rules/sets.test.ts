// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { builtIn, mine, systemHost } from "#lib/testing/fake-rule-sets.ts";
import {
  byReason,
  entryPattern,
  globalState,
  isOn,
  overrides,
  overridesLabel,
  setNameError,
  setsOnFor,
  stateFor,
  systemFor,
  systemScope,
  userSetNumber,
} from "./sets.ts";

describe("where a set is on (R-37)", () => {
  it("follows the workspace's switch, then every workspace's, then the default", () => {
    const set = builtIn("github", {
      global: true,
      overrides: [{ workspace: "api" as never, enabled: false }],
    });
    expect(isOn(set, "api")).toBe(false);
    expect(isOn(set, "web")).toBe(true);
    expect(isOn(set, null)).toBe(true);
    expect(isOn(builtIn("x"), "web")).toBe(false);
    expect(isOn(mine(1), "web")).toBe(true);
  });

  it("says the every-workspace state and where it comes from", () => {
    expect(globalState(builtIn("x"))).toBe("Off (built-in sets ship off)");
    expect(globalState(mine(1))).toBe(
      "On for every workspace (new sets start on)",
    );
    expect(globalState(builtIn("x", { global: true }))).toBe(
      "On for every workspace",
    );
    expect(globalState(mine(1, { global: false }))).toBe(
      "Off for every workspace",
    );
  });

  it("names the workspaces that switch it for themselves", () => {
    const set = mine(1, {
      overrides: [
        { workspace: "api" as never, enabled: false },
        { workspace: "web" as never, enabled: true },
      ],
    });
    expect(overridesLabel(set)).toBe("off in api; on in web");
    expect(stateFor(set, "api")).toBe("Off here");
    expect(stateFor(set, "web")).toBe("On here");
    expect(stateFor(set, "other")).toBe("On, as for every workspace");
    expect(stateFor(builtIn("x"), "other")).toBe("Off, as for every workspace");
    expect(overrides(set, "api")).toBe(true);
    expect(overrides(set, "other")).toBe(false);
  });

  it("offers only your sets that are on for the workspace", () => {
    const sets = [
      builtIn("github", { global: true }),
      mine(1),
      mine(2, { overrides: [{ workspace: "api" as never, enabled: false }] }),
    ];
    expect(setsOnFor(sets, "api").map((s) => s.id)).toEqual(["user:1"]);
    expect(setsOnFor(sets, "web").map((s) => s.id)).toEqual([
      "user:1",
      "user:2",
    ]);
  });
});

describe("how entries and hosts read", () => {
  it("writes a suffix with a star, whatever form it came in", () => {
    expect(
      entryPattern({ pattern: ".example.com", pattern_kind: "suffix" }),
    ).toBe("*.example.com");
    expect(
      entryPattern({ pattern: "example.com", pattern_kind: "suffix" }),
    ).toBe("*.example.com");
    expect(
      entryPattern({ pattern: "*.example.com", pattern_kind: "suffix" }),
    ).toBe("*.example.com");
    expect(entryPattern({ pattern: "a.example", pattern_kind: "exact" })).toBe(
      "a.example",
    );
  });

  it("knows the number of a set you made", () => {
    expect(userSetNumber({ id: "user:12" })).toBe(12);
    expect(userSetNumber({ id: "builtin:github" })).toBe(null);
  });

  it("groups System managed hosts by reason and workspace (R-40)", () => {
    const hosts = [
      systemHost("open-vsx.org"),
      systemHost("marketplace.visualstudio.com", {
        reason: "direct_ssh",
        reason_text: "Direct SSH is on.",
        workspace: "ssh" as never,
      }),
      systemHost("openvsx.eclipsecontent.org"),
    ];
    const groups = byReason(hosts);
    expect(groups.map((g) => [g.reason, g.workspace, g.hosts.length])).toEqual([
      ["code_server", null, 2],
      ["direct_ssh", "ssh", 1],
    ]);
    expect(systemScope(groups[0] ?? { workspace: null })).toBe(
      "Every workspace",
    );
    expect(systemScope({ workspace: "ssh" as never })).toBe("ssh");
    expect(systemFor(hosts, "web").map((h) => h.pattern)).toEqual([
      "open-vsx.org",
      "openvsx.eclipsecontent.org",
    ]);
    expect(systemFor(hosts, "ssh")).toHaveLength(3);
  });
});

describe("a set's name", () => {
  it("needs 1 to 64 characters", () => {
    expect(setNameError("  ")).toBe("Give the rule set a name.");
    expect(setNameError("x".repeat(65))).toBe(
      "A name is at most 64 characters.",
    );
    expect(setNameError(" Work ")).toBe(null);
  });
});
