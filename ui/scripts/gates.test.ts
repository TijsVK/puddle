// SPDX-License-Identifier: GPL-3.0-or-later
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { advisories, judge } from "./audit.ts";
import { allowed, collect, render } from "./licences.ts";

describe("licence allowlist", () => {
  it("accepts the policy's licences and SPDX expressions covered by them", () => {
    for (const ok of [
      "MIT",
      "ISC",
      "Apache-2.0",
      "BSD-3-Clause",
      "0BSD",
      "(MIT OR GPL-2.0)",
      "(MIT AND ISC)",
    ]) {
      expect(allowed(ok), ok).toBe(true);
    }
  });

  it("refuses anything else, including one bad term of an AND", () => {
    for (const bad of [
      "MPL-2.0",
      "GPL-3.0-only",
      "UNLICENSED",
      "(MIT AND MPL-2.0)",
      "SEE LICENSE IN x",
    ]) {
      expect(allowed(bad), bad).toBe(false);
    }
  });
});

describe("collect and render", () => {
  const dir = mkdtempSync(join(tmpdir(), "licences-"));
  const make = (name: string, manifest: object, licence?: string) => {
    const d = join(dir, name);
    mkdirSync(d, { recursive: true });
    writeFileSync(
      join(d, "package.json"),
      JSON.stringify({ name, version: "1.0.0", ...manifest }),
    );
    if (licence !== undefined) writeFileSync(join(d, "LICENSE"), licence);
    return d;
  };

  it("collects text and flags missing or disallowed licences", () => {
    try {
      const good = make(
        "b-good",
        { license: "MIT", repository: { url: "git+https://example.test/b" } },
        "Permission is hereby granted\r\n",
      );
      const old = make("a-old", { licenses: [{ type: "ISC" }] }, "ISC text");
      const obj = make(
        "c-obj",
        { license: { type: "Apache-2.0" } },
        "Apache text",
      );
      const none = make("d-none", {}, "text");
      const mpl = make("e-mpl", { license: "MPL-2.0" }, "text");
      const nofile = make("f-nofile", { license: "MIT" });
      const over = make("g-over", {}, "MIT text");
      const { entries, problems } = collect(
        [good, old, obj, none, mpl, nofile, over, join(dir, "missing")],
        {
          "g-over@1.0.0": { licence: "MIT" },
        },
      );
      expect(entries.map((e: { name: string }) => e.name)).toEqual([
        "a-old",
        "b-good",
        "c-obj",
        "d-none",
        "e-mpl",
        "f-nofile",
        "g-over",
      ]);
      expect(problems.join("\n")).toContain(
        "d-none@1.0.0: no licence declared",
      );
      expect(problems.join("\n")).toContain(
        "e-mpl@1.0.0: licence MPL-2.0 is not on the allowlist",
      );
      expect(problems.join("\n")).toContain("f-nofile@1.0.0: no licence file");
      expect(problems.join("\n")).toContain("missing: no package.json");
      expect(problems.join("\n")).not.toContain("g-over");

      const text = render(entries.slice(0, 2));
      expect(text).toContain("a-old 1.0.0 (ISC)");
      expect(text).toContain("https://example.test/b");
      expect(text).not.toContain("\r");
      expect(text.endsWith("\n")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("audit", () => {
  const report = {
    vulnerabilities: {
      foo: {
        via: [
          {
            url: "https://github.com/advisories/GHSA-1",
            severity: "high",
            title: "bad",
          },
          "bar",
        ],
      },
      bar: {
        via: [
          {
            url: "https://github.com/advisories/GHSA-2",
            severity: "low",
            title: "meh",
          },
        ],
      },
    },
  };

  it("lists advisories by id and ignores transitive name-only entries", () => {
    expect(advisories(report).map((a: { id: string }) => a.id)).toEqual([
      "GHSA-1",
      "GHSA-2",
    ]);
    expect(advisories({})).toEqual([]);
  });

  it("fails what is not excepted, an expired exception, and reports unused ones", () => {
    const found = advisories(report).filter(
      (a: { severity: string }) => a.severity === "high",
    );
    expect(judge(found, [], "2026-10-07").failures).toHaveLength(1);
    expect(
      judge(found, [{ id: "GHSA-1", review_by: "2027-01-01" }], "2026-10-07"),
    ).toEqual({ failures: [], unused: [] });
    expect(
      judge(found, [{ id: "GHSA-1", review_by: "2026-01-01" }], "2026-10-07")
        .failures[0],
    ).toContain("expired");
    expect(
      judge([], [{ id: "GHSA-9", review_by: "2027-01-01" }], "2026-10-07")
        .unused,
    ).toEqual(["GHSA-9"]);
  });
});
