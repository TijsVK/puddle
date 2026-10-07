// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { rule } from "#lib/testing/fake-rules.ts";
import {
  DEFAULT_SORT,
  EXPIRY_OPTIONS,
  NO_FILTER,
  expiryFrom,
  isExpired,
  matches,
  patternLabel,
  ruleName,
  scopeLabel,
  sentence,
  view,
  workspaceNameError,
  workspacesIn,
} from "./model.ts";

const NOW = 10_000_000;

const set = [
  rule(1, { pattern: "a.example.com", created_at: 100 }),
  rule(2, {
    pattern: ".example.org",
    pattern_kind: "suffix",
    effect: "deny",
    scope: { type: "sandbox", sandbox: "shop" as never },
    expires_at: NOW + 1000,
    created_at: 300,
  }),
  rule(3, {
    pattern: "b.example.net",
    scope: { type: "sandbox", sandbox: "docs" as never },
    expires_at: NOW - 1,
    created_at: 200,
  }),
];

describe("reading a rule", () => {
  it("names the pattern, the workspace and the expiry state", () => {
    expect(patternLabel(set[0]!)).toBe("a.example.com");
    expect(patternLabel(set[1]!)).toBe("*.example.org");
    expect(patternLabel({ pattern: "x.org", pattern_kind: "suffix" })).toBe(
      "*.x.org",
    );
    expect(scopeLabel(set[0]!)).toBe("Every workspace");
    expect(scopeLabel(set[1]!)).toBe("shop");
    expect(ruleName(set[1]!)).toBe("deny *.example.org for workspace shop");
    expect(ruleName(set[0]!)).toBe("allow a.example.com for every workspace");
    expect(isExpired(set[0]!, NOW)).toBe(false);
    expect(isExpired(set[1]!, NOW)).toBe(false);
    expect(isExpired(set[2]!, NOW)).toBe(true);
    expect(isExpired({ expires_at: NOW }, NOW)).toBe(true);
  });
});

describe("filtering", () => {
  const keep = (over: Partial<typeof NO_FILTER>) =>
    set
      .filter((r) => matches(r, { ...NO_FILTER, ...over }, NOW))
      .map((r) => r.id);

  it("keeps everything with no filter", () => {
    expect(keep({})).toEqual([1, 2, 3]);
  });
  it("matches the host as a case-insensitive substring of the pattern", () => {
    expect(keep({ host: "EXAMPLE.o" })).toEqual([2]);
    expect(keep({ host: "  b.ex " })).toEqual([3]);
    expect(keep({ host: "nothing" })).toEqual([]);
  });
  it("filters by workspace or by every workspace", () => {
    expect(keep({ scope: "global" })).toEqual([1]);
    expect(keep({ scope: "shop" })).toEqual([2]);
    expect(keep({ scope: "none" })).toEqual([]);
  });
  it("filters by effect and by state", () => {
    expect(keep({ effect: "deny" })).toEqual([2]);
    expect(keep({ effect: "allow" })).toEqual([1, 3]);
    expect(keep({ state: "expired" })).toEqual([3]);
    expect(keep({ state: "active" })).toEqual([1, 2]);
  });
  it("combines the filters", () => {
    expect(keep({ effect: "allow", state: "active" })).toEqual([1]);
  });
});

describe("sorting", () => {
  const ids = (key: Parameters<typeof view>[2]) =>
    view(set, NO_FILTER, key, NOW).map((r) => r.id);

  it("defaults to newest first", () => {
    expect(ids(DEFAULT_SORT)).toEqual([2, 3, 1]);
  });
  it("sorts every column both ways", () => {
    expect(ids({ key: "created", direction: "asc" })).toEqual([1, 3, 2]);
    expect(ids({ key: "pattern", direction: "asc" })).toEqual([2, 1, 3]);
    expect(ids({ key: "effect", direction: "asc" })).toEqual([1, 3, 2]);
    expect(ids({ key: "effect", direction: "desc" })).toEqual([2, 3, 1]);
    expect(ids({ key: "scope", direction: "asc" })).toEqual([3, 1, 2]);
  });
  it("puts permanent rules after expiring ones when ascending", () => {
    expect(ids({ key: "expires", direction: "asc" })).toEqual([3, 2, 1]);
    expect(ids({ key: "expires", direction: "desc" })).toEqual([1, 2, 3]);
  });
  it("breaks ties by id so the order is stable", () => {
    const same = [rule(5, { created_at: 1 }), rule(4, { created_at: 1 })];
    expect(
      view(same, NO_FILTER, { key: "created", direction: "asc" }, NOW).map(
        (r) => r.id,
      ),
    ).toEqual([4, 5]);
  });
  it("does not change the input", () => {
    const before = set.map((r) => r.id);
    view(set, NO_FILTER, { key: "pattern", direction: "desc" }, NOW);
    expect(set.map((r) => r.id)).toEqual(before);
  });
});

describe("helpers", () => {
  it("lists the workspaces the rules name, once, sorted", () => {
    expect(workspacesIn(set)).toEqual(["docs", "shop"]);
    expect(workspacesIn([])).toEqual([]);
  });
  it("turns a duration into an epoch time", () => {
    expect(expiryFrom(NOW, null)).toBeNull();
    expect(expiryFrom(NOW, 3600)).toBe(NOW + 3_600_000);
    expect(EXPIRY_OPTIONS[0]?.secs).toBeNull();
  });
  it("checks a workspace name as the API does", () => {
    expect(workspaceNameError("")).toMatch(/name the workspace/i);
    expect(workspaceNameError("my-shop")).toBeNull();
    expect(workspaceNameError("a")).toBeNull();
    for (const bad of ["Shop", "-a", "a-", "a b", "a".repeat(64), "a.b"])
      expect(workspaceNameError(bad), bad).not.toBeNull();
  });
  it("shows the API's lower-case messages as sentences", () => {
    expect(sentence("invalid pattern")).toBe("Invalid pattern.");
    expect(sentence("Already.")).toBe("Already.");
    expect(sentence("  ")).toBe("");
  });
});
