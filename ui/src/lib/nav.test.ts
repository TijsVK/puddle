// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { documentTitle, NAV, sectionFor } from "./nav.ts";

describe("nav", () => {
  it("has the six top-level sections, in order", () => {
    expect(NAV.map((n) => n.label)).toEqual([
      "Workspaces",
      "Inbox",
      "Rules",
      "Activity",
      "Identities",
      "Settings",
    ]);
    expect(new Set(NAV.map((n) => n.href)).size).toBe(NAV.length);
  });

  it("finds the section of a path, including nested ones", () => {
    expect(sectionFor("/rules")?.label).toBe("Rules");
    expect(sectionFor("/workspaces/abc/network")?.label).toBe("Workspaces");
    expect(sectionFor("/rulesx")).toBeUndefined();
    expect(sectionFor("/")).toBeUndefined();
  });

  it("titles pages, with the pending count only on the inbox", () => {
    expect(documentTitle("/inbox", 0)).toBe("Inbox - puddle");
    expect(documentTitle("/inbox", 3)).toBe("Inbox (3) - puddle");
    expect(documentTitle("/rules", 3)).toBe("Rules - puddle");
    expect(documentTitle("/nope", 3)).toBe("Not found - puddle");
  });

  it("titles the first-run steps by their name, with no pending count", () => {
    expect(documentTitle("/welcome", 3)).toBe("Welcome - puddle");
    expect(documentTitle("/welcome/connect", 3)).toBe("Connect - puddle");
    expect(documentTitle("/welcome/unknown", 0)).toBe("Welcome - puddle");
  });
});
