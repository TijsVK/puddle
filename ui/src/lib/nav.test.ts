// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { documentTitle, NAV, sectionFor } from "./nav.ts";

describe("nav", () => {
  it("has the five sections of D-73, in order", () => {
    expect(NAV.map((n) => n.label)).toEqual([
      "Inbox",
      "Workspaces",
      "Rules",
      "Activity",
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
});
