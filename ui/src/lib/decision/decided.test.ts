// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  decidedPattern,
  decidedSentence,
  expiryPhrase,
  type Decided,
} from "./decided.ts";

const base: Decided = {
  ruleId: 1,
  effect: "allow",
  pattern: "example.com",
  patternKind: "exact",
  workspace: "demo",
  ruleSet: null,
  expiresAt: null,
  alsoClosed: 0,
  at: 0,
};

describe("decided wording", () => {
  it("shows an exact host as it is and a suffix rule as *.domain, with or without the dot", () => {
    expect(decidedPattern(base)).toBe("example.com");
    expect(
      decidedPattern({ pattern: ".example.com", patternKind: "suffix" }),
    ).toBe("*.example.com");
    expect(
      decidedPattern({ pattern: "example.com", patternKind: "suffix" }),
    ).toBe("*.example.com");
  });

  it("says permanently, or until the expiry", () => {
    expect(expiryPhrase(null)).toBe("permanently");
    expect(expiryPhrase(Date.UTC(2026, 9, 7, 12, 0), "en-GB")).toMatch(
      /^until 7 Oct 2026/,
    );
  });

  it("reads as a sentence for either effect and scope", () => {
    expect(decidedSentence(base)).toBe(
      "Allowed example.com for workspace demo, permanently",
    );
    expect(
      decidedSentence({
        ...base,
        effect: "deny",
        workspace: null,
        patternKind: "suffix",
        pattern: ".x.org",
      }),
    ).toBe("Denied *.x.org for every workspace, permanently");
  });
});

describe("a decision into a rule set", () => {
  it("names the set instead of a workspace", () => {
    expect(
      decidedSentence({ ...base, workspace: null, ruleSet: "Client X" }),
    ).toBe("Allowed example.com in rule set Client X, permanently");
  });
});
