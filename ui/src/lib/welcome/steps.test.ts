// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { around, isWelcome, STEPS, stepFor } from "./steps.ts";

describe("first-run steps", () => {
  it("run welcome, check, certificates, connect, look, first workspace", () => {
    expect(STEPS.map((s) => s.id)).toEqual([
      "welcome",
      "check",
      "certificates",
      "connect",
      "look",
      "workspace",
    ]);
  });

  it("recognise the flow's paths and nothing else", () => {
    expect(isWelcome("/welcome")).toBe(true);
    expect(isWelcome("/welcome/check")).toBe(true);
    expect(isWelcome("/welcomed")).toBe(false);
    expect(isWelcome("/workspaces")).toBe(false);
  });

  it("find a step by path, with or without a trailing slash", () => {
    expect(stepFor("/welcome")?.id).toBe("welcome");
    expect(stepFor("/welcome/")?.id).toBe("welcome");
    expect(stepFor("/welcome/look/")?.id).toBe("look");
    expect(stepFor("/welcome/nope")).toBeUndefined();
    expect(stepFor("/")).toBeUndefined();
  });

  it("know the neighbours of each step", () => {
    expect(around("welcome")).toEqual({
      back: undefined,
      next: "/welcome/check",
    });
    expect(around("connect")).toEqual({
      back: "/welcome/certificates",
      next: "/welcome/look",
    });
    expect(around("workspace")).toEqual({
      back: "/welcome/look",
      next: undefined,
    });
  });
});
