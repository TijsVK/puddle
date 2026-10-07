// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { absoluteTime, relativeTime } from "./relative-time.ts";

const now = Date.UTC(2026, 9, 7, 12, 0, 0);

describe("relativeTime", () => {
  it.each([
    [0, "just now"],
    [-9_000, "just now"],
    [-30_000, "30 seconds ago"],
    [-60_000, "1 minute ago"],
    [-5 * 60_000, "5 minutes ago"],
    [-3_600_000, "1 hour ago"],
    [-3 * 3_600_000, "3 hours ago"],
    [-86_400_000, "yesterday"],
    [-3 * 86_400_000, "3 days ago"],
    [2 * 3_600_000, "in 2 hours"],
  ])("%d ms from now reads %s", (offset, text) => {
    expect(relativeTime(now + offset, now, "en")).toBe(text);
  });

  it("uses the OS locale by default", () => {
    expect(relativeTime(now - 120_000, now)).toEqual(expect.any(String));
  });
});

describe("absoluteTime", () => {
  it("has date and time", () => {
    expect(absoluteTime(now, "en-GB")).toMatch(/7 Oct 2026/);
  });
});
