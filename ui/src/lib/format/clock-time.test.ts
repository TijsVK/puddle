// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { clockTime, startOfDay } from "./clock-time.ts";

describe("clockTime", () => {
  const noon = new Date(2026, 9, 7, 12, 30, 5).getTime();
  const dayStart = startOfDay(noon);
  it("finds the start of the local day", () => {
    expect(new Date(dayStart).getHours()).toBe(0);
    expect(new Date(dayStart).getDate()).toBe(7);
    expect(startOfDay(dayStart)).toBe(dayStart);
  });
  it("prints today's moments as a time", () => {
    expect(clockTime(noon, dayStart, "en-GB")).toBe("12:30:05");
    expect(clockTime(dayStart, dayStart, "en-GB")).toBe("00:00:00");
  });
  it("adds the date before today", () => {
    expect(clockTime(dayStart - 1000, dayStart, "en-GB")).toBe(
      "6 Oct, 23:59:59",
    );
    expect(clockTime(dayStart - 1000, dayStart, "en-US")).toBe(
      "Oct 6, 11:59:59 PM",
    );
  });
  it("uses the OS locale when none is given", () => {
    expect(clockTime(noon, dayStart)).toMatch(/12.30.05|0?0?12.30.05/);
  });
});
