// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  DETAIL_HEIGHT,
  ROW_HEIGHT,
  visibleRange,
  type WindowInput,
} from "./window.ts";

const base: WindowInput = {
  scrollTop: 0,
  viewportHeight: 360,
  rowCount: 1000,
  rowHeight: 36,
  overscan: 2,
  openIndex: -1,
  detailHeight: 100,
};

const total = (r: ReturnType<typeof visibleRange>, input: WindowInput) =>
  r.padTop +
  (r.end - r.start) * input.rowHeight +
  (input.openIndex >= r.start && input.openIndex < r.end
    ? input.detailHeight
    : 0) +
  r.padBottom;

describe("visibleRange", () => {
  it("draws nothing for an empty list", () => {
    expect(visibleRange({ ...base, rowCount: 0 })).toEqual({
      start: 0,
      end: 0,
      padTop: 0,
      padBottom: 0,
    });
  });
  it("draws the top rows, the viewport and the overscan, and pads the rest", () => {
    const r = visibleRange(base);
    expect(r).toEqual({
      start: 0,
      end: 13,
      padTop: 0,
      padBottom: (1000 - 13) * 36,
    });
  });
  it("moves with the scroll position and keeps the total height", () => {
    for (const scrollTop of [0, 35, 36, 5000, 35_000, 35_640, 99_999]) {
      const input = { ...base, scrollTop };
      const r = visibleRange(input);
      expect(r.start).toBeLessThanOrEqual(r.end);
      expect(total(r, input)).toBe(1000 * 36);
      expect(r.padTop).toBe(r.start * 36);
    }
    const mid = visibleRange({ ...base, scrollTop: 3600 });
    expect(mid.start).toBe(98);
    expect(mid.end).toBe(113);
  });
  it("clamps a negative scroll (rubber banding) and a scroll past the end", () => {
    expect(visibleRange({ ...base, scrollTop: -50 }).start).toBe(0);
    const end = visibleRange({ ...base, scrollTop: 10_000_000 });
    expect(end.end).toBe(1000);
    expect(end.padBottom).toBe(0);
  });
  it("accounts for the open row's detail above, inside and below the window", () => {
    for (const [openIndex, scrollTop] of [
      [5, 0],
      [5, 36 * 5 + 36 + 50],
      [5, 36 * 5 + 36 + 100 + 20],
      [5, 36 * 200],
      [990, 36 * 100],
      [2000, 0],
    ]) {
      const input = {
        ...base,
        openIndex: openIndex as number,
        scrollTop: scrollTop as number,
      };
      const r = visibleRange(input);
      const effective = {
        ...input,
        openIndex: input.openIndex < 1000 ? input.openIndex : -1,
      };
      expect(total(r, effective)).toBe(
        1000 * 36 + (effective.openIndex >= 0 ? 100 : 0),
      );
    }
  });
  it("keeps the open row drawn while its detail is on screen", () => {
    const input = { ...base, openIndex: 5, scrollTop: 36 * 5 + 36 + 60 };
    const r = visibleRange(input);
    expect(r.start).toBeLessThanOrEqual(5);
    expect(r.end).toBeGreaterThan(5);
  });
  it("has the heights the stylesheet uses", () => {
    expect(ROW_HEIGHT).toBe(36);
    expect(DETAIL_HEIGHT).toBe(280);
  });
});
