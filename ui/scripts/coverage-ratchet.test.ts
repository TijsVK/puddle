// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { judge, readTotals } from "./coverage-ratchet.ts";

const floor = { lines: 92, regions: 90 };

describe("readTotals", () => {
  it("reads the llvm-cov summary totals", () => {
    const json = JSON.stringify({
      data: [
        { totals: { lines: { percent: 93.5 }, regions: { percent: 91.25 } } },
      ],
    });
    expect(readTotals(json)).toEqual({ lines: 93.5, regions: 91.25 });
  });
  it("refuses a summary without totals", () => {
    expect(() => readTotals('{"data":[{"totals":{}}]}')).toThrow(/no lines/);
  });
});

describe("judge", () => {
  const base = { lines: 93.1, regions: 90.4 };

  it("passes at the baseline and proposes nothing", () => {
    const v = judge(
      { lines: 93.1, regions: 90.4 },
      base,
      floor,
      undefined,
      false,
    );
    expect(v).toEqual({ failures: [], raised: undefined });
  });

  it("fails below the baseline even when above the floor", () => {
    const v = judge(
      { lines: 93.0, regions: 90.5 },
      base,
      floor,
      undefined,
      false,
    );
    expect(v.failures).toEqual([
      "lines coverage 93.00 % is below the baseline 93.1 %",
    ]);
  });

  it("fails below the floor when the baseline is lower than the floor", () => {
    const v = judge(
      { lines: 91, regions: 95 },
      { lines: 80, regions: 80 },
      floor,
      undefined,
      false,
    );
    expect(v.failures).toEqual([
      "lines coverage 91.00 % is below the floor 92 %",
    ]);
  });

  it("proposes a baseline rounded down when coverage rose, never rounded up", () => {
    const v = judge(
      { lines: 93.99, regions: 90.4 },
      base,
      floor,
      undefined,
      false,
    );
    expect(v.raised).toEqual({ lines: 93.9, regions: 90.4 });
  });

  it("fails a lowered baseline unless the owner OK'd it", () => {
    const lowered = { lines: 92.5, regions: 90.4 };
    const prev = { lines: 93.1, regions: 90.4 };
    expect(
      judge({ lines: 94, regions: 91 }, lowered, floor, prev, false).failures,
    ).toHaveLength(1);
    expect(
      judge({ lines: 94, regions: 91 }, lowered, floor, prev, true).failures,
    ).toEqual([]);
  });
});
