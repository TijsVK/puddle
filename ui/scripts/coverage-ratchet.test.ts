// SPDX-License-Identifier: GPL-3.0-or-later
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { judge, main, readTotals, WOBBLE } from "./coverage-ratchet.ts";

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
    expect(v).toEqual({ failures: [], notes: [], raised: undefined });
  });

  it("compares the value as printed, two decimals, so 93.6996 meets a 93.7 baseline", () => {
    const v = judge(
      { lines: 93.6996, regions: 90.4 },
      { lines: 93.7, regions: 90.4 },
      floor,
      undefined,
      false,
    );
    expect(v.failures).toEqual([]);
  });

  it("fails more than the wobble below the baseline even when above the floor", () => {
    const v = judge(
      { lines: 93.0, regions: 90.5 },
      base,
      floor,
      undefined,
      false,
    );
    expect(v.failures).toEqual([
      "lines coverage 93.00 % is more than 0.05 points below the baseline 93.1 %",
    ]);
  });

  describe("the wobble allowance", () => {
    const at = (lines: number, regions = 90.4) =>
      judge({ lines, regions }, base, floor, undefined, false);

    it("is 0.05 points", () => {
      expect(WOBBLE).toBe(0.05);
    });

    it("passes 0.02 below the baseline and says so in one note", () => {
      const v = at(93.08);
      expect(v.failures).toEqual([]);
      expect(v.notes).toEqual([
        "lines coverage 93.08 % is below the baseline 93.1 % by 0.02 points, within the allowed wobble of 0.05 points",
      ]);
      expect(v.raised).toBeUndefined();
    });

    it("passes exactly 0.05 below the baseline", () => {
      const v = at(93.05);
      expect(v.failures).toEqual([]);
      expect(v.notes).toHaveLength(1);
      expect(v.notes[0]).toContain("by 0.05 points");
    });

    it("fails 0.06 below the baseline", () => {
      const v = at(93.04);
      expect(v.failures).toEqual([
        "lines coverage 93.04 % is more than 0.05 points below the baseline 93.1 %",
      ]);
      expect(v.notes).toEqual([]);
    });

    it("compares the printed value: 93.0451 prints 93.05 and passes, 93.0449 prints 93.04 and fails", () => {
      expect(at(93.0451).failures).toEqual([]);
      expect(at(93.0449).failures).toHaveLength(1);
    });

    it("applies to regions as well, each total on its own", () => {
      const v = at(93.1, 90.35);
      expect(v.failures).toEqual([]);
      expect(v.notes).toEqual([
        "regions coverage 90.35 % is below the baseline 90.4 % by 0.05 points, within the allowed wobble of 0.05 points",
      ]);
      expect(at(93.1, 90.34).failures).toEqual([
        "regions coverage 90.34 % is more than 0.05 points below the baseline 90.4 %",
      ]);
    });

    it("says nothing at or above the baseline", () => {
      expect(at(93.1).notes).toEqual([]);
      expect(at(93.5).notes).toEqual([]);
    });

    it("has no allowance on the floor, even when the baseline sits on it", () => {
      const onFloor = { lines: 92, regions: 90 };
      const v = judge(
        { lines: 91.98, regions: 90 },
        onFloor,
        floor,
        undefined,
        false,
      );
      expect(v.failures).toEqual([
        "lines coverage 91.98 % is below the floor 92 %",
      ]);
      expect(v.notes).toEqual([]);
    });

    it("does not let the floor excuse a baseline above it", () => {
      const v = judge(
        { lines: 92.5, regions: 90.4 },
        base,
        floor,
        undefined,
        false,
      );
      expect(v.failures).toEqual([
        "lines coverage 92.50 % is more than 0.05 points below the baseline 93.1 %",
      ]);
    });

    it("never lowers the baseline: a wobble pass proposes nothing", () => {
      expect(at(93.06).raised).toBeUndefined();
    });
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

describe("main", () => {
  let dir: string;
  let out: string[];
  let err: string[];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "coverage-ratchet-"));
    out = [];
    err = [];
    vi.spyOn(console, "log").mockImplementation(
      (m: string) => void out.push(m),
    );
    vi.spyOn(console, "error").mockImplementation(
      (m: string) => void err.push(m),
    );
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (name: string, value: unknown) => {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(value));
    return path;
  };
  const run = (
    measured: { lines: number; regions: number },
    baseline: { lines: number; regions: number },
    extra: string[] = [],
  ) => {
    const summary = write("summary.json", {
      data: [
        {
          totals: {
            lines: { percent: measured.lines },
            regions: { percent: measured.regions },
          },
        },
      ],
    });
    const file = write("baseline.json", baseline);
    const code = main([
      ...["--summary", summary, "--baseline", file],
      ...["--floor-lines", "92", "--floor-regions", "90"],
      ...extra,
    ]);
    return { code, file, text: () => readFileSync(file, "utf8") };
  };
  const base = { lines: 93.1, regions: 90.4 };

  it("passes 0.02 below the baseline, logs one line saying so and leaves the baseline alone, --write or not", () => {
    for (const extra of [[], ["--write"]]) {
      out.length = 0;
      const r = run({ lines: 93.08, regions: 90.4 }, base, extra);
      expect(r.code).toBe(0);
      const said = out.filter((l) => l.includes("wobble"));
      expect(said).toEqual([
        "coverage ratchet: lines coverage 93.08 % is below the baseline 93.1 % by 0.02 points, within the allowed wobble of 0.05 points",
      ]);
      expect(JSON.parse(r.text())).toEqual(base);
      expect(err).toEqual([]);
    }
  });

  it("passes exactly 0.05 below the baseline", () => {
    expect(run({ lines: 93.05, regions: 90.4 }, base).code).toBe(0);
  });

  it("fails 0.06 below the baseline and does not write", () => {
    const r = run({ lines: 93.04, regions: 90.4 }, base, ["--write"]);
    expect(r.code).toBe(1);
    expect(err).toEqual([
      "coverage ratchet: lines coverage 93.04 % is more than 0.05 points below the baseline 93.1 %",
    ]);
    expect(out.some((l) => l.includes("wobble"))).toBe(false);
    expect(JSON.parse(r.text())).toEqual(base);
  });

  it("raises the baseline to the measured value, rounded down, with --write", () => {
    const r = run({ lines: 93.99, regions: 91.27 }, base, ["--write"]);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.text())).toEqual({ lines: 93.9, regions: 91.2 });
    expect(out.join("\n")).toContain("baseline raised to lines 93.9");
  });

  it("only says a raise is possible without --write", () => {
    const r = run({ lines: 93.99, regions: 91.27 }, base);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.text())).toEqual(base);
    expect(out.join("\n")).toContain("coverage is above the baseline");
  });

  it("still fails a lowered baseline without the owner's OK, wobble or not", () => {
    const previous = write("previous.json", base);
    const lowered = { lines: 93.0, regions: 90.4 };
    const measured = { lines: 93.0, regions: 90.4 };
    expect(run(measured, lowered, ["--previous", previous]).code).toBe(1);
    expect(err.join("\n")).toContain("baseline was lowered");
    vi.stubEnv("COVERAGE_BASELINE_LOWER_OK", "1");
    expect(run(measured, lowered, ["--previous", previous]).code).toBe(0);
  });

  it("refuses a call without its arguments", () => {
    expect(() => main([])).toThrow(/usage/);
  });
});
