// SPDX-License-Identifier: GPL-3.0-or-later
// The coverage ratchet (docs/STANDARDS.md, "Coverage"): the workspace's line and region coverage
// must stay at or above the floor (lines 92 %, regions 90 %) and at or above the committed baseline
// in scripts/coverage-baseline.json. The baseline only goes up: when coverage rises a local run
// writes the new value (rounded down to 0.1) for you to commit, and a change that lowers the
// committed baseline fails unless COVERAGE_BASELINE_LOWER_OK=1, which scripts/check.sh sets only
// when a commit of the change carries the trailer `Owner-OK: coverage-baseline`.
//
// Usage: node scripts/coverage-ratchet.ts --summary <llvm-cov json> --baseline <file>
//          --floor-lines 92 --floor-regions 90 [--previous <baseline json of the base commit>] [--write]
// `--summary` is `cargo llvm-cov report --json --summary-only` output. `--write` raises the baseline.
//
// What it can't see: it reads two totals, so a drop in one crate hidden by a gain in another passes
// (the diff-coverage gate is what catches new uncovered lines), and a green ratchet says nothing
// about how well the tests assert.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export interface Totals {
  lines: number;
  regions: number;
}

/** Reads the workspace totals out of `cargo llvm-cov report --json --summary-only`. */
export function readTotals(json: string): Totals {
  const t = (
    JSON.parse(json) as {
      data: { totals: Record<string, { percent: number }> }[];
    }
  ).data[0]?.totals;
  if (!t?.["lines"] || !t["regions"])
    throw new Error("summary has no lines/regions totals");
  return { lines: t["lines"].percent, regions: t["regions"].percent };
}

/** The value as printed (two decimals): what the gate compares, so a printed 93.70 meets a 93.7 baseline. */
const shown = (n: number) => Math.round(n * 100) / 100;
const down = (n: number) => Math.floor(n * 10 + 1e-9) / 10;

export interface Verdict {
  failures: string[];
  /** The baseline to commit when coverage went up, else undefined. */
  raised: Totals | undefined;
}

export function judge(
  measured: Totals,
  baseline: Totals,
  floor: Totals,
  previous: Totals | undefined,
  lowerOk: boolean,
): Verdict {
  const failures: string[] = [];
  for (const k of ["lines", "regions"] as const) {
    const need = Math.max(floor[k], baseline[k]);
    if (shown(measured[k]) < need) {
      const why =
        baseline[k] > floor[k]
          ? `baseline ${baseline[k]}`
          : `floor ${floor[k]}`;
      failures.push(
        `${k} coverage ${measured[k].toFixed(2)} % is below the ${why} %`,
      );
    }
    if (previous && baseline[k] < previous[k] && !lowerOk) {
      failures.push(
        `the ${k} baseline was lowered (${previous[k]} to ${baseline[k]}); that needs the owner's OK`,
      );
    }
  }
  const next = {
    lines: Math.max(baseline.lines, down(shown(measured.lines))),
    regions: Math.max(baseline.regions, down(shown(measured.regions))),
  };
  const raised =
    next.lines > baseline.lines || next.regions > baseline.regions
      ? next
      : undefined;
  return { failures, raised };
}

function parseBaseline(text: string): Totals {
  const b = JSON.parse(text) as Partial<Totals>;
  if (typeof b.lines !== "number" || typeof b.regions !== "number") {
    throw new Error("baseline needs numeric lines and regions");
  }
  return { lines: b.lines, regions: b.regions };
}

export function main(argv: string[]): number {
  const get = (n: string) => argv[argv.indexOf(`--${n}`) + 1];
  const summary = get("summary");
  const file = get("baseline");
  if (!summary || !file || !get("floor-lines") || !get("floor-regions")) {
    throw new Error(
      "usage: coverage-ratchet.ts --summary f --baseline f --floor-lines n --floor-regions n [--previous f] [--write]",
    );
  }
  const measured = readTotals(readFileSync(summary, "utf8"));
  const baseline = parseBaseline(readFileSync(file, "utf8"));
  const prevFile = argv.includes("--previous") ? get("previous") : undefined;
  const previous = prevFile
    ? parseBaseline(readFileSync(prevFile, "utf8"))
    : undefined;
  const floor = {
    lines: Number(get("floor-lines")),
    regions: Number(get("floor-regions")),
  };
  const v = judge(
    measured,
    baseline,
    floor,
    previous,
    process.env["COVERAGE_BASELINE_LOWER_OK"] === "1",
  );
  console.log(
    `coverage: lines ${measured.lines.toFixed(2)} % (baseline ${baseline.lines}), regions ${measured.regions.toFixed(2)} % (baseline ${baseline.regions})`,
  );
  if (v.failures.length > 0) {
    for (const f of v.failures) console.error(`coverage ratchet: ${f}`);
    return 1;
  }
  if (v.raised) {
    if (argv.includes("--write")) {
      writeFileSync(file, `${JSON.stringify(v.raised, null, 2)}\n`);
      console.log(
        `coverage ratchet: baseline raised to lines ${v.raised.lines}, regions ${v.raised.regions} in ${file}; commit it`,
      );
    } else {
      console.log(
        `coverage ratchet: coverage is above the baseline; raise it with \`scripts/check.sh coverage-ratchet\` and commit scripts/coverage-baseline.json`,
      );
    }
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    console.error(`coverage-ratchet: ${(e as Error).message}`);
    process.exitCode = 2;
  }
}
