// SPDX-License-Identifier: GPL-3.0-or-later
// The diff-coverage gate (docs/STANDARDS.md, "Coverage"): every line a change adds or changes in
// code that a coverage run measured must be executed by a test, or sit in the reviewed exclusion
// file (scripts/diff-coverage-exclusions.txt: `path glob | text in the line, or * | reason`).
//
// Usage: node scripts/diff-coverage.ts --base <rev> --lcov <file> --exts .rs[,.ts] [--prefix ui/]
//          [--exclusions <file>] [--label <name>]
// `--base` is the commit the change is measured from (merge base locally, PR or push base in CI);
// the diff is that commit against the working tree. `--lcov` is an lcov report whose `SF:` paths
// are absolute or relative to `--prefix` (a directory under the repository root, default "").
//
// What it can't see (a pass is not proof of tested behaviour):
// - Lines without coverage data: comments, blank lines, declarations, and code compiled out of the
//   measured build (`cfg(windows)` lines inside a Linux run). Only executable lines can fail.
// - Whole files absent from the report (types-only files, files not compiled here): listed as
//   "not measured", never failed.
// - Line coverage, not branch or region: a line where one branch ran counts as covered.
// - Untracked files: `git diff` only sees tracked ones, so `git add -N <file>` before running by hand.
// - A covered line is not an asserted line: it says a test ran it, not that a test checked it.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

/** Execution counts per line, per repository-relative path. */
export type Coverage = Map<string, Map<number, number>>;

/** One line a change adds: where, and its text (for exclusion matching and the report). */
export interface AddedLine {
  path: string;
  line: number;
  text: string;
}

export interface Exclusion {
  glob: string;
  needle: string;
  reason: string;
  used: boolean;
}

const posix = (p: string) => p.split("\\").join("/");

/** Parses an lcov report; a line seen twice (generic instantiations) keeps its highest count. */
export function parseLcov(
  text: string,
  repoRoot: string,
  prefix: string,
): Coverage {
  const out: Coverage = new Map();
  let current: Map<number, number> | undefined;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.startsWith("SF:")) {
      const file = raw.slice(3);
      const abs = resolve(repoRoot, prefix, file);
      const path = posix(relative(repoRoot, abs));
      current = out.get(path) ?? new Map();
      out.set(path, current);
    } else if (raw.startsWith("DA:") && current) {
      const [no, count] = raw.slice(3).split(",");
      const line = Number(no);
      const hits = Number(count);
      if (Number.isInteger(line) && Number.isFinite(hits)) {
        current.set(line, Math.max(current.get(line) ?? 0, hits));
      }
    } else if (raw === "end_of_record") {
      current = undefined;
    }
  }
  return out;
}

/** Parses `git diff -U0` output into the added lines (new-file numbering). */
export function parseDiff(diff: string): AddedLine[] {
  const out: AddedLine[] = [];
  let path: string | undefined;
  let next = 0;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("+++ ")) {
      path =
        raw === "+++ /dev/null"
          ? undefined
          : posix(raw.slice(4).replace(/^b\//, ""));
    } else if (raw.startsWith("@@")) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      if (m) next = Number(m[1]);
    } else if (path && raw.startsWith("+") && !raw.startsWith("+++")) {
      out.push({ path, line: next, text: raw.slice(1) });
      next += 1;
    }
  }
  return out;
}

/** Exclusion file: `path glob | text in the line (or *) | reason`, `#` comments, blanks ignored. */
export function parseExclusions(text: string): Exclusion[] {
  const out: Exclusion[] = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const first = line.indexOf("|");
    const second = line.indexOf("|", first + 1);
    const glob = first < 0 ? "" : line.slice(0, first).trim();
    const needle = second < 0 ? "" : line.slice(first + 1, second).trim();
    const reason = second < 0 ? "" : line.slice(second + 1).trim();
    if (!glob || !needle || !reason) {
      throw new Error(
        `exclusions line ${i + 1}: want "path glob | text in the line, or * | reason" (a reason is required)`,
      );
    }
    out.push({ glob, needle, reason, used: false });
  }
  return out;
}

function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i] as string;
    if (c === "*" && glob[i + 1] === "*") {
      re += ".*";
      i += 1;
    } else if (c === "*") re += "[^/]*";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export interface Report {
  /** Added lines that are executable and never ran, and match no exclusion. */
  uncovered: AddedLine[];
  /** Added lines that are executable and ran. */
  covered: number;
  /** Added lines an exclusion accepted (only those that would have failed). */
  excluded: number;
  /** Changed files with no entry in the coverage report. */
  notMeasured: string[];
}

export function judge(
  added: AddedLine[],
  coverage: Coverage,
  exclusions: Exclusion[],
): Report {
  const matchers = exclusions.map((e) => ({ e, re: globToRegExp(e.glob) }));
  const report: Report = {
    uncovered: [],
    covered: 0,
    excluded: 0,
    notMeasured: [],
  };
  const unmeasured = new Set<string>();
  for (const a of added) {
    const lines = coverage.get(a.path);
    if (!lines) {
      unmeasured.add(a.path);
      continue;
    }
    const hits = lines.get(a.line);
    if (hits === undefined) continue; // not an executable line
    if (hits > 0) {
      report.covered += 1;
      continue;
    }
    const hit = matchers.find(
      ({ e, re }) =>
        re.test(a.path) && (e.needle === "*" || a.text.includes(e.needle)),
    );
    if (hit) {
      hit.e.used = true;
      report.excluded += 1;
    } else report.uncovered.push(a);
  }
  report.notMeasured = [...unmeasured].sort();
  return report;
}

/** The environment without the variables a git hook exports, which would override `cwd`. */
export function cleanGitEnv(
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const k of ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_PREFIX"])
    delete out[k];
  return out;
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, {
    env: cleanGitEnv(),
    cwd,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
}

export interface Options {
  base: string;
  lcov: string;
  exts: string[];
  prefix: string;
  exclusions?: string | undefined;
  label: string;
}

function parseArgs(argv: string[]): Options {
  const get = (name: string) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const base = get("base");
  const lcov = get("lcov");
  const exts = get("exts");
  if (!base || !lcov || !exts) {
    throw new Error(
      "usage: diff-coverage.ts --base <rev> --lcov <file> --exts .rs[,.ts] [--prefix dir/] [--exclusions file] [--label name]",
    );
  }
  return {
    base,
    lcov,
    exts: exts.split(","),
    prefix: get("prefix") ?? "",
    exclusions: get("exclusions"),
    label: get("label") ?? "diff-coverage",
  };
}

export function run(opts: Options, cwd: string = process.cwd()): number {
  const repoRoot = git(["rev-parse", "--show-toplevel"], cwd).trim();
  if (!existsSync(opts.lcov)) {
    console.error(
      `${opts.label}: ${opts.lcov} not found; run the coverage gate first`,
    );
    return 1;
  }
  const diff = git(
    [
      "diff",
      "-U0",
      "--no-color",
      "--no-ext-diff",
      "--no-renames",
      opts.base,
      "--",
    ],
    repoRoot,
  );
  const added = parseDiff(diff).filter(
    (a) =>
      a.path.startsWith(opts.prefix) &&
      opts.exts.some((x) => a.path.endsWith(x)),
  );
  const coverage = parseLcov(
    readFileSync(opts.lcov, "utf8"),
    repoRoot,
    opts.prefix,
  );
  const exclusions = opts.exclusions
    ? parseExclusions(readFileSync(opts.exclusions, "utf8"))
    : [];
  const report = judge(added, coverage, exclusions);
  if (report.notMeasured.length > 0) {
    console.log(
      `${opts.label}: not in the coverage report (not measured): ${report.notMeasured.join(", ")}`,
    );
  }
  for (const e of exclusions.filter((x) => !x.used)) {
    console.log(
      `${opts.label}: note: exclusion "${e.glob} | ${e.needle}" matched nothing in this diff`,
    );
  }
  if (report.uncovered.length > 0) {
    console.error(
      `${opts.label}: ${report.uncovered.length} added or changed line(s) never ran in a test:`,
    );
    for (const u of report.uncovered)
      console.error(`  ${u.path}:${u.line}: ${u.text.trim()}`);
    console.error(
      `  Cover them, or list them with a reason in the exclusion file (reviewed like code).`,
    );
    return 1;
  }
  console.log(
    `${opts.label} ok: ${report.covered} changed executable line(s) covered, ${report.excluded} excluded, since ${opts.base.slice(0, 10)}`,
  );
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
  try {
    process.exitCode = run(parseArgs(process.argv.slice(2)));
  } catch (e) {
    console.error(`diff-coverage: ${(e as Error).message}`);
    process.exitCode = 2;
  }
}
