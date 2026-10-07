// SPDX-License-Identifier: GPL-3.0-or-later
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  judge,
  parseDiff,
  parseExclusions,
  parseLcov,
  run,
  type Options,
} from "./diff-coverage.ts";

const diff = `diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -2,0 +3,2 @@ fn x
+let a = 1;
+let b = 2;
@@ -9 +11 @@
-old
+new
diff --git a/gone.rs b/gone.rs
--- a/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
`;

describe("parseDiff", () => {
  it("numbers added lines in the new file and skips deletions", () => {
    expect(parseDiff(diff)).toEqual([
      { path: "src/a.rs", line: 3, text: "let a = 1;" },
      { path: "src/a.rs", line: 4, text: "let b = 2;" },
      { path: "src/a.rs", line: 11, text: "new" },
    ]);
  });
});

describe("parseLcov", () => {
  it("makes paths repository-relative and keeps the highest count of a repeated line", () => {
    const cov = parseLcov(
      "SF:/repo/crates/x/src/a.rs\nDA:3,0\nDA:3,2\nDA:4,0\nend_of_record\nSF:src/b.ts\nDA:1,1\nend_of_record\n",
      "/repo",
      "ui/",
    );
    expect(cov.get("crates/x/src/a.rs")?.get(3)).toBe(2);
    expect(cov.get("crates/x/src/a.rs")?.get(4)).toBe(0);
    expect(cov.get("ui/src/b.ts")?.get(1)).toBe(1);
  });
});

describe("exclusions file", () => {
  it("needs a reason on every entry", () => {
    expect(() => parseExclusions("a.rs | * |")).toThrow(/reason is required/);
    expect(() => parseExclusions("a.rs | *")).toThrow(/reason is required/);
  });
  it("ignores comments and blank lines and keeps a | inside the reason", () => {
    const [e] = parseExclusions(
      "# c\n\ncrates/**/win.rs | * | OS glue | tier W\n",
    );
    expect(e).toMatchObject({
      glob: "crates/**/win.rs",
      needle: "*",
      reason: "OS glue | tier W",
    });
  });
});

describe("judge", () => {
  const cov = new Map([
    [
      "src/a.rs",
      new Map([
        [3, 1],
        [4, 0],
        [11, 0],
      ]),
    ],
  ]);
  const added = parseDiff(diff);

  it("fails an executable line that never ran, ignores lines with no data, and says so for unmeasured files", () => {
    const r = judge(
      [...added, { path: "src/new.rs", line: 1, text: "x" }],
      cov,
      [],
    );
    expect(r.covered).toBe(1);
    expect(r.uncovered.map((u) => u.line)).toEqual([4, 11]);
    expect(r.notMeasured).toEqual(["src/new.rs"]);
  });

  it("accepts a listed exclusion by file and line text, and marks it used", () => {
    const ex = parseExclusions(
      "src/*.rs | new | reason one\nsrc/a.rs | let b | reason two",
    );
    const r = judge(added, cov, ex);
    expect(r.uncovered).toEqual([]);
    expect(r.excluded).toBe(2);
    expect(ex.every((e) => e.used)).toBe(true);
  });

  it("does not let an exclusion for another file or other text through", () => {
    const ex = parseExclusions(
      "src/b.rs | * | other file\nsrc/a.rs | nothing here | other text",
    );
    expect(judge(added, cov, ex).uncovered).toHaveLength(2);
    expect(ex.some((e) => e.used)).toBe(false);
  });
});

describe("run on a real git repository", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function repo(): string {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "diff-coverage-")));
    dirs.push(dir);
    const g = (...a: string[]) => execFileSync("git", a, { cwd: dir });
    g("init", "-q");
    g("config", "user.email", "t@example.com");
    g("config", "user.name", "t");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src/a.rs"), "fn a() {\n    1;\n}\n");
    g("add", ".");
    g("commit", "-q", "-m", "base");
    writeFileSync(
      join(dir, "src/a.rs"),
      "fn a() {\n    1;\n    2;\n    3;\n}\n",
    );
    return dir;
  }
  const opts = (lcov: string): Options => ({
    base: "HEAD",
    lcov,
    exts: [".rs"],
    prefix: "",
    label: "t",
  });

  it("passes when every added executable line ran", () => {
    const dir = repo();
    writeFileSync(
      join(dir, "l.info"),
      `SF:${dir}/src/a.rs\nDA:2,1\nDA:3,1\nDA:4,5\nend_of_record\n`,
    );
    vi.spyOn(console, "log").mockImplementation(() => {});
    expect(run(opts(join(dir, "l.info")), dir)).toBe(0);
  });

  it("fails and names the file and line when one added line never ran", () => {
    const dir = repo();
    writeFileSync(
      join(dir, "l.info"),
      `SF:${dir}/src/a.rs\nDA:2,1\nDA:3,1\nDA:4,0\nend_of_record\n`,
    );
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(run(opts(join(dir, "l.info")), dir)).toBe(1);
    expect(err.mock.calls.flat().join("\n")).toContain("src/a.rs:4: 3;");
  });

  it("fails when the coverage report is missing", () => {
    const dir = repo();
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(run(opts(join(dir, "nope.info")), dir)).toBe(1);
  });
});
