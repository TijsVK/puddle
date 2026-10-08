// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  copyText,
  failures,
  isBlocked,
  reportText,
  STATUS_LABEL,
  STATUS_MARK,
  took,
  verdict,
  warnings,
  type DoctorCheck,
  type DoctorReport,
} from "./doctor.ts";

function check(status: DoctorCheck["status"], id = "runtime"): DoctorCheck {
  return {
    id,
    title: id,
    status,
    summary: "s",
    finding: null,
    fix: null,
    detail: null,
  };
}

const report = (...statuses: DoctorCheck["status"][]): DoctorReport => ({
  schema_version: 1,
  puddle_version: "1.0.0",
  os: "linux",
  arch: "x86_64",
  ok: !statuses.includes("fail"),
  checks: statuses.map((status, i) => check(status, `c${i}`)),
  elapsed_ms: 1840,
});

afterEach(() => vi.unstubAllGlobals());

describe("system check model", () => {
  it("blocks on a failed check only", () => {
    expect(isBlocked(report("ok", "info", "warn", "skipped"))).toBe(false);
    expect(isBlocked(report("ok", "fail"))).toBe(true);
    expect(failures(report("fail", "ok", "fail")).length).toBe(2);
    expect(warnings(report("warn", "ok", "warn", "fail")).length).toBe(2);
  });

  it("says what was found in one sentence", () => {
    expect(verdict(report("ok", "info"))).toBe("No problems found.");
    expect(verdict(report("ok", "warn"))).toBe(
      "No problems found; 1 warning to know about.",
    );
    expect(verdict(report("warn", "warn"))).toBe(
      "No problems found; 2 warnings to know about.",
    );
    expect(verdict(report("fail"))).toBe(
      "1 problem to fix before puddle can run workspaces.",
    );
    expect(verdict(report("fail", "fail", "warn"))).toBe(
      "2 problems to fix before puddle can run workspaces; 1 warning.",
    );
  });

  it("words every status in text, not only by symbol", () => {
    for (const status of Object.keys(STATUS_LABEL) as DoctorCheck["status"][]) {
      expect(STATUS_LABEL[status]).not.toBe("");
      expect(STATUS_MARK[status]).not.toBe("");
    }
    expect(new Set(Object.values(STATUS_LABEL)).size).toBe(5);
  });

  it("shows the time in seconds with one decimal", () => {
    expect(took(report("ok"))).toBe("1.8 s");
  });

  it("makes the report's JSON with its schema version for copying", () => {
    const parsed = JSON.parse(reportText(report("ok"))) as DoctorReport;
    expect(parsed.schema_version).toBe(1);
    expect(parsed.checks).toHaveLength(1);
  });

  it("copies text, and says when the browser refuses", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    expect(await copyText("hello")).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
    vi.stubGlobal("navigator", {
      clipboard: {
        writeText: async () => {
          throw new Error("denied");
        },
      },
    });
    expect(await copyText("hello")).toBe(false);
    vi.stubGlobal("navigator", {});
    expect(await copyText("hello")).toBe(false);
  });
});
