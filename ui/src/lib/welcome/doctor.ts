// SPDX-License-Identifier: GPL-3.0-or-later
// The system check as the first-run flow shows it: what blocks, how to word the result, and the
// report as text for "Copy report".
import type { components } from "#lib/api/schema.d.ts";

export type DoctorReport = components["schemas"]["DoctorReport"];
export type DoctorCheck = components["schemas"]["DoctorCheck"];
export type DoctorStatus = DoctorCheck["status"];

/** What a screen reader hears for the symbol in front of a check. */
export const STATUS_LABEL: Record<DoctorStatus, string> = {
  ok: "OK",
  info: "Info",
  warn: "Warning",
  fail: "Problem",
  skipped: "Not checked",
};

/** The glyph in front of a check. Never the only signal: the label is always in the text. */
export const STATUS_MARK: Record<DoctorStatus, string> = {
  ok: "✓",
  info: "i",
  warn: "!",
  fail: "✕",
  skipped: "–",
};

export const failures = (report: DoctorReport): DoctorCheck[] =>
  report.checks.filter((check) => check.status === "fail");

export const warnings = (report: DoctorReport): DoctorCheck[] =>
  report.checks.filter((check) => check.status === "warn");

/** A failed check means puddle cannot run workspaces: the flow does not go on until it is fixed. */
export const isBlocked = (report: DoctorReport): boolean =>
  failures(report).length > 0;

const plural = (n: number, word: string): string =>
  n === 1 ? `1 ${word}` : `${n} ${word}s`;

/** The one sentence under the list. */
export function verdict(report: DoctorReport): string {
  const fails = failures(report).length;
  const warns = warnings(report).length;
  if (fails > 0) {
    const also = warns > 0 ? `; ${plural(warns, "warning")}` : "";
    return `${plural(fails, "problem")} to fix before puddle can run workspaces${also}.`;
  }
  if (warns > 0) {
    return `No problems found; ${plural(warns, "warning")} to know about.`;
  }
  return "No problems found.";
}

/** How long the checks took, for the line under the verdict. */
export function took(report: DoctorReport): string {
  return `${(report.elapsed_ms / 1000).toFixed(1)} s`;
}

/** The report as JSON, with its `schema_version`, for a bug report or a support request. */
export const reportText = (report: DoctorReport): string =>
  JSON.stringify(report, null, 2);

/** Puts text on the clipboard; `false` when the browser or the user refuses. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
