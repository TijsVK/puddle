// SPDX-License-Identifier: GPL-3.0-or-later
// A decision made in this session, and how it reads in a sentence (toast, "Decided just now").
import type { components } from "#lib/api/schema.d.ts";

type Rule = components["schemas"]["Rule"];

export interface Decided {
  ruleId: number;
  effect: Rule["effect"];
  pattern: string;
  patternKind: Rule["pattern_kind"];
  /** `null` is every workspace (or a rule set's entry). */
  workspace: string | null;
  /** The rule set the rule went into, by name; `null` for a plain rule. */
  ruleSet: string | null;
  expiresAt: number | null;
  alsoClosed: number;
  at: number;
}

/** `*.example.com` for a suffix rule, the host itself for an exact one. */
export function decidedPattern(d: Pick<Decided, "pattern" | "patternKind">) {
  if (d.patternKind === "suffix") {
    return `*${d.pattern.startsWith(".") ? "" : "."}${d.pattern}`;
  }
  return d.pattern;
}

export function expiryPhrase(expiresAt: number | null, locale?: string) {
  if (expiresAt === null) return "permanently";
  const when = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(expiresAt);
  return `until ${when}`;
}

/** "Allowed *.example.com for every workspace, permanently". */
export function decidedSentence(d: Decided, locale?: string): string {
  const verb = d.effect === "allow" ? "Allowed" : "Denied";
  const when = expiryPhrase(d.expiresAt, locale);
  if (d.ruleSet !== null) {
    return `${verb} ${decidedPattern(d)} in rule set ${d.ruleSet}, ${when}`;
  }
  const who =
    d.workspace === null ? "every workspace" : `workspace ${d.workspace}`;
  return `${verb} ${decidedPattern(d)} for ${who}, ${when}`;
}
