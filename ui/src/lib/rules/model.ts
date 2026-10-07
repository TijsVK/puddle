// SPDX-License-Identifier: GPL-3.0-or-later
// The rules table as pure data: how a rule reads, which rules a filter keeps, and in which order
// they are shown. No layout and no API calls here.
import type { components } from "#lib/api/schema.d.ts";

export type Rule = components["schemas"]["Rule"];

export type SortKey = "pattern" | "effect" | "scope" | "expires" | "created";
export type SortDirection = "asc" | "desc";
export interface Sort {
  key: SortKey;
  direction: SortDirection;
}

export type EffectFilter = "any" | "allow" | "deny";
export type StateFilter = "any" | "active" | "expired";
/** `any`, `global`, or a workspace name. */
export type ScopeFilter = string;

export interface Filter {
  /** Case-insensitive substring of the pattern. */
  host: string;
  scope: ScopeFilter;
  effect: EffectFilter;
  state: StateFilter;
}

export const NO_FILTER: Filter = {
  host: "",
  scope: "any",
  effect: "any",
  state: "any",
};

export const DEFAULT_SORT: Sort = { key: "created", direction: "desc" };

/** A rule whose time has passed never matches, whether or not the sweeper has removed it yet. */
export function isExpired(
  rule: Pick<Rule, "expires_at">,
  now: number,
): boolean {
  return rule.expires_at !== null && rule.expires_at <= now;
}

/** The workspace a rule belongs to, or `null` for every workspace. */
export function workspaceOf(rule: Pick<Rule, "scope">): string | null {
  return rule.scope.type === "global" ? null : rule.scope.sandbox;
}

export function scopeLabel(rule: Pick<Rule, "scope">): string {
  const workspace = workspaceOf(rule);
  return workspace === null ? "Every workspace" : workspace;
}

/** `*.example.com` for a suffix rule, the host for an exact one. */
export function patternLabel(rule: Pick<Rule, "pattern" | "pattern_kind">) {
  if (rule.pattern_kind === "suffix") {
    return `*${rule.pattern.startsWith(".") ? "" : "."}${rule.pattern}`;
  }
  return rule.pattern;
}

/** "Allow *.example.com, every workspace": how a rule is named in buttons and messages. */
export function ruleName(rule: Rule): string {
  const who =
    rule.scope.type === "global"
      ? "every workspace"
      : `workspace ${rule.scope.sandbox}`;
  return `${rule.effect === "allow" ? "allow" : "deny"} ${patternLabel(rule)} for ${who}`;
}

export function matches(rule: Rule, filter: Filter, now: number): boolean {
  const needle = filter.host.trim().toLowerCase();
  if (needle !== "" && !rule.pattern.toLowerCase().includes(needle))
    return false;
  if (filter.scope !== "any") {
    const workspace = workspaceOf(rule);
    if (
      filter.scope === "global"
        ? workspace !== null
        : workspace !== filter.scope
    )
      return false;
  }
  if (filter.effect !== "any" && rule.effect !== filter.effect) return false;
  if (filter.state !== "any") {
    if (isExpired(rule, now) !== (filter.state === "expired")) return false;
  }
  return true;
}

/** Permanent rules sort after every expiring one when ascending. */
const FAR = Number.MAX_SAFE_INTEGER;

function compare(a: Rule, b: Rule, key: SortKey): number {
  switch (key) {
    case "pattern":
      return a.pattern.localeCompare(b.pattern);
    case "effect":
      return a.effect.localeCompare(b.effect);
    case "scope":
      return scopeLabel(a).localeCompare(scopeLabel(b));
    case "expires":
      return (a.expires_at ?? FAR) - (b.expires_at ?? FAR);
    case "created":
      return a.created_at - b.created_at;
  }
}

/** The kept rules in order; ties fall back to the id, so the order never flickers. */
export function view(
  rules: readonly Rule[],
  filter: Filter,
  sort: Sort,
  now: number,
): Rule[] {
  const sign = sort.direction === "asc" ? 1 : -1;
  return rules
    .filter((rule) => matches(rule, filter, now))
    .sort((a, b) => sign * compare(a, b, sort.key) || sign * (a.id - b.id));
}

/** The workspaces the rules name, for the scope filter and the add form's suggestions. */
export function workspacesIn(rules: readonly Rule[]): string[] {
  return [
    ...new Set(rules.map(workspaceOf).filter((w): w is string => w !== null)),
  ].sort();
}

export interface ExpiryOption {
  /** Seconds from now; `null` is permanent. */
  secs: number | null;
  label: string;
}

export const EXPIRY_OPTIONS: readonly ExpiryOption[] = [
  { secs: null, label: "Never (permanent)" },
  { secs: 3600, label: "In 1 hour" },
  { secs: 28_800, label: "In 8 hours" },
  { secs: 86_400, label: "In 1 day" },
  { secs: 604_800, label: "In 7 days" },
];

/** Epoch ms for "this long from now", or `null` for permanent. */
export function expiryFrom(now: number, secs: number | null): number | null {
  return secs === null ? null : now + secs * 1000;
}

/** A workspace name is a DNS label (`a-z`, `0-9`, `-`, no leading or trailing `-`). */
export function workspaceNameError(name: string): string | null {
  if (name === "") return "Name the workspace the rule belongs to.";
  if (name.length > 63 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(name))
    return "A workspace name uses lower-case letters, digits and hyphens, and starts and ends with a letter or digit.";
  return null;
}

/** The API's messages are lower case with no full stop; the form shows them as sentences. */
export function sentence(message: string): string {
  const trimmed = message.trim();
  if (trimmed === "") return trimmed;
  const first = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(first) ? first : `${first}.`;
}

export const PRECEDENCE =
  "The most specific rule wins: an exact host beats a pattern, and a longer pattern beats a shorter one. At the same specificity a workspace rule beats an every-workspace rule, then deny beats allow.";
