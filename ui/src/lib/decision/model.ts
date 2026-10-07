// SPDX-License-Identifier: GPL-3.0-or-later
// The four-outcome model of an approve or deny (rules spec R-15), as pure functions: effect x scope x
// match x duration go in, the `DecisionRequest` body of the API comes out. No UI layout is in
// here, so another control (four buttons, a pie menu) can be built on it. The one rule it
// enforces: a decision for every workspace is never built without `confirmed`.
import type { components } from "#lib/api/schema.d.ts";

export type Effect = components["schemas"]["Effect"];
export type Scope = components["schemas"]["ScopeChoice"];
export type DecisionBody = components["schemas"]["DecisionRequest"];
export type Match = "exact" | "suffix";

/** Seconds, or `null` for permanent. */
export type DurationSecs = number | null;

export interface DurationOption {
  secs: DurationSecs;
  /** In the options form: "How long". */
  label: string;
  /** In a sentence: "allowed ... for 8 hours". */
  phrase: string;
}

/** Permanent (the default), 1 hour, 8 hours, 1 day, 7 days. */
export const DURATIONS: readonly DurationOption[] = [
  { secs: null, label: "Permanently", phrase: "permanently" },
  { secs: 3600, label: "1 hour", phrase: "for 1 hour" },
  { secs: 28_800, label: "8 hours", phrase: "for 8 hours" },
  { secs: 86_400, label: "1 day", phrase: "for 1 day" },
  { secs: 604_800, label: "7 days", phrase: "for 7 days" },
];

/** A rule set you made, as a place to put the rule instead of a workspace (rules spec R-38). */
export interface RuleSetChoice {
  /** The number of `user:<id>`. */
  id: number;
  name: string;
  /** On for every workspace that doesn't switch it off: the rule then reaches beyond this one. */
  everywhere: boolean;
}

export interface Choice {
  effect: Effect;
  scope: Scope;
  /** Put the rule into this set instead (`scope` stays `sandbox`); `null` for a plain rule. */
  ruleSet: RuleSetChoice | null;
  match: Match;
  durationSecs: DurationSecs;
}

/** What a request is about: the host as the guest asked for it, and the group it sits in. */
export interface Target {
  host: string;
  /** The inbox group's registrable domain (`example.co.uk`), or the IP literal. */
  registrableDomain: string;
}

/** R-15's defaults: this workspace, the exact host, permanent. Never widened implicitly. */
export function narrowest(effect: Effect): Choice {
  return {
    effect,
    scope: "sandbox",
    ruleSet: null,
    match: "exact",
    durationSecs: null,
  };
}

/**
 * The suffix a "everything under ..." choice would send, or `null` when there is none: the host
 * is already the registrable domain, or the host is an IP literal (no names under it).
 */
export function suffixFor(target: Target): string | null {
  const host = target.host.toLowerCase();
  const domain = target.registrableDomain.toLowerCase();
  if (host === domain || isIpLiteral(host) || isIpLiteral(domain)) return null;
  if (!host.endsWith(`.${domain}`)) return null;
  return `.${domain}`;
}

export function isIpLiteral(host: string): boolean {
  if (host.includes(":")) return true;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/** True for every choice that reaches beyond the request's own workspace. */
export function needsConfirm(
  choice: Pick<Choice, "scope" | "ruleSet">,
): boolean {
  if (choice.ruleSet !== null) return choice.ruleSet.everywhere;
  return choice.scope === "global";
}

export type BuildError = "confirmation_required" | "no_suffix";

export type Built =
  | { ok: true; effect: Effect; body: DecisionBody }
  | { ok: false; error: BuildError };

/**
 * The call for a choice. A global choice without `confirmed` is refused here, whatever the UI
 * did; a suffix choice for a host that has no suffix is refused too.
 */
export function build(
  choice: Choice,
  target: Target,
  confirmed: boolean,
): Built {
  if (needsConfirm(choice) && !confirmed) {
    return { ok: false, error: "confirmation_required" };
  }
  const body: DecisionBody =
    choice.ruleSet === null
      ? { scope: choice.scope }
      : { scope: "sandbox", rule_set: choice.ruleSet.id };
  if (choice.match === "suffix") {
    const suffix = suffixFor(target);
    if (suffix === null) return { ok: false, error: "no_suffix" };
    body.suffix = suffix;
  }
  if (choice.durationSecs !== null) body.expires_in_secs = choice.durationSecs;
  return { ok: true, effect: choice.effect, body };
}

export function durationPhrase(secs: DurationSecs): string {
  return DURATIONS.find((d) => d.secs === secs)?.phrase ?? `for ${secs} s`;
}

/** The pattern a choice covers, as shown to the user: `*.example.com` or the exact host. */
export function patternLabel(choice: Choice, target: Target): string {
  if (choice.match === "suffix") {
    const suffix = suffixFor(target);
    if (suffix !== null) return `*${suffix}`;
  }
  return target.host;
}

/** "Allow *.example.com for every workspace, permanently", for the confirm dialog and toasts. */
export function describe(
  choice: Choice,
  target: Target,
  workspace: string,
): string {
  const verb = choice.effect === "allow" ? "Allow" : "Deny";
  const when = durationPhrase(choice.durationSecs);
  if (choice.ruleSet !== null) {
    const reach = choice.ruleSet.everywhere
      ? "which is on for every workspace"
      : `which is on for ${workspace}`;
    return `${verb} ${patternLabel(choice, target)} in rule set ${choice.ruleSet.name} (${reach}), ${when}`;
  }
  const who =
    choice.scope === "global" ? "every workspace" : `workspace ${workspace}`;
  return `${verb} ${patternLabel(choice, target)} for ${who}, ${when}`;
}
