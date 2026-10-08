// SPDX-License-Identifier: GPL-3.0-or-later
// Rule sets and System managed as pure data (rules spec §7): where a set is on and why, how its
// entries and the System managed hosts read. No layout and no API calls here.
import type { components } from "#lib/api/schema.d.ts";

type Schemas = components["schemas"];
export type RuleSet = Schemas["RuleSetView"];
export type RuleSetEntry = Schemas["RuleSetEntry"];
export type SystemHost = Schemas["SystemManagedHost"];
export type SystemReason = Schemas["SystemReason"];

/** Whether `set` is on for `workspace`, or for every workspace when `workspace` is `null`. */
export function isOn(set: RuleSet, workspace: string | null): boolean {
  if (workspace !== null) {
    const own = set.overrides.find((o) => o.workspace === workspace);
    if (own) return own.enabled;
  }
  return set.global ?? set.default_on;
}

/** "On for every workspace", "Off (built-in sets ship off)": the every-workspace state in words. */
export function globalState(set: RuleSet): string {
  if (set.global !== null) {
    return set.global ? "On for every workspace" : "Off for every workspace";
  }
  if (set.default_on) return "On for every workspace (new sets start on)";
  return "Off (built-in sets ship off)";
}

/** "On here", "Off, as for every workspace": a set's state for one workspace and where it comes from. */
export function stateFor(set: RuleSet, workspace: string): string {
  const own = set.overrides.find((o) => o.workspace === workspace);
  if (own) return own.enabled ? "On here" : "Off here";
  return isOn(set, null)
    ? "On, as for every workspace"
    : "Off, as for every workspace";
}

/** Whether `workspace` switches the set for itself. */
export function overrides(set: RuleSet, workspace: string): boolean {
  return set.overrides.some((o) => o.workspace === workspace);
}

/** The System managed hosts that apply to `workspace`. */
export function systemFor(
  hosts: readonly SystemHost[],
  workspace: string,
): SystemHost[] {
  return hosts.filter((h) => h.workspace === null || h.workspace === workspace);
}

/** "On in demo; off in api": the workspaces that switch the set for themselves. */
export function overridesLabel(set: RuleSet): string {
  return set.overrides
    .map((o) => `${o.enabled ? "on" : "off"} in ${o.workspace}`)
    .join("; ");
}

/** `*.example.com` for a suffix entry, the host for an exact one. */
export function entryPattern(
  entry: Pick<RuleSetEntry, "pattern" | "pattern_kind">,
) {
  if (entry.pattern_kind === "suffix" && !entry.pattern.startsWith("*")) {
    return `*${entry.pattern.startsWith(".") ? "" : "."}${entry.pattern}`;
  }
  return entry.pattern;
}

/** The number of a set you made (`user:4` is 4), or `null` for a built-in one. */
export function userSetNumber(set: Pick<RuleSet, "id">): number | null {
  const match = /^user:(\d+)$/.exec(set.id);
  return match ? Number(match[1]) : null;
}

/** Your sets that are on for `workspace`: the places an inbox decision can put its rule. */
export function setsOnFor(
  sets: readonly RuleSet[],
  workspace: string,
): RuleSet[] {
  return sets.filter((s) => s.kind === "user" && isOn(s, workspace));
}

/** "Every workspace" or the one workspace a System managed host is allowed for. */
export function systemScope(host: Pick<SystemHost, "workspace">): string {
  return host.workspace === null ? "Every workspace" : host.workspace;
}

export interface ReasonGroup {
  reason: SystemReason;
  text: string;
  /** `null` for every workspace. */
  workspace: string | null;
  hosts: SystemHost[];
}

/** The System managed hosts grouped by reason and workspace, in the order the API sent them. */
export function byReason(hosts: readonly SystemHost[]): ReasonGroup[] {
  const groups: ReasonGroup[] = [];
  for (const host of hosts) {
    const group = groups.find(
      (g) => g.reason === host.reason && g.workspace === host.workspace,
    );
    if (group) group.hosts.push(host);
    else
      groups.push({
        reason: host.reason,
        text: host.reason_text,
        workspace: host.workspace,
        hosts: [host],
      });
  }
  return groups;
}

/** A set's name is 1 to 64 characters; the server checks it is not taken. */
export function setNameError(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed === "") return "Give the rule set a name.";
  if ([...trimmed].length > 64) return "A name is at most 64 characters.";
  return null;
}

export const SETS_INTRO =
  "Named groups of rules you switch on or off as one, for every workspace or for one. A set never opens what your own rules close: your rules decide first, and a set's allow only fills the gaps.";

export const SYSTEM_INTRO =
  "Puddle allows these hosts because of choices you made, and only while you keep them. Your own rules decide first: add a deny rule to block one.";
