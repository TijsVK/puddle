// SPDX-License-Identifier: GPL-3.0-or-later
// The live event the rules screen listens to. The API will add `rules_changed` to its `Event`
// union (and so to the generated schema); until then it is read here, defensively. When the API
// has it, check this guard against the generated type.

/** True for the event that says some rule was added, changed, deleted or expired. */
export function isRulesChanged(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>)["type"] === "rules_changed"
  );
}
