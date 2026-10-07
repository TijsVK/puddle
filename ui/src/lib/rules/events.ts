// SPDX-License-Identifier: GPL-3.0-or-later
// The live event the rules screen listens to. It is read defensively: an event that is not an
// object with that exact type is ignored.
import type { components } from "#lib/api/schema.d.ts";

type Event = components["schemas"]["Event"];

/** Some rule was added, changed, deleted or expired. */
export type RulesChanged = Extract<Event, { type: "rules_changed" }>;

export function isRulesChanged(value: unknown): value is RulesChanged {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>)["type"] === "rules_changed"
  );
}
