// SPDX-License-Identifier: GPL-3.0-or-later
// The live event the activity screen listens to. It is read defensively: an event that is not an
// object with that exact type is ignored.
import type { components } from "#lib/api/schema.d.ts";

type Event = components["schemas"]["Event"];

/** One or more audit records were committed; `id` is the newest. */
export type AuditAppended = Extract<Event, { type: "audit_appended" }>;

export function isAuditAppended(value: unknown): value is AuditAppended {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>)["type"] === "audit_appended"
  );
}
