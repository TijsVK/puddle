// SPDX-License-Identifier: GPL-3.0-or-later
// The one stream event the network-health screen acts on.
import type { components } from "#lib/api/schema.d.ts";

export type NetworkChanged = Extract<
  components["schemas"]["Event"],
  { type: "network_changed" }
>;

/** Whether `raw` is a `network_changed` event with a numeric epoch. */
export function isNetworkChanged(raw: unknown): raw is NetworkChanged {
  return (
    typeof raw === "object" &&
    raw !== null &&
    (raw as Record<string, unknown>)["type"] === "network_changed" &&
    typeof (raw as Record<string, unknown>)["epoch"] === "number"
  );
}
