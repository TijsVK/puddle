// SPDX-License-Identifier: GPL-3.0-or-later
// The live events the inbox applies. The API will add them to its `Event` union (and so to the
// generated schema); until then they are described here and read defensively, so a field that
// is missing or has the wrong type drops the event instead of corrupting the list. When the API
// has them, replace these types by `components["schemas"]` ones and keep the guards.
import type { components } from "#lib/api/schema.d.ts";

export type PendingRequest = components["schemas"]["PendingRequest"];
export type PendingState = components["schemas"]["PendingState"];

export interface PendingOpened {
  type: "pending_opened";
  request: PendingRequest;
  /** Proposed: the group the row belongs to. Without it the list is refetched. */
  registrable_domain?: string | null;
}
export interface PendingUpdated {
  type: "pending_updated";
  id: number;
  attempts: number;
  last_seen: number;
}
export interface PendingClosed {
  type: "pending_closed";
  id: number;
  state: PendingState;
  rule_id: number | null;
}
export interface SuppressionChanged {
  type: "suppression_changed";
  sandbox: string;
  active: boolean;
  count: number;
}

export type InboxEvent =
  PendingOpened | PendingUpdated | PendingClosed | SuppressionChanged;

const isNum = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v);
const isStr = (v: unknown): v is string => typeof v === "string";

function isRequest(v: unknown): v is PendingRequest {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return (
    isNum(r["id"]) &&
    isStr(r["sandbox"]) &&
    isStr(r["host"]) &&
    isNum(r["port"]) &&
    isNum(r["first_seen"]) &&
    isNum(r["last_seen"]) &&
    isNum(r["attempts"]) &&
    isStr(r["state"])
  );
}

/** The event as an inbox event, or `undefined` for any other or malformed event. */
export function asInboxEvent(value: unknown): InboxEvent | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const e = value as Record<string, unknown>;
  switch (e["type"]) {
    case "pending_opened":
      if (!isRequest(e["request"])) return undefined;
      return {
        type: "pending_opened",
        request: e["request"],
        registrable_domain: isStr(e["registrable_domain"])
          ? e["registrable_domain"]
          : null,
      };
    case "pending_updated":
      if (!isNum(e["id"]) || !isNum(e["attempts"]) || !isNum(e["last_seen"])) {
        return undefined;
      }
      return {
        type: "pending_updated",
        id: e["id"],
        attempts: e["attempts"],
        last_seen: e["last_seen"],
      };
    case "pending_closed":
      if (!isNum(e["id"]) || !isStr(e["state"])) return undefined;
      return {
        type: "pending_closed",
        id: e["id"],
        state: e["state"] as PendingState,
        rule_id: isNum(e["rule_id"]) ? e["rule_id"] : null,
      };
    case "suppression_changed":
      if (
        !isStr(e["sandbox"]) ||
        typeof e["active"] !== "boolean" ||
        !isNum(e["count"])
      ) {
        return undefined;
      }
      return {
        type: "suppression_changed",
        sandbox: e["sandbox"],
        active: e["active"],
        count: e["count"],
      };
    default:
      return undefined;
  }
}
