// SPDX-License-Identifier: GPL-3.0-or-later
// The live events the inbox applies, read defensively: a field that is missing or has the wrong
// type drops the event instead of corrupting the list. `pending_opened` carries the API's short
// form of a request (`PendingSummary`, with its registrable domain); it is widened here to the
// full `PendingRequest` the list holds, as an open request.
import type { components } from "#lib/api/schema.d.ts";

export type PendingRequest = components["schemas"]["PendingRequest"];
export type PendingState = components["schemas"]["PendingState"];

export interface PendingOpened {
  type: "pending_opened";
  request: PendingRequest;
  /** The group the row belongs to. Without it the list is refetched. */
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

/** The request in an event: a full one, or the API's short form widened to an open request. */
function asRequest(v: unknown): PendingRequest | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const r = v as Record<string, unknown>;
  if (
    !isNum(r["id"]) ||
    !isStr(r["sandbox"]) ||
    !isStr(r["host"]) ||
    !isNum(r["port"]) ||
    !isNum(r["first_seen"]) ||
    !isNum(r["last_seen"]) ||
    !isNum(r["attempts"])
  ) {
    return undefined;
  }
  if (isStr(r["state"])) return v as PendingRequest;
  return {
    id: r["id"],
    sandbox: r["sandbox"] as PendingRequest["sandbox"],
    host: r["host"],
    port: r["port"],
    first_seen: r["first_seen"],
    last_seen: r["last_seen"],
    attempts: r["attempts"],
    state: "requested",
    decided_at: null,
    decided_by: null,
    rule_id: null,
    blocked_by: null,
  };
}

/** The group of an opened request: on the event, or on the request itself. */
function domainOf(e: Record<string, unknown>): string | null {
  const inner = e["request"] as Record<string, unknown>;
  for (const holder of [e, inner]) {
    const domain = holder["registrable_domain"];
    if (isStr(domain) && domain !== "") return domain;
  }
  return null;
}

/** The event as an inbox event, or `undefined` for any other or malformed event. */
export function asInboxEvent(value: unknown): InboxEvent | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const e = value as Record<string, unknown>;
  switch (e["type"]) {
    case "pending_opened": {
      const request = asRequest(e["request"]);
      if (!request) return undefined;
      return {
        type: "pending_opened",
        request,
        registrable_domain: domainOf(e),
      };
    }
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
