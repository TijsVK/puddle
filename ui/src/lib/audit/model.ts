// SPDX-License-Identifier: GPL-3.0-or-later
// What the activity screen shows of an audit record, and how its filters turn into an API query
// and a page address. Pure: nothing here touches the page or the network.
import type { components } from "#lib/api/schema.d.ts";

type Schemas = components["schemas"];
export type AuditEntry = Schemas["AuditEntry"];
export type AuditRecord = Schemas["AuditRecord"];
export type AuditType = Schemas["AuditType"];
export type AuditOutcome = Schemas["AuditOutcome"];

/** The newest matching records come first and the log is read back from there. */
export const PAGE_SIZE = 200;
/** The API's cap per page, used when the whole filtered log is exported. */
export const EXPORT_PAGE_SIZE = 500;

export type RangeKey = "1h" | "24h" | "7d" | "all";

export const RANGES: readonly { key: RangeKey; label: string; ms: number }[] = [
  { key: "1h", label: "Last hour", ms: 3_600_000 },
  { key: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { key: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { key: "all", label: "Everything", ms: 0 },
];

export const DEFAULT_RANGE: RangeKey = "24h";

export interface Filter {
  /** A workspace's name; empty for all. */
  sandbox: string;
  type: AuditType | "";
  outcome: AuditOutcome | "";
  /** Text the host (or a rule's pattern) contains; empty for all. */
  host: string;
  range: RangeKey;
}

export const NO_FILTER: Filter = {
  sandbox: "",
  type: "",
  outcome: "",
  host: "",
  range: DEFAULT_RANGE,
};

export const TYPES: readonly { value: AuditType; label: string }[] = [
  { value: "connection", label: "Connection" },
  { value: "pending_created", label: "Request opened" },
  { value: "pending_decided", label: "Request decided" },
  { value: "pending_expired", label: "Request expired" },
  { value: "pending_suppressed", label: "Requests held back" },
  { value: "rule_created", label: "Rule added" },
  { value: "rule_updated", label: "Rule changed" },
  { value: "rule_deleted", label: "Rule deleted" },
  { value: "rule_expired", label: "Rule expired" },
  { value: "audit_trimmed", label: "Log trimmed" },
];

export const OUTCOMES: readonly { value: AuditOutcome; label: string }[] = [
  { value: "allow", label: "Allowed" },
  { value: "deny", label: "Denied" },
  { value: "pending", label: "Waiting" },
  { value: "blocked", label: "Blocked" },
  { value: "expired", label: "Expired" },
];

const typeLabels = new Map(TYPES.map((t) => [t.value, t.label]));
const outcomeLabels = new Map(OUTCOMES.map((o) => [o.value, o.label]));

export function typeLabel(type: AuditType): string {
  return typeLabels.get(type) ?? type;
}

export function outcomeLabel(outcome: AuditOutcome): string {
  return outcomeLabels.get(outcome) ?? outcome;
}

/** True when any filter differs from the screen's defaults (the "Clear filters" button shows). */
export function isFiltered(filter: Filter): boolean {
  return (
    filter.sandbox !== "" ||
    filter.type !== "" ||
    filter.outcome !== "" ||
    filter.host.trim() !== "" ||
    filter.range !== DEFAULT_RANGE
  );
}

/** True when the filter leaves out part of the log (so "no records" may just mean "none match"). */
export function isNarrowed(filter: Filter): boolean {
  return (
    filter.sandbox !== "" ||
    filter.type !== "" ||
    filter.outcome !== "" ||
    filter.host.trim() !== "" ||
    filter.range !== "all"
  );
}

/** The server-side filters of `GET /api/audit`; `now` fixes a relative range. */
export interface AuditQuery {
  sandbox?: string;
  type?: AuditType;
  outcome?: AuditOutcome;
  host_contains?: string;
  from?: number;
}

export function toQuery(filter: Filter, now: number): AuditQuery {
  const query: AuditQuery = {};
  if (filter.sandbox !== "") query.sandbox = filter.sandbox;
  if (filter.type !== "") query.type = filter.type;
  if (filter.outcome !== "") query.outcome = filter.outcome;
  const host = filter.host.trim();
  if (host !== "") query.host_contains = host;
  const range = RANGES.find((r) => r.key === filter.range);
  if (range && range.ms > 0) query.from = now - range.ms;
  return query;
}

/** The page address's query string for a filter (`""` when it is the default view). */
export function toSearch(filter: Filter): string {
  const params = new URLSearchParams();
  if (filter.sandbox !== "") params.set("workspace", filter.sandbox);
  if (filter.type !== "") params.set("type", filter.type);
  if (filter.outcome !== "") params.set("outcome", filter.outcome);
  if (filter.host.trim() !== "") params.set("host", filter.host.trim());
  if (filter.range !== DEFAULT_RANGE) params.set("range", filter.range);
  const text = params.toString();
  return text === "" ? "" : `?${text}`;
}

/** A filter from a page address; anything it does not recognise is left at the default. */
export function fromSearch(search: string): Filter {
  const params = new URLSearchParams(search);
  const type = params.get("type");
  const outcome = params.get("outcome");
  const range = params.get("range");
  return {
    sandbox: params.get("workspace") ?? "",
    type: TYPES.some((t) => t.value === type) ? (type as AuditType) : "",
    outcome: OUTCOMES.some((o) => o.value === outcome)
      ? (outcome as AuditOutcome)
      : "",
    host: params.get("host") ?? "",
    range: RANGES.some((r) => r.key === range)
      ? (range as RangeKey)
      : DEFAULT_RANGE,
  };
}

export type Tone = "allow" | "deny" | "warn" | "neutral";

/** One record as a table row reads it. Every string can quote a guest and is shown as text only. */
export interface RowView {
  /** Epoch ms. */
  ts: number;
  /** The workspace; `null` for what is not about one (a global rule, a trim). */
  workspace: string | null;
  type: string;
  /** The host (and port), or a rule's pattern; `null` when there is none. */
  destination: string | null;
  outcome: { label: string; tone: Tone } | null;
  /** What else is worth a glance: why, how much, which rule. */
  detail: string;
}

const REASONS: Record<string, string> = {
  rule: "a rule",
  no_rule: "no rule yet",
  puddle_endpoint: "puddle's own address",
  ssh_unsupported: "SSH is not supported",
  local_address: "a local address",
  puddle_request: "puddle's own request",
};

const DECISIONS: Record<string, { label: string; tone: Tone }> = {
  allow: { label: "Allowed", tone: "allow" },
  deny: { label: "Denied", tone: "deny" },
  pending: { label: "Waiting", tone: "warn" },
  blocked: { label: "Blocked", tone: "deny" },
};

/** `1.5 MB`, in powers of 1024 as file sizes read. */
export function bytesLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const text = value >= 10 ? value.toFixed(0) : value.toFixed(1);
  return `${text} ${units[unit]}`;
}

function endpoint(host: string | null, port: number | null): string | null {
  if (host === null) return null;
  return port === null ? host : `${host}:${port}`;
}

function ruleLabel(rule: Schemas["AuditRule"]): string {
  const where =
    rule.scope === "global"
      ? "every workspace"
      : `workspace ${rule.sandbox_id ?? "?"}`;
  return `${rule.effect} for ${where}`;
}

function pendingOutcome(state: string): RowView["outcome"] {
  if (state === "allowed") return DECISIONS["allow"] ?? null;
  if (state === "denied") return DECISIONS["deny"] ?? null;
  if (state === "expired") return { label: "Expired", tone: "neutral" };
  return DECISIONS["pending"] ?? null;
}

function connectionDetail(
  record: Extract<AuditRecord, { type: "connection" }>,
): string {
  const parts: string[] = [];
  if (record.method !== null) {
    parts.push(`${record.method} ${record.path ?? ""}`.trim());
  }
  const reason = REASONS[record.reason] ?? record.reason;
  parts.push(
    record.rule_id !== null ? `rule ${record.rule_id}` : `because ${reason}`,
  );
  if (record.bytes_up > 0 || record.bytes_down > 0) {
    parts.push(
      `${bytesLabel(record.bytes_up)} up, ${bytesLabel(record.bytes_down)} down`,
    );
  }
  if (record.injected) parts.push("credential added");
  return parts.join(" · ");
}

/** How a record reads as a row. */
export function describe(record: AuditRecord): RowView {
  const type = typeLabel(record.type);
  switch (record.type) {
    case "connection":
      return {
        ts: record.ts,
        workspace: record.sandbox_id,
        type,
        destination: endpoint(record.host, record.port),
        outcome:
          record.decision === null
            ? null
            : (DECISIONS[record.decision] ?? null),
        detail: connectionDetail(record),
      };
    case "pending_created":
    case "pending_decided":
    case "pending_expired": {
      const p = record.pending;
      const detail =
        record.type === "pending_expired"
          ? `expired: ${record.reason}`
          : record.type === "pending_decided"
            ? `by ${p.decided_by ?? "unknown"}${p.rule_id === null ? "" : `, rule ${p.rule_id}`}`
            : p.attempts > 1
              ? `${p.attempts} attempts`
              : "";
      return {
        ts: record.ts,
        workspace: p.sandbox_id,
        type,
        destination: endpoint(p.host, p.port),
        outcome:
          record.type === "pending_created"
            ? pendingOutcome("requested")
            : record.type === "pending_expired"
              ? pendingOutcome("expired")
              : pendingOutcome(p.state),
        detail,
      };
    }
    case "pending_suppressed":
      return {
        ts: record.ts,
        workspace: record.sandbox_id,
        type,
        destination: null,
        outcome: null,
        detail: `${record.count} requests held back`,
      };
    case "rule_created":
    case "rule_expired":
    case "rule_deleted":
    case "rule_updated": {
      const detail =
        record.type === "rule_deleted"
          ? `${ruleLabel(record.rule)}, by ${record.actor}, ${record.reason}`
          : record.type === "rule_updated"
            ? `${ruleLabel(record.rule)}, by ${record.actor}`
            : `${ruleLabel(record.rule)}${record.type === "rule_created" ? `, by ${record.rule.created_by}` : ""}`;
      return {
        ts: record.ts,
        workspace: record.rule.sandbox_id,
        type,
        destination: record.rule.pattern,
        outcome: null,
        detail,
      };
    }
    case "audit_trimmed":
      return {
        ts: record.ts,
        workspace: null,
        type,
        destination: null,
        outcome: null,
        detail: `${record.deleted_records} older records deleted`,
      };
  }
}

/** The record as the API sent it, indented, for the row's expanded view. */
export function rawJson(record: AuditRecord): string {
  return JSON.stringify(record, null, 2);
}

/** One export line: the record exactly as the API sent it. */
export function jsonLine(record: AuditRecord): string {
  return `${JSON.stringify(record)}\n`;
}

/** `puddle-activity-2026-10-07T12-00-00.jsonl`. */
export function exportName(now: number): string {
  return `puddle-activity-${new Date(now).toISOString().slice(0, 19).replaceAll(":", "-")}.jsonl`;
}
