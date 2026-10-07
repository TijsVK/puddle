// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for `GET /api/audit` and `GET /api/workspaces`, for unit and component tests, in the
// shape openapi-fetch returns them. It filters and pages like the API does. Not shipped (tests
// import it).
import type { components } from "#lib/api/schema.d.ts";
import type { AuditEntry, AuditRecord } from "#lib/audit/model.ts";

type Connection = Extract<AuditRecord, { type: "connection" }>;

/** A connection record; `id` and `ts` rise together. */
export function connection(
  id: number,
  over: Partial<Connection> = {},
): AuditEntry {
  return {
    id,
    record: {
      type: "connection",
      ts: 1_000_000 + id * 1000,
      sandbox_id: "demo",
      origin: "sandbox",
      host: `h${id}.example.com`,
      port: 443,
      decision: "allow",
      reason: "rule",
      rule_id: 1,
      rule_set: null,
      pending_id: null,
      binding_id: null,
      bytes_up: 0,
      bytes_down: 0,
      count: null,
      injected: false,
      method: null,
      path: null,
      path_truncated: false,
      resolved_ip: null,
      upstream: null,
      ...over,
    },
  };
}

function hostOf(record: AuditRecord): string {
  if (record.type === "connection") return record.host ?? "";
  if ("pending" in record) return record.pending.host;
  if ("rule" in record) return record.rule.pattern;
  return "";
}

function sandboxOf(record: AuditRecord): string | null {
  if (record.type === "connection") return record.sandbox_id;
  if (record.type === "pending_suppressed") return record.sandbox_id;
  if ("pending" in record) return record.pending.sandbox_id;
  if ("rule" in record) return record.rule.sandbox_id;
  return null;
}

function outcomeOf(record: AuditRecord): string | null {
  if (record.type === "connection") return record.decision;
  if (record.type === "pending_created") return "pending";
  return null;
}

export interface AuditQuery {
  sandbox?: string;
  type?: string;
  outcome?: string;
  host_contains?: string;
  from?: number;
  to?: number;
  before?: number;
  after?: number;
  limit?: number;
}

export class FakeAudit {
  /** Oldest first, ids ascending. */
  entries: AuditEntry[] = [];
  workspaces: string[] = [];
  /** The queries of every audit read, in order. */
  queries: AuditQuery[] = [];
  down = false;
  /** Answer the next audit read with this status. */
  failNext: number | null = null;
  /** Audit reads wait for this before they answer. */
  gate: Promise<void> | null = null;

  private reply(status: number, data?: unknown) {
    const response = { status, ok: status < 400 } as Response;
    return status < 400
      ? { data, response }
      : { error: { error: "internal", message: "refused" }, response };
  }

  GET = async (
    path: string,
    init?: { params?: { query?: AuditQuery } },
  ): Promise<unknown> => {
    if (this.down) throw new TypeError("down");
    if (path === "/api/workspaces") {
      return this.reply(200, {
        workspaces: this.workspaces.map((name) => ({ name, id: name })),
      } satisfies {
        workspaces: Partial<components["schemas"]["Workspace"]>[];
      });
    }
    const query = init?.params?.query ?? {};
    this.queries.push(query);
    await this.gate;
    if (this.failNext !== null) {
      const status = this.failNext;
      this.failNext = null;
      return this.reply(status);
    }
    const limit = Math.min(query.limit ?? 100, 500);
    const matches = this.entries.filter(
      ({ record }) =>
        (query.sandbox === undefined || sandboxOf(record) === query.sandbox) &&
        (query.type === undefined || record.type === query.type) &&
        (query.outcome === undefined || outcomeOf(record) === query.outcome) &&
        (query.host_contains === undefined ||
          hostOf(record)
            .toLowerCase()
            .includes(query.host_contains.toLowerCase())) &&
        (query.from === undefined || record.ts >= query.from) &&
        (query.to === undefined || record.ts < query.to),
    );
    if (query.after !== undefined) {
      const entries = matches
        .filter((e) => e.id > (query.after as number))
        .slice(0, limit);
      return this.reply(200, {
        entries,
        next_after: entries.at(-1)?.id ?? query.after,
        next_before: null,
      });
    }
    const older =
      query.before === undefined
        ? matches
        : matches.filter((e) => e.id < (query.before as number));
    const entries = older.slice(-limit).reverse();
    const full = older.length > limit;
    return this.reply(200, {
      entries,
      next_after: matches.at(-1)?.id ?? 0,
      next_before: full ? (entries.at(-1)?.id ?? null) : null,
    });
  };
}
