// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { connection } from "#lib/testing/fake-audit.ts";
import {
  DEFAULT_RANGE,
  NO_FILTER,
  OUTCOMES,
  TYPES,
  bytesLabel,
  describe as row,
  exportName,
  fromSearch,
  isFiltered,
  isNarrowed,
  jsonLine,
  outcomeLabel,
  rawJson,
  toQuery,
  toSearch,
  typeLabel,
  type AuditRecord,
  type Filter,
} from "./model.ts";

const rule = {
  id: 7,
  pattern: ".example.com",
  pattern_kind: "suffix",
  scope: "sandbox",
  sandbox_id: "shop",
  effect: "allow",
  expires_at: null,
  created_at: 1,
  created_by: "ui",
  source_pending_id: null,
};
const pending = {
  id: 3,
  sandbox_id: "shop",
  host: "evil.example.org",
  port: 8443,
  first_seen: 1,
  last_seen: 2,
  attempts: 1,
  state: "requested",
  decided_at: null,
  decided_by: null,
  rule_id: null,
};

describe("filters and the API query", () => {
  it("sends nothing for the defaults but the range", () => {
    expect(toQuery(NO_FILTER, 100_000_000)).toEqual({
      from: 100_000_000 - 86_400_000,
    });
    expect(toQuery({ ...NO_FILTER, range: "all" }, 5)).toEqual({});
  });
  it("sends every set filter, trimmed, and measures the range from now", () => {
    const filter: Filter = {
      sandbox: "shop",
      type: "connection",
      outcome: "deny",
      host: "  github  ",
      range: "1h",
    };
    expect(toQuery(filter, 10_000_000)).toEqual({
      sandbox: "shop",
      type: "connection",
      outcome: "deny",
      host_contains: "github",
      from: 10_000_000 - 3_600_000,
    });
  });
  it("knows when a filter is not the default view", () => {
    expect(isFiltered(NO_FILTER)).toBe(false);
    expect(isFiltered({ ...NO_FILTER, host: "  " })).toBe(false);
    for (const change of [
      { sandbox: "a" },
      { type: "connection" },
      { outcome: "allow" },
      { host: "x" },
      { range: "7d" },
    ] as Partial<Filter>[]) {
      expect(isFiltered({ ...NO_FILTER, ...change })).toBe(true);
    }
  });
});

describe("isNarrowed", () => {
  it("is false only when nothing is left out of the log", () => {
    expect(isNarrowed({ ...NO_FILTER, range: "all" })).toBe(false);
    expect(isNarrowed(NO_FILTER)).toBe(true);
    expect(isNarrowed({ ...NO_FILTER, range: "all", host: "  " })).toBe(false);
    for (const change of [
      { sandbox: "a" },
      { type: "connection" },
      { outcome: "allow" },
      { host: "x" },
    ] as Partial<Filter>[]) {
      expect(isNarrowed({ ...NO_FILTER, range: "all", ...change })).toBe(true);
    }
  });
});

describe("the page address", () => {
  it("is empty for the default view", () => {
    expect(toSearch(NO_FILTER)).toBe("");
    expect(fromSearch("")).toEqual(NO_FILTER);
  });
  it("round-trips every filter, whatever the host holds", () => {
    const filter: Filter = {
      sandbox: "shop",
      type: "rule_created",
      outcome: "blocked",
      host: "a&b=c d",
      range: "all",
    };
    expect(fromSearch(toSearch(filter))).toEqual(filter);
    for (const t of TYPES)
      expect(fromSearch(toSearch({ ...NO_FILTER, type: t.value })).type).toBe(
        t.value,
      );
    for (const o of OUTCOMES)
      expect(
        fromSearch(toSearch({ ...NO_FILTER, outcome: o.value })).outcome,
      ).toBe(o.value);
  });
  it("drops what it does not recognise instead of failing", () => {
    expect(fromSearch("?type=nope&outcome=x&range=forever&other=1")).toEqual({
      ...NO_FILTER,
      range: DEFAULT_RANGE,
    });
  });
});

describe("labels", () => {
  it("names every type and outcome, and passes an unknown one through", () => {
    expect(typeLabel("pending_created")).toBe("Request opened");
    expect(outcomeLabel("allow")).toBe("Allowed");
    expect(typeLabel("later" as never)).toBe("later");
    expect(outcomeLabel("later" as never)).toBe("later");
  });
  it("prints sizes in powers of 1024", () => {
    expect(bytesLabel(0)).toBe("0 B");
    expect(bytesLabel(1023)).toBe("1023 B");
    expect(bytesLabel(1536)).toBe("1.5 KB");
    expect(bytesLabel(20 * 1024)).toBe("20 KB");
    expect(bytesLabel(2 * 1024 * 1024)).toBe("2.0 MB");
    expect(bytesLabel(5 * 1024 ** 5)).toBe("5120 TB");
  });
});

describe("a record as a row", () => {
  it("shows a connection with its outcome, reason and size", () => {
    const view = row(
      connection(1, { bytes_up: 2048, bytes_down: 3 * 1024 * 1024 }).record,
    );
    expect(view).toMatchObject({
      workspace: "demo",
      type: "Connection",
      destination: "h1.example.com:443",
      outcome: { label: "Allowed", tone: "allow" },
    });
    expect(view.detail).toBe("rule 1 · 2.0 KB up, 3.0 MB down");
  });
  it("explains a block, a waiting request and a request line", () => {
    const blocked = row(
      connection(1, {
        decision: "blocked",
        reason: "local_address",
        rule_id: null,
        method: "GET",
        path: "/x",
        injected: true,
      }).record,
    );
    expect(blocked.outcome).toEqual({ label: "Blocked", tone: "deny" });
    expect(blocked.detail).toBe(
      "GET /x · because a local address · credential added",
    );
    const waiting = row(
      connection(2, { decision: "pending", reason: "no_rule", rule_id: null })
        .record,
    );
    expect(waiting.outcome).toEqual({ label: "Waiting", tone: "warn" });
    expect(waiting.detail).toBe("because no rule yet");
    const odd = row(
      connection(3, {
        reason: "something_new",
        rule_id: null,
        method: "PUT",
        path: null,
      }).record,
    );
    expect(odd.detail).toBe("PUT · because something_new");
  });
  it("leaves the outcome and the address out when the record has none", () => {
    const view = row(
      connection(1, { decision: null, host: null, port: null }).record,
    );
    expect(view.outcome).toBeNull();
    expect(view.destination).toBeNull();
    expect(
      row(connection(1, { host: "a.test", port: null }).record).destination,
    ).toBe("a.test");
  });
  it("shows the three request records", () => {
    const created = row({
      type: "pending_created",
      ts: 1,
      pending,
    } as AuditRecord);
    expect(created).toMatchObject({
      workspace: "shop",
      destination: "evil.example.org:8443",
      outcome: { label: "Waiting" },
      detail: "",
    });
    expect(
      row({
        type: "pending_created",
        ts: 1,
        pending: { ...pending, attempts: 4 },
      } as AuditRecord).detail,
    ).toBe("4 attempts");
    const decided = (state: string, by: string | null, ruleId: number | null) =>
      row({
        type: "pending_decided",
        ts: 1,
        pending: { ...pending, state, decided_by: by, rule_id: ruleId },
      } as AuditRecord);
    expect(decided("allowed", "ui", 9)).toMatchObject({
      outcome: { label: "Allowed", tone: "allow" },
      detail: "by ui, rule 9",
    });
    expect(decided("denied", null, null)).toMatchObject({
      outcome: { label: "Denied", tone: "deny" },
      detail: "by unknown",
    });
    const expired = row({
      type: "pending_expired",
      ts: 1,
      pending,
      reason: "timeout",
    } as unknown as AuditRecord);
    expect(expired).toMatchObject({
      outcome: { label: "Expired", tone: "neutral" },
      detail: "expired: timeout",
    });
  });
  it("shows rule changes by pattern and scope, with no outcome", () => {
    const base = { ts: 1, rule };
    expect(row({ ...base, type: "rule_created" } as AuditRecord)).toMatchObject(
      {
        workspace: "shop",
        destination: ".example.com",
        outcome: null,
        detail: "allow for workspace shop, by ui",
      },
    );
    expect(
      row({
        ...base,
        type: "rule_expired",
        rule: { ...rule, scope: "global", sandbox_id: null },
      } as AuditRecord),
    ).toMatchObject({
      workspace: null,
      detail: "allow for every workspace",
    });
    expect(
      row({
        ...base,
        type: "rule_updated",
        actor: "cli",
        before: rule,
      } as unknown as AuditRecord).detail,
    ).toBe("allow for workspace shop, by cli");
    expect(
      row({
        ...base,
        type: "rule_deleted",
        actor: "ui",
        reason: "user",
        rule: { ...rule, sandbox_id: null },
      } as unknown as AuditRecord).detail,
    ).toBe("allow for workspace ?, by ui, user");
  });
  it("shows the two records that belong to no host", () => {
    expect(
      row({
        type: "pending_suppressed",
        ts: 1,
        sandbox_id: "shop",
        count: 40,
      } as AuditRecord),
    ).toMatchObject({
      workspace: "shop",
      destination: null,
      detail: "40 requests held back",
    });
    expect(
      row({
        type: "audit_trimmed",
        ts: 1,
        deleted_records: 12,
        oldest_ts_kept: null,
      } as AuditRecord),
    ).toMatchObject({ workspace: null, detail: "12 older records deleted" });
  });
});

describe("raw records and export lines", () => {
  const { record } = connection(1, { host: 'a"b.test' });
  it("indents the raw record and keeps a hostile host as text", () => {
    expect(rawJson(record)).toContain('\n  "host": "a\\"b.test"');
    expect(JSON.parse(rawJson(record))).toEqual(record);
  });
  it("writes one line per record, exactly as the API sent it", () => {
    const line = jsonLine(record);
    expect(line.endsWith("\n")).toBe(true);
    expect(line.slice(0, -1)).not.toContain("\n");
    expect(JSON.parse(line)).toEqual(record);
  });
  it("names the file after the moment, with no characters a file system refuses", () => {
    expect(exportName(Date.UTC(2026, 9, 7, 12, 0, 5))).toBe(
      "puddle-activity-2026-10-07T12-00-05.jsonl",
    );
  });
});
