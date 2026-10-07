// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { narrowest } from "#lib/decision/model.ts";
import { FakeInbox, FakeSource, request } from "#lib/testing/fake-inbox.ts";
import {
  PendingStore,
  groupRows,
  limitGroups,
  type Row,
} from "./pending.svelte.ts";

function setup(over: { pollMs?: number; slowPollMs?: number } = {}) {
  const inbox = new FakeInbox();
  const source = new FakeSource();
  const counts: number[] = [];
  const store = new PendingStore({
    api: inbox as never,
    source,
    now: () => 42,
    onCount: (n) => counts.push(n),
    ...over,
  });
  return { inbox, source, store, counts };
}

const rowOf = (store: PendingStore, id: number): Row => {
  const row = store.rows.find((r) => r.request.id === id);
  if (!row) throw new Error(`no row ${id}`);
  return row;
};

describe("groupRows", () => {
  it("groups by domain, newest group first, newest row first inside", () => {
    const rows: Row[] = [
      { request: request(1), domain: "a.com" },
      { request: request(2), domain: "b.com" },
      { request: request(3), domain: "a.com" },
      { request: request(4, { first_seen: 1_000_010 }), domain: "c.com" },
    ];
    const groups = groupRows(rows);
    expect(groups.map((g) => g.domain)).toEqual(["c.com", "a.com", "b.com"]);
    expect(groups[1]?.rows.map((r) => r.request.id)).toEqual([3, 1]);
  });

  it("is empty for no rows", () => {
    expect(groupRows([])).toEqual([]);
  });
});

describe("limitGroups", () => {
  const rows = (n: number, domain: string, from = 1): Row[] =>
    Array.from({ length: n }, (_, i) => ({
      request: request(from + i),
      domain,
    }));
  const groups = groupRows([...rows(3, "a.com", 1), ...rows(2, "b.com", 10)]);

  it("keeps the first rows in order, with each group's full count", () => {
    const shown = limitGroups(groups, 4);
    expect(shown.map((g) => [g.domain, g.rows.length, g.total])).toEqual([
      [
        groups[0]?.domain,
        Math.min(4, groups[0]?.rows.length ?? 0),
        groups[0]?.rows.length,
      ],
      [
        groups[1]?.domain,
        4 - (groups[0]?.rows.length ?? 0),
        groups[1]?.rows.length,
      ],
    ]);
  });

  it("drops groups that have no row left, and shows everything when the limit is large", () => {
    expect(limitGroups(groups, 2)).toHaveLength(1);
    expect(limitGroups(groups, 0)).toEqual([]);
    expect(limitGroups(groups, 99).flatMap((g) => g.rows)).toHaveLength(5);
  });
});

describe("refresh", () => {
  it("loads the groups, the held-back counters and tells the badge the count", async () => {
    const { inbox, store, counts } = setup();
    inbox.add(request(1), "example.com");
    inbox.add(request(2, { sandbox: "other" as never }), "example.com");
    inbox.suppression["demo"] = { active: true, count: 12 };
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.count).toBe(2);
    expect(store.groups).toHaveLength(1);
    expect(store.workspaces).toEqual(["demo", "other"]);
    expect(store.suppression["demo"]).toMatchObject({
      active: true,
      count: 12,
    });
    expect(store.suppression["other"]).toMatchObject({ active: false });
    expect(counts).toEqual([2]);
  });

  it("says it failed on the first failure, and keeps what it has after a later one", async () => {
    const { inbox, store } = setup();
    inbox.down = true;
    await store.refresh();
    expect(store.status).toBe("failed");
    inbox.down = false;
    inbox.add(request(1));
    await store.refresh();
    expect(store.status).toBe("ready");
    inbox.down = true;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.count).toBe(1);
  });

  it("treats a non-OK answer like a failure", async () => {
    const { inbox, store } = setup();
    inbox.GET = (async () => ({
      error: {},
      response: { status: 500, ok: false },
    })) as never;
    await store.refresh();
    expect(store.status).toBe("failed");
  });

  it("shares a run between concurrent calls and runs once more afterwards", async () => {
    const { inbox, store } = setup();
    inbox.add(request(1));
    const a = store.refresh();
    const b = store.refresh();
    expect(b).toBe(a);
    await a;
    await vi.waitFor(() =>
      expect(inbox.calls.filter((c) => c === "GET /api/inbox")).toHaveLength(2),
    );
  });

  it("reads a workspace's local toggles only for rows that are local, and blocks them when off", async () => {
    const { inbox, store } = setup();
    inbox.add(request(1, { host: "192.168.1.10" }), "192.168.1.10");
    inbox.add(
      request(2, { host: "10.0.0.5", sandbox: "lab" as never }),
      "10.0.0.5",
    );
    inbox.add(request(3, { host: "8.8.8.8" }), "8.8.8.8");
    inbox.toggles["demo"] = { private: false };
    inbox.toggles["lab"] = { private: true };
    await store.refresh();
    expect(store.blockedBy(rowOf(store, 1).request)).toBe("private");
    expect(store.blockedBy(rowOf(store, 2).request)).toBeNull();
    expect(store.blockedBy(rowOf(store, 3).request)).toBeNull();
    expect(inbox.calls.filter((c) => c.includes("settings"))).toHaveLength(2);
  });

  it("does not block when the settings can't be read", async () => {
    const { inbox, store } = setup();
    inbox.add(request(1, { host: "192.168.1.10" }), "192.168.1.10");
    await store.refresh();
    expect(store.toggles["demo"]).toBeNull();
    expect(store.blockedBy(rowOf(store, 1).request)).toBeNull();
  });

  it("copes with a suppression or settings call that throws", async () => {
    const { inbox, store } = setup();
    inbox.add(request(1, { host: "192.168.1.10" }), "192.168.1.10");
    const get = inbox.GET;
    inbox.GET = (async (path: string, init: never) => {
      if (path !== "/api/inbox") throw new TypeError("down");
      return get(path, init);
    }) as never;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.suppression).toEqual({});
    expect(store.toggles["demo"]).toBeNull();
  });
});

describe("events", () => {
  it("opens, updates and closes rows in place without a refetch", async () => {
    const { inbox, source, store, counts } = setup();
    inbox.add(request(1), "example.com");
    store.start();
    await vi.waitFor(() => expect(store.status).toBe("ready"));
    const before = inbox.calls.length;

    source.emit({
      type: "pending_opened",
      request: request(2, { host: "x.other.org" }),
      registrable_domain: "other.org",
    });
    expect(store.groups.map((g) => g.domain).sort()).toEqual([
      "example.com",
      "other.org",
    ]);
    source.emit({ type: "pending_updated", id: 2, attempts: 5, last_seen: 77 });
    expect(rowOf(store, 2).request).toMatchObject({
      attempts: 5,
      last_seen: 77,
    });
    source.emit({
      type: "pending_updated",
      id: 99,
      attempts: 5,
      last_seen: 77,
    });
    source.emit({
      type: "pending_closed",
      id: 1,
      state: "allowed",
      rule_id: 4,
    });
    expect(store.rows.map((r) => r.request.id)).toEqual([2]);
    source.emit({
      type: "suppression_changed",
      sandbox: "demo",
      active: true,
      count: 3,
    });
    expect(store.suppression["demo"]).toMatchObject({ active: true, count: 3 });
    source.emit({ type: "status_changed", sandbox: "demo", status: "running" });
    source.emit({
      type: "pending_opened",
      request: request(2),
      registrable_domain: "other.org",
    });
    expect(store.count).toBe(1);
    expect(counts.at(-1)).toBe(1);

    // Only the suppression lookup for a workspace not seen before is allowed to call out.
    expect(
      inbox.calls.slice(before).filter((c) => c === "GET /api/inbox"),
    ).toEqual([]);
  });

  it("looks up the group when an opened event doesn't carry it", async () => {
    vi.useFakeTimers();
    try {
      const { inbox, source, store } = setup();
      store.start();
      await vi.advanceTimersByTimeAsync(0);
      inbox.add(request(5), "example.com");
      source.emit({ type: "pending_opened", request: request(5) });
      expect(store.count).toBe(0);
      await vi.advanceTimersByTimeAsync(200);
      expect(store.count).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reads the toggles of a local request that arrives live", async () => {
    const { inbox, source, store } = setup();
    store.start();
    await vi.waitFor(() => expect(store.status).toBe("ready"));
    inbox.toggles["demo"] = { private: false };
    source.emit({
      type: "pending_opened",
      request: request(8, { host: "10.1.1.1" }),
      registrable_domain: "10.1.1.1",
    });
    await vi.waitFor(() =>
      expect(store.blockedBy(rowOf(store, 8).request)).toBe("private"),
    );
  });

  it("applies events that arrive during a refetch after it, so nothing is lost", async () => {
    const { inbox, source, store } = setup();
    inbox.add(request(1), "example.com");
    store.start();
    await vi.waitFor(() => expect(store.status).toBe("ready"));

    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const get = inbox.GET;
    inbox.GET = (async (path: string, init: never) => {
      const out = await get(path, init);
      if (path === "/api/inbox") await gate;
      return out;
    }) as never;
    source.resync();
    source.emit({
      type: "pending_closed",
      id: 1,
      state: "allowed",
      rule_id: 1,
    });
    expect(store.count).toBe(1);
    release();
    await vi.waitFor(() => expect(store.count).toBe(0));
  });
});

describe("converging after the stream is lost", () => {
  it("a resync fetches what happened meanwhile", async () => {
    const { inbox, source, store } = setup();
    inbox.add(request(1), "example.com");
    store.start();
    await vi.waitFor(() => expect(store.count).toBe(1));
    // The stream is down: three requests open and one is decided elsewhere, with no events.
    inbox.add(request(2), "example.com");
    inbox.add(request(3), "example.com");
    inbox.open = inbox.open.filter((o) => o.request.id !== 1);
    source.resync();
    await vi.waitFor(() =>
      expect(store.rows.map((r) => r.request.id).sort()).toEqual([2, 3]),
    );
  });
});

describe("polling", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("polls while no pending events come, slows down once they do, and stops when stopped", async () => {
    const { inbox, source, store } = setup({
      pollMs: 1000,
      slowPollMs: 10_000,
    });
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    const polls = () =>
      inbox.calls.filter((c) => c === "GET /api/inbox").length;
    expect(polls()).toBe(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(polls()).toBe(2);

    inbox.add(request(1), "example.com");
    await vi.advanceTimersByTimeAsync(1000);
    expect(store.count).toBe(1);

    source.emit({ type: "pending_updated", id: 1, attempts: 2, last_seen: 5 });
    await vi.advanceTimersByTimeAsync(1000); // the already-scheduled tick still fires
    const afterSwitch = polls();
    await vi.advanceTimersByTimeAsync(5000);
    expect(polls()).toBe(afterSwitch);
    await vi.advanceTimersByTimeAsync(5000);
    expect(polls()).toBe(afterSwitch + 1);

    stop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(polls()).toBe(afterSwitch + 1);
    expect(source.listeners.size).toBe(0);
  });

  it("works without a source", async () => {
    const inbox = new FakeInbox();
    const store = new PendingStore({ api: inbox as never, pollMs: 500 });
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(600);
    expect(inbox.calls.length).toBeGreaterThan(1);
    stop();
  });

  it("stopped before the first load finishes, it never schedules a poll", async () => {
    const inbox = new FakeInbox();
    const store = new PendingStore({ api: inbox as never, pollMs: 500 });
    const stop = store.start();
    stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(inbox.calls.filter((c) => c === "GET /api/inbox")).toHaveLength(1);
  });
});

describe("decide", () => {
  async function loaded() {
    const s = setup();
    s.inbox.add(request(1, { host: "a.example.com" }), "example.com");
    s.inbox.add(request(2, { host: "b.example.com" }), "example.com");
    s.inbox.add(
      request(3, { host: "a.example.com", sandbox: "other" as never }),
      "example.com",
    );
    await s.store.refresh();
    return s;
  }

  it("approves one host in one workspace and records it for undo", async () => {
    const { store, inbox } = await loaded();
    const result = await store.decide(
      rowOf(store, 1),
      narrowest("allow"),
      false,
    );
    expect(result).toMatchObject({
      ok: true,
      decided: {
        effect: "allow",
        pattern: "a.example.com",
        patternKind: "exact",
        workspace: "demo",
        alsoClosed: 0,
        at: 42,
      },
    });
    expect(inbox.calls).toContain("POST /api/pending/{id}/approve");
    expect(store.rows.map((r) => r.request.id)).toEqual([2, 3]);
    expect(store.decided).toHaveLength(1);
  });

  it("closes the other rows the new rule decides (also_closed), for a suffix and a global rule", async () => {
    const { store } = await loaded();
    const result = await store.decide(
      rowOf(store, 1),
      {
        effect: "deny",
        scope: "global",
        ruleSet: null,
        match: "suffix",
        durationSecs: 3600,
      },
      true,
    );
    expect(result).toMatchObject({
      ok: true,
      decided: {
        effect: "deny",
        workspace: null,
        patternKind: "suffix",
        alsoClosed: 2,
        expiresAt: 5_000_000,
      },
    });
    expect(store.count).toBe(0);
  });

  it("puts the rule into a rule set when asked, and says so", async () => {
    const { store } = await loaded();
    const result = await store.decide(
      rowOf(store, 1),
      {
        ...narrowest("allow"),
        ruleSet: { id: 4, name: "Client X", everywhere: false },
      },
      false,
    );
    expect(result).toMatchObject({
      ok: true,
      decided: { workspace: null, ruleSet: "Client X" },
    });
  });

  it("keeps at most eight decided entries, newest first", async () => {
    const { store, inbox } = setup();
    for (let i = 1; i <= 10; i += 1) inbox.add(request(i), `d${i}.com`);
    await store.refresh();
    for (let i = 1; i <= 10; i += 1)
      await store.decide(rowOf(store, i), narrowest("allow"), false);
    expect(store.decided).toHaveLength(8);
    expect(store.decided[0]?.pattern).toBe("h10.example.com");
  });

  it("refuses a global choice that was not confirmed, without calling the API", async () => {
    const { store, inbox } = await loaded();
    const before = inbox.calls.length;
    const result = await store.decide(
      rowOf(store, 1),
      { ...narrowest("allow"), scope: "global" },
      false,
    );
    expect(result).toMatchObject({ ok: false, reason: "invalid" });
    expect(inbox.calls.length).toBe(before);
  });

  it("answers a stale request (409, 404) by refetching", async () => {
    const { store, inbox } = await loaded();
    inbox.nextDecisionStatus = 409;
    inbox.open = inbox.open.filter((o) => o.request.id !== 1);
    const result = await store.decide(
      rowOf(store, 1),
      narrowest("allow"),
      false,
    );
    expect(result).toMatchObject({ ok: false, reason: "stale" });
    await vi.waitFor(() => expect(store.count).toBe(2));
    inbox.nextDecisionStatus = 404;
    expect(
      await store.decide(rowOf(store, 2), narrowest("deny"), false),
    ).toMatchObject({ reason: "stale" });
  });

  it("reports other failures with the server's message, and a dead service", async () => {
    const { store, inbox } = await loaded();
    inbox.nextDecisionStatus = 500;
    expect(
      await store.decide(rowOf(store, 1), narrowest("allow"), false),
    ).toEqual({
      ok: false,
      reason: "failed",
      message: "refused",
    });
    inbox.down = true;
    expect(
      await store.decide(rowOf(store, 1), narrowest("allow"), false),
    ).toMatchObject({
      ok: false,
      reason: "failed",
      message: "puddle's service isn't answering.",
    });
  });

  it("falls back to a generic message when the error has no body", async () => {
    const { store, inbox } = await loaded();
    inbox.POST = (async () => ({
      response: { status: 500, ok: false },
    })) as never;
    expect(
      await store.decide(rowOf(store, 1), narrowest("allow"), false),
    ).toMatchObject({
      message: "puddle's service refused the decision.",
    });
  });
});

describe("undo", () => {
  it("deletes the rule and drops the entry; a rule already gone counts as undone", async () => {
    const { store, inbox } = setup();
    inbox.add(request(1));
    inbox.add(request(2));
    await store.refresh();
    const first = await store.decide(
      rowOf(store, 1),
      narrowest("allow"),
      false,
    );
    const second = await store.decide(
      rowOf(store, 2),
      narrowest("allow"),
      false,
    );
    if (!first.ok || !second.ok) throw new Error("decide failed");
    expect(await store.undo(first.decided)).toEqual({ ok: true });
    expect(inbox.rules).toHaveLength(1);
    inbox.rules = [];
    expect(await store.undo(second.decided)).toEqual({ ok: true });
    expect(store.decided).toEqual([]);
  });

  it("keeps the entry and says so when the service refuses or is down", async () => {
    const { store, inbox } = setup();
    inbox.add(request(1));
    await store.refresh();
    const r = await store.decide(rowOf(store, 1), narrowest("allow"), false);
    if (!r.ok) throw new Error("decide failed");
    inbox.DELETE = (async () => ({
      response: { status: 500, ok: false },
    })) as never;
    expect(await store.undo(r.decided)).toEqual({
      ok: false,
      message: "puddle couldn't undo that.",
    });
    inbox.down = true;
    inbox.DELETE = (async () => {
      throw new TypeError("down");
    }) as never;
    expect(await store.undo(r.decided)).toMatchObject({ ok: false });
    expect(store.decided).toHaveLength(1);
  });
});
