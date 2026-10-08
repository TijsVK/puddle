// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { NO_FILTER, type Filter } from "#lib/audit/model.ts";
import { FakeAudit, connection } from "#lib/testing/fake-audit.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { AuditStore } from "./audit.svelte.ts";

const ALL: Filter = { ...NO_FILTER, range: "all" };
let api: FakeAudit;
let source: FakeSource;

function make() {
  return new AuditStore({
    api: api as never,
    source,
    now: () => 2_000_000_000,
  });
}

function fill(count: number, first = 1) {
  for (let i = 0; i < count; i += 1) api.entries.push(connection(first + i));
}

const ids = (store: AuditStore) => store.entries.map((e) => e.id);

async function settle() {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
}

beforeEach(() => {
  api = new FakeAudit();
  source = new FakeSource();
});

describe("reading the log", () => {
  it("loads the newest page first, with the filter the server applies", async () => {
    fill(250);
    const store = make();
    await store.load({ ...ALL, workspace: "demo", host: "h1" });
    expect(store.status).toBe("ready");
    expect(api.queries[0]).toEqual({
      workspace: "demo",
      host_contains: "h1",
      limit: 200,
    });
    expect(ids(store)[0]).toBe(199);
    expect(store.hasMore).toBe(false);
    expect(store.epoch).toBe(1);
  });
  it("pages back with `before` until the oldest, then stops asking", async () => {
    fill(450);
    const store = make();
    await store.load(ALL);
    expect(store.entries).toHaveLength(200);
    expect(store.hasMore).toBe(true);
    await store.loadMore();
    expect(store.entries).toHaveLength(400);
    expect(api.queries[1]?.before).toBe(251);
    await store.loadMore();
    expect(ids(store)).toEqual(Array.from({ length: 450 }, (_, i) => 450 - i));
    expect(store.hasMore).toBe(false);
    const asked = api.queries.length;
    await store.loadMore();
    expect(api.queries).toHaveLength(asked);
  });
  it("reads one older page for calls that overlap", async () => {
    fill(450);
    const store = make();
    await store.load(ALL);
    await Promise.all([store.loadMore(), store.loadMore()]);
    expect(api.queries.filter((q) => q.before !== undefined)).toHaveLength(1);
  });
  it("fixes a relative range when the filter is applied, for every later page", async () => {
    for (let i = 1; i <= 450; i += 1)
      api.entries.push(connection(i, { ts: 1_999_999_000 + i }));
    let clock = 2_000_000_000;
    const store = new AuditStore({
      api: api as never,
      source,
      now: () => clock,
    });
    await store.load({ ...NO_FILTER, range: "1h" });
    clock += 1_000_000;
    await store.loadMore();
    expect(api.queries[0]?.from).toBe(2_000_000_000 - 3_600_000);
    expect(api.queries[1]?.from).toBe(2_000_000_000 - 3_600_000);
  });
  it("fails the first read quietly, and keeps the list after a later failure", async () => {
    api.down = true;
    const store = make();
    await store.load(ALL);
    expect(store.status).toBe("failed");
    expect(store.reloading).toBe(false);
    api.down = false;
    fill(3);
    await store.load(ALL);
    expect(store.status).toBe("ready");
    api.failNext = 500;
    await store.load(ALL);
    expect(store.status).toBe("failed");
    api.down = true;
    await store.load(ALL);
    expect(store.status).toBe("failed");
  });
  it("keeps the old rows while a new filter's answer is on its way, and drops a stale answer", async () => {
    fill(5);
    const store = make();
    await store.load(ALL);
    const first = store.load({ ...ALL, host: "h1" });
    expect(store.status).toBe("ready");
    expect(store.reloading).toBe(true);
    expect(store.entries).toHaveLength(5);
    const second = store.load({ ...ALL, host: "h2" });
    await Promise.all([first, second]);
    expect(ids(store)).toEqual([2]);
    expect(store.reloading).toBe(false);
  });
  it("starts a new list at the top, following the tail again", async () => {
    fill(3);
    const store = make();
    await store.load(ALL);
    store.setFollowing(false);
    await store.load({ ...ALL, host: "h1" });
    expect(store.following).toBe(true);
  });
  it("survives a failed older page and tries again on the next ask", async () => {
    fill(450);
    const store = make();
    await store.load(ALL);
    api.failNext = 500;
    await store.loadMore();
    expect(store.entries).toHaveLength(200);
    expect(store.loadingMore).toBe(false);
    api.down = true;
    await store.loadMore();
    api.down = false;
    await store.loadMore();
    expect(store.entries).toHaveLength(400);
  });
  it("reads the workspace names for the filter, sorted, and keeps them on failure", async () => {
    api.workspaces = ["web-shop", "api"];
    const store = make();
    await store.loadWorkspaces();
    expect(store.workspaces).toEqual(["api", "web-shop"]);
    api.down = true;
    await store.loadWorkspaces();
    expect(store.workspaces).toEqual(["api", "web-shop"]);
  });
});

describe("the live tail", () => {
  it("adds new records on top when an event says so, and not before", async () => {
    fill(3);
    const store = make();
    const stop = store.start();
    await store.load(ALL);
    api.entries.push(connection(4), connection(5));
    expect(ids(store)).toEqual([3, 2, 1]);
    source.emit({ type: "audit_appended", id: 5 });
    await settle();
    expect(ids(store)).toEqual([5, 4, 3, 2, 1]);
    expect(api.queries.at(-1)).toMatchObject({ after: 3 });
    stop();
    api.entries.push(connection(6));
    source.emit({ type: "audit_appended", id: 6 });
    await settle();
    expect(ids(store)).toEqual([5, 4, 3, 2, 1]);
  });
  it("ignores other events and an event that is not an object", async () => {
    fill(1);
    const store = make();
    store.start();
    await store.load(ALL);
    const asked = api.queries.length;
    source.emit({ type: "rules_changed" });
    source.emit(null);
    source.emit("audit_appended");
    await settle();
    expect(api.queries).toHaveLength(asked);
  });
  it("tails only what matches the filter, using the server's filter", async () => {
    api.entries.push(connection(1, { host: "a.test" }));
    const store = make();
    store.start();
    await store.load({ ...ALL, host: "a.test" });
    api.entries.push(
      connection(2, { host: "b.test" }),
      connection(3, { host: "a.test" }),
    );
    source.emit({ type: "audit_appended", id: 3 });
    await settle();
    expect(ids(store)).toEqual([3, 1]);
    expect(api.queries.at(-1)).toMatchObject({ host_contains: "a.test" });
  });
  it("reads on past a full page and puts the newest on top", async () => {
    fill(2);
    const store = make();
    store.start();
    await store.load(ALL);
    fill(1100, 3);
    source.emit({ type: "audit_appended", id: 1102 });
    await settle();
    expect(store.entries).toHaveLength(1102);
    expect(ids(store)[0]).toBe(1102);
    expect(api.queries.filter((q) => q.after !== undefined)).toHaveLength(3);
  });
  it("holds records back while the view is away from the top, and shows them on return", async () => {
    fill(3);
    const store = make();
    store.start();
    await store.load(ALL);
    store.setFollowing(false);
    api.entries.push(connection(4));
    source.emit({ type: "audit_appended", id: 4 });
    await settle();
    expect(ids(store)).toEqual([3, 2, 1]);
    expect(ids({ entries: store.held } as never)).toEqual([4]);
    api.entries.push(connection(5));
    source.emit({ type: "audit_appended", id: 5 });
    await settle();
    expect(store.held.map((e) => e.id)).toEqual([5, 4]);
    store.setFollowing(true);
    expect(ids(store)).toEqual([5, 4, 3, 2, 1]);
    expect(store.held).toEqual([]);
    store.show();
    expect(ids(store)).toHaveLength(5);
  });
  it("stops reading while Live is off, and catches up when it is back on", async () => {
    fill(2);
    const store = make();
    store.start();
    await store.load(ALL);
    store.setLive(false);
    api.entries.push(connection(3));
    source.emit({ type: "audit_appended", id: 3 });
    source.resync();
    await settle();
    expect(ids(store)).toEqual([2, 1]);
    store.setLive(true);
    await settle();
    expect(ids(store)).toEqual([3, 2, 1]);
  });
  it("catches up after a resync (lagged or reconnect) with no event", async () => {
    fill(1);
    const store = make();
    store.start();
    await store.load(ALL);
    api.entries.push(connection(2));
    source.resync();
    await settle();
    expect(ids(store)).toEqual([2, 1]);
  });
  it("runs one read for events that overlap, then one more", async () => {
    fill(1);
    const store = make();
    store.start();
    await store.load(ALL);
    api.entries.push(connection(2));
    source.emit({ type: "audit_appended", id: 2 });
    source.emit({ type: "audit_appended", id: 2 });
    source.emit({ type: "audit_appended", id: 2 });
    await settle();
    expect(ids(store)).toEqual([2, 1]);
    expect(api.queries.filter((q) => q.after !== undefined)).toHaveLength(2);
  });
  it("does nothing before the first page, during a reload, or when the read fails", async () => {
    const store = make();
    await store.catchUp();
    expect(api.queries).toHaveLength(0);
    fill(1);
    await store.load(ALL);
    const reload = store.load(ALL);
    await store.catchUp();
    expect(api.queries.filter((q) => q.after !== undefined)).toHaveLength(0);
    await reload;
    api.down = true;
    await store.catchUp();
    api.down = false;
    api.failNext = 500;
    await store.catchUp();
    expect(ids(store)).toEqual([1]);
    api.entries.push(connection(2));
    await store.catchUp();
    expect(ids(store)).toEqual([2, 1]);
  });
  it("drops a tail answer that belongs to an earlier filter", async () => {
    fill(2);
    const store = make();
    await store.load(ALL);
    api.entries.push(connection(3));
    const tail = store.catchUp();
    const reload = store.load({ ...ALL, host: "h1" });
    await Promise.all([tail, reload]);
    expect(ids(store)).toEqual([1]);
    expect(store.held).toEqual([]);
  });
  it("starts without a source", async () => {
    const store = new AuditStore({ api: api as never });
    expect(store.start()).toBeTypeOf("function");
  });
});

describe("exporting", () => {
  it("writes every matching record oldest first, a page at a time", async () => {
    fill(1200);
    const store = make();
    const seen: number[] = [];
    const result = await store.export({
      filter: ALL,
      onProgress: (n) => seen.push(n),
    });
    if (!result.ok) throw new Error("export failed");
    expect(result.records).toBe(1200);
    expect(seen).toEqual([500, 1000, 1200]);
    const first = JSON.parse(result.lines[0] ?? "") as { host: string };
    expect(first.host).toBe("h1.example.com");
    expect(result.lines.every((l) => l.endsWith("\n"))).toBe(true);
    expect(api.queries.map((q) => q.after)).toEqual([0, 500, 1000]);
  });
  it("applies the filter, and an exact multiple of a page ends on an empty one", async () => {
    fill(500);
    const store = make();
    const result = await store.export({ filter: { ...ALL, host: "h" } });
    expect(result).toMatchObject({ ok: true, records: 500 });
    expect(api.queries).toHaveLength(2);
    expect(api.queries[0]).toMatchObject({ host_contains: "h" });
  });
  it("is empty for a filter nothing matches", async () => {
    const result = await make().export({ filter: ALL });
    expect(result).toEqual({ ok: true, lines: [], records: 0 });
  });
  it("stops when cancelled, and says why when the service fails", async () => {
    fill(1200);
    const store = make();
    let pages = 0;
    const cancelled = await store.export({
      filter: ALL,
      onProgress: () => (pages += 1),
      cancelled: () => pages >= 1,
    });
    expect(cancelled).toEqual({ ok: false, cancelled: true });
    api.failNext = 500;
    expect(await store.export({ filter: ALL })).toMatchObject({
      ok: false,
      message: expect.stringContaining("couldn't read"),
    });
    api.down = true;
    expect(await store.export({ filter: ALL })).toMatchObject({
      ok: false,
      message: expect.stringContaining("isn't answering"),
    });
  });
});
