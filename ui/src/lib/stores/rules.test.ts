// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeRules, rule } from "#lib/testing/fake-rules.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { RulesStore } from "./rules.svelte.ts";

let api: FakeRules;
let source: FakeSource;
let changed: number;

function make(pollMs = 10_000, slowPollMs = 60_000) {
  return new RulesStore({
    api: api as never,
    source,
    pollMs,
    slowPollMs,
    onDecidedElsewhere: () => {
      changed += 1;
    },
  });
}

beforeEach(() => {
  api = new FakeRules();
  source = new FakeSource();
  changed = 0;
});
afterEach(() => vi.useRealTimers());

describe("reading", () => {
  it("loads every rule", async () => {
    api.rules = [rule(1), rule(2)];
    const store = make();
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.rules.map((r) => r.id)).toEqual([1, 2]);
  });
  it("fails the first read quietly, and keeps what it has after a later failure", async () => {
    api.down = true;
    const store = make();
    await store.refresh();
    expect(store.status).toBe("failed");
    api.down = false;
    api.rules = [rule(1)];
    await store.refresh();
    expect(store.status).toBe("ready");
    api.down = true;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.rules).toHaveLength(1);
  });
  it("treats an error answer like a failure", async () => {
    api.GET = async () =>
      ({
        error: { error: "internal", message: "x" },
        response: { status: 500, ok: false } as Response,
      }) as never;
    const store = make();
    await store.refresh();
    expect(store.status).toBe("failed");
  });
  it("shares overlapping reads and runs one more after them", async () => {
    const store = make();
    const first = store.refresh();
    void store.refresh();
    void store.refresh();
    await first;
    await vi.waitFor(() => expect(api.calls.length).toBe(2));
  });
});

describe("adding", () => {
  const body = {
    effect: "allow" as const,
    pattern: "*.example.com",
    scope: { type: "global" as const },
  };
  it("puts the new rule first and tells the badge", async () => {
    api.rules = [rule(1)];
    const store = make();
    await store.refresh();
    const result = await store.add(body);
    expect(result.ok).toBe(true);
    expect(store.rules.map((r) => r.pattern)).toEqual([
      ".example.com",
      "h1.example.com",
    ]);
    expect(changed).toBe(1);
  });
  it("hands back a 422 as a pattern error in sentence form", async () => {
    api.refuse = { status: 422, message: "pattern is a public suffix" };
    const result = await make().add(body);
    expect(result).toEqual({
      ok: false,
      field: "pattern",
      message: "Pattern is a public suffix.",
    });
    expect(changed).toBe(0);
  });
  it("hands back any other refusal, and a stopped service, as a form error", async () => {
    api.refuse = { status: 500, message: "boom" };
    expect(await make().add(body)).toMatchObject({
      field: "form",
      message: "Boom.",
    });
    api.down = true;
    expect(await make().add(body)).toMatchObject({ field: "form" });
  });
});

describe("changing", () => {
  it("replaces a rule with its new expiry", async () => {
    api.rules = [rule(1), rule(2)];
    const store = make();
    await store.refresh();
    expect(await store.setExpiry(2, 99)).toEqual({ ok: true });
    expect(store.rules.find((r) => r.id === 2)?.expires_at).toBe(99);
    expect(api.bodies.at(-1)).toEqual({ expires_at: 99 });
  });
  it("drops a rule that is gone, and reports refusals and outages", async () => {
    api.rules = [rule(1)];
    const store = make();
    await store.refresh();
    expect(await store.setExpiry(7, 5)).toEqual({
      ok: false,
      message: "That rule is already gone.",
    });
    api.refuse = { status: 422, message: "expiry must be in the future" };
    expect(await store.setExpiry(1, 5)).toEqual({
      ok: false,
      message: "Expiry must be in the future.",
    });
    api.down = true;
    expect((await store.setExpiry(1, 5)).ok).toBe(false);
  });
  it("deletes, counts an already deleted rule as deleted, and reports failures", async () => {
    api.rules = [rule(1), rule(2)];
    const store = make();
    await store.refresh();
    expect(await store.remove(1)).toEqual({ ok: true });
    expect(store.rules.map((r) => r.id)).toEqual([2]);
    expect(await store.remove(1)).toEqual({ ok: true });
    api.refuse = { status: 500, message: "x" };
    expect((await store.remove(2)).ok).toBe(false);
    expect(store.rules).toHaveLength(1);
    api.down = true;
    expect((await store.remove(2)).ok).toBe(false);
  });
});

describe("staying current", () => {
  it("refetches on rules_changed and ignores other events", async () => {
    vi.useFakeTimers();
    api.rules = [rule(1)];
    const store = make();
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    const before = api.calls.length;
    source.emit({ type: "oom_kill" });
    source.emit(null);
    await vi.advanceTimersByTimeAsync(0);
    expect(api.calls.length).toBe(before);
    api.rules = [rule(1), rule(2)];
    source.emit({ type: "rules_changed" });
    await vi.advanceTimersByTimeAsync(0);
    expect(store.rules).toHaveLength(2);
    stop();
  });
  it("refetches after a resync", async () => {
    vi.useFakeTimers();
    const store = make();
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    api.rules = [rule(3)];
    source.resync();
    await vi.advanceTimersByTimeAsync(0);
    expect(store.rules.map((r) => r.id)).toEqual([3]);
    stop();
  });
  it("polls until it has seen a rule event, then only slowly, and stops when told", async () => {
    vi.useFakeTimers();
    const store = make(1000, 10_000);
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(3100);
    const polled = api.calls.length;
    expect(polled).toBeGreaterThanOrEqual(3);
    source.emit({ type: "rules_changed" });
    // The tick already waiting runs once more, and schedules the slow one.
    await vi.advanceTimersByTimeAsync(1000);
    const afterEvent = api.calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.calls.length).toBe(afterEvent);
    await vi.advanceTimersByTimeAsync(6000);
    expect(api.calls.length).toBeGreaterThan(afterEvent);
    stop();
    const stopped = api.calls.length;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(api.calls.length).toBe(stopped);
    expect(source.listeners.size).toBe(0);
  });
});
