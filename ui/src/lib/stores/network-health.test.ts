// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { report } from "#lib/testing/fake-network.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { NetworkHealthStore } from "./network-health.svelte.ts";

type Answer = { data?: unknown; response: { status: number } } | "throw";
let answers: Answer[];
let calls: number;
let hold: Promise<void> | null;

const api = {
  GET: async () => {
    calls += 1;
    if (hold) await hold;
    const a = answers.shift() ?? { data: report(), response: { status: 200 } };
    if (a === "throw") throw new Error("down");
    return a;
  },
};
let source: FakeSource;
const make = () => new NetworkHealthStore({ api: api as never, source });
const ok = (epoch: number) => {
  const r = report();
  r.proxy.epoch = epoch;
  return { data: r, response: { status: 200 } };
};

beforeEach(() => {
  answers = [];
  calls = 0;
  hold = null;
  source = new FakeSource();
});

describe("NetworkHealthStore", () => {
  it("reads the report and is ready", async () => {
    answers.push(ok(1));
    const store = make();
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.report?.proxy.epoch).toBe(1);
    expect(store.reading).toBe(false);
  });

  it("says unavailable on 503 and failed when nothing was ever read", async () => {
    answers.push({ response: { status: 503 } });
    const a = make();
    await a.refresh();
    expect(a.status).toBe("unavailable");
    answers.push({ response: { status: 500 } });
    const b = make();
    await b.refresh();
    expect(b.status).toBe("failed");
    answers.push("throw");
    const c = make();
    await c.refresh();
    expect(c.status).toBe("failed");
  });

  it("keeps the last report when a later read fails", async () => {
    answers.push(ok(1), { response: { status: 500 } }, "throw");
    const store = make();
    await store.refresh();
    await store.refresh();
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.report?.proxy.epoch).toBe(1);
  });

  it("shares one run for overlapping calls and reads once more afterwards", async () => {
    let release = () => {};
    hold = new Promise((r) => {
      release = r;
    });
    answers.push(ok(1), ok(2));
    const store = make();
    const first = store.refresh();
    expect(store.reading).toBe(true);
    const second = store.refresh();
    release();
    hold = null;
    await Promise.all([first, second]);
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(2);
    expect(store.report?.proxy.epoch).toBe(2);
  });

  it("reads again on network_changed and after a resync, and not for other events", async () => {
    const store = make();
    const stop = store.start();
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(1);
    source.emit({ type: "rules_changed" });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(1);
    answers.push(ok(9));
    source.emit({ type: "network_changed", epoch: 9 });
    await new Promise((r) => setTimeout(r, 0));
    expect(store.report?.proxy.epoch).toBe(9);
    source.resync();
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(3);
    stop();
    source.emit({ type: "network_changed", epoch: 10 });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(3);
  });

  it("works without a source", async () => {
    const store = new NetworkHealthStore({ api: api as never });
    store.start()();
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toBe(1);
  });
});
