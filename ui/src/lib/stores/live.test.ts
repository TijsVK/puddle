// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import type { EventStreamOptions } from "../api/sse.ts";
import { LiveState } from "./live.svelte.ts";

function fakeApi(result: () => unknown) {
  return { GET: vi.fn(async () => result()) } as never;
}

const ok = (n: number) => ({
  data: { requests: Array.from({ length: n }, () => ({})) },
  response: { status: 200 },
});

describe("LiveState.refresh", () => {
  it("counts the open requests and clears a problem", async () => {
    const live = new LiveState({ api: fakeApi(() => ok(3)) });
    live.problem = "unreachable";
    await live.refresh();
    expect(live.pending).toBe(3);
    expect(live.problem).toBeNull();
  });

  it("names a 401 as unauthorized and keeps the last count", async () => {
    let answer: unknown = ok(2);
    const live = new LiveState({ api: fakeApi(() => answer) });
    await live.refresh();
    answer = { error: { error: "unauthorized" }, response: { status: 401 } };
    await live.refresh();
    expect(live.problem).toBe("unauthorized");
    expect(live.pending).toBe(2);
  });

  it("names other failures and thrown errors as unreachable", async () => {
    const live = new LiveState({
      api: fakeApi(() => ({ error: {}, response: { status: 500 } })),
    });
    await live.refresh();
    expect(live.problem).toBe("unreachable");
    live.problem = null;
    const thrown = new LiveState({
      api: fakeApi(() => {
        throw new TypeError("down");
      }),
    });
    await thrown.refresh();
    expect(thrown.problem).toBe("unreachable");
  });
});

describe("LiveState.start", () => {
  it("refreshes on start, on a timer and on resync, mirrors the stream state, and stops cleanly", async () => {
    vi.useFakeTimers();
    try {
      const api = fakeApi(() => ok(1));
      let options: EventStreamOptions | undefined;
      const live = new LiveState({
        api,
        pollMs: 1000,
        events: (o) => {
          options = o;
          return (async function* () {
            yield { type: "status_changed" };
          })();
        },
      });
      const stop = live.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(
        (api as { GET: ReturnType<typeof vi.fn> }).GET,
      ).toHaveBeenCalledTimes(1);
      expect(live.pending).toBe(1);

      await vi.advanceTimersByTimeAsync(1000);
      expect(
        (api as { GET: ReturnType<typeof vi.fn> }).GET,
      ).toHaveBeenCalledTimes(2);

      options?.onState?.("reconnecting");
      expect(live.stream).toBe("reconnecting");
      options?.onResync?.("lagged");
      await vi.advanceTimersByTimeAsync(0);
      expect(
        (api as { GET: ReturnType<typeof vi.fn> }).GET,
      ).toHaveBeenCalledTimes(3);

      stop();
      expect(options?.signal.aborted).toBe(true);
      await vi.advanceTimersByTimeAsync(5000);
      expect(
        (api as { GET: ReturnType<typeof vi.fn> }).GET,
      ).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("uses the app's client, the real stream and a 15 s poll by default", () => {
    const live = new LiveState();
    expect(live.pending).toBe(0);
    expect(live.stream).toBe("connecting");
    expect(live.problem).toBeNull();
  });
});

describe("LiveState.subscribe", () => {
  it("hands every event and every resync to the listeners until they unsubscribe", async () => {
    vi.useFakeTimers();
    try {
      let options: EventStreamOptions | undefined;
      let push: (event: unknown) => void = () => undefined;
      const live = new LiveState({
        api: fakeApi(() => ok(0)),
        pollMs: 60_000,
        events: (o) => {
          options = o;
          return (async function* () {
            const queue: unknown[] = [];
            push = (e) => queue.push(e);
            while (!o.signal.aborted) {
              const next = queue.shift();
              if (next !== undefined) yield next;
              else await new Promise((r) => setTimeout(r, 10));
            }
          })();
        },
      });
      const event = vi.fn();
      const resync = vi.fn();
      const unsubscribe = live.subscribe({ event, resync });
      live.subscribe({});
      const stop = live.start();
      await vi.advanceTimersByTimeAsync(0);
      push({ type: "pending_opened" });
      await vi.advanceTimersByTimeAsync(20);
      expect(event).toHaveBeenCalledWith({ type: "pending_opened" });
      options?.onResync?.("lagged");
      expect(resync).toHaveBeenCalledOnce();
      unsubscribe();
      options?.onResync?.("reconnect");
      push({ type: "x" });
      await vi.advanceTimersByTimeAsync(20);
      expect(resync).toHaveBeenCalledOnce();
      expect(event).toHaveBeenCalledOnce();
      stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("lets a screen that knows the count tell the badge at once", () => {
    const live = new LiveState({ api: fakeApi(() => ok(0)) });
    live.setPending(7);
    expect(live.pending).toBe(7);
  });
});
