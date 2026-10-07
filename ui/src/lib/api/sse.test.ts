// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_BACKOFF_MS,
  eventStream,
  sleep,
  type PuddleEvent,
  type StreamState,
} from "./sse.ts";

const enc = new TextEncoder();

/** A response whose body yields `chunks`, then ends (or stays open when `hold` is set). */
function sse(chunks: string[], hold?: AbortSignal): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(enc.encode(chunk));
      if (hold) {
        hold.addEventListener("abort", () =>
          controller.error(new DOMException("aborted", "AbortError")),
        );
      } else {
        controller.close();
      }
    },
  });
  return new Response(body, {
    headers: { "content-type": "text/event-stream" },
  });
}

const status = (name: string) =>
  `data: {"type":"status_changed","sandbox":"${name}","status":"running"}\n\n`;

function setup(responses: Array<() => Response | Promise<Response>>) {
  const controller = new AbortController();
  const requests: Array<{ url: string; headers: Headers }> = [];
  let call = 0;
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    requests.push({ url: String(input), headers: new Headers(init?.headers) });
    const next = responses[Math.min(call, responses.length - 1)];
    call += 1;
    if (!next) throw new Error("no response");
    return next();
  });
  const sleeps: number[] = [];
  const sleepFn = async (ms: number) => {
    sleeps.push(ms);
  };
  const states: StreamState[] = [];
  const resyncs: string[] = [];
  const base = {
    signal: controller.signal,
    fetch: fetch as unknown as typeof globalThis.fetch,
    sleep: sleepFn,
    getToken: () => "tok",
    onState: (s: StreamState) => states.push(s),
    onResync: (reason: string) => resyncs.push(reason),
  };
  return { controller, fetch, requests, sleeps, states, resyncs, base };
}

async function take(
  stream: AsyncIterable<PuddleEvent>,
  count: number,
): Promise<PuddleEvent[]> {
  const out: PuddleEvent[] = [];
  if (count === 0) return out;
  for await (const event of stream) {
    out.push(event);
    if (out.length === count) break;
  }
  return out;
}

describe("eventStream", () => {
  it("yields events, sends the token and asks for an event stream", async () => {
    const t = setup([() => sse([status("a"), status("b")])]);
    const events = await take(eventStream(t.base), 2);
    expect(
      events.map((e) => (e.type === "status_changed" ? e.sandbox : "?")),
    ).toEqual(["a", "b"]);
    expect(t.requests[0]?.url).toBe("/api/events");
    expect(t.requests[0]?.headers.get("authorization")).toBe("Bearer tok");
    expect(t.requests[0]?.headers.get("accept")).toBe("text/event-stream");
    expect(t.states.slice(0, 2)).toEqual(["connecting", "connected"]);
  });

  it("sends no Authorization header without a token", async () => {
    const t = setup([() => sse([status("a")])]);
    await take(eventStream({ ...t.base, getToken: () => undefined }), 1);
    expect(t.requests[0]?.headers.has("authorization")).toBe(false);
  });

  it("filters by workspace in the query", async () => {
    const t = setup([() => sse([status("a")])]);
    await take(eventStream({ ...t.base, sandbox: "my box" }), 1);
    expect(t.requests[0]?.url).toBe("/api/events?sandbox=my%20box");
  });

  it("reassembles frames split across chunks and ignores comments", async () => {
    const frame = status("split");
    const t = setup([
      () => sse([": keep-alive\n\n", frame.slice(0, 20), frame.slice(20)]),
    ]);
    const events = await take(eventStream(t.base), 1);
    expect(events[0]).toMatchObject({
      type: "status_changed",
      sandbox: "split",
    });
  });

  it("skips frames that are not JSON events and carries on", async () => {
    const t = setup([
      () =>
        sse([
          "data: not json\n\n",
          'data: {"no":"type"}\n\n',
          "data: 5\n\n",
          status("ok"),
        ]),
    ]);
    const events = await take(eventStream(t.base), 1);
    expect(events[0]).toMatchObject({ sandbox: "ok" });
  });

  it("reports lagged for a refetch and keeps going", async () => {
    const t = setup([
      () => sse(['event: lagged\ndata: {"missed":3}\n\n', status("after")]),
    ]);
    const lagged: unknown[] = [];
    const events = await take(
      eventStream({
        ...t.base,
        onResync: (reason, l) => void lagged.push([reason, l]),
      }),
      1,
    );
    expect(lagged).toEqual([["lagged", { missed: 3 }]]);
    expect(events[0]).toMatchObject({ sandbox: "after" });
  });

  it("reports lagged even when its body is malformed", async () => {
    const t = setup([() => sse(["event: lagged\ndata: {{\n\n", status("x")])]);
    const lagged: unknown[] = [];
    await take(
      eventStream({
        ...t.base,
        onResync: (reason, l) => void lagged.push([reason, l]),
      }),
      1,
    );
    expect(lagged).toEqual([["lagged", undefined]]);
  });

  it("reconnects after the stream ends, tells the caller to refetch, and backs off", async () => {
    const t = setup([() => sse([status("one")]), () => sse([status("two")])]);
    const events = await take(eventStream(t.base), 2);
    expect(events).toHaveLength(2);
    expect(t.fetch).toHaveBeenCalledTimes(2);
    expect(t.resyncs).toEqual(["reconnect"]);
    expect(t.sleeps).toEqual([1000]);
    expect(t.states).toContain("reconnecting");
  });

  it("backs off 1, 2, 5, 10, 10 s while the server is down, and counts again after a success", async () => {
    const down = () => new Response("nope", { status: 503 });
    const t = setup([
      down,
      down,
      down,
      down,
      down,
      () => sse([status("up")]),
      down,
      () => sse([status("again")]),
    ]);
    const events = await take(eventStream(t.base), 2);
    expect(events).toHaveLength(2);
    expect(t.sleeps).toEqual([1000, 2000, 5000, 10_000, 10_000, 1000, 2000]);
    // The first connection is not a "reconnect"; the one after it is.
    expect(t.resyncs).toEqual(["reconnect"]);
  });

  it("treats network errors and a missing body like HTTP errors", async () => {
    const t = setup([
      () => {
        throw new TypeError("network down");
      },
      () => ({ ok: true, status: 200, body: null }) as unknown as Response,
      () => sse([status("ok")]),
    ]);
    const events = await take(eventStream(t.base), 1);
    expect(events).toHaveLength(1);
    expect(t.sleeps).toEqual([1000, 2000]);
  });

  it("uses the default schedule when given none or an empty one", async () => {
    const down = () => new Response("", { status: 500 });
    const t = setup([down, () => sse([status("a")])]);
    await take(eventStream({ ...t.base, backoffMs: [] }), 1);
    expect(t.sleeps).toEqual([DEFAULT_BACKOFF_MS[0]]);
    const custom = setup([down, down, () => sse([status("a")])]);
    await take(eventStream({ ...custom.base, backoffMs: [7] }), 1);
    expect(custom.sleeps).toEqual([7, 7]);
  });

  it("ends cleanly when aborted while the stream is open", async () => {
    const t = setup([() => sse([status("a")], t.controller.signal)]);
    const seen: PuddleEvent[] = [];
    const run = (async () => {
      for await (const event of eventStream(t.base)) {
        seen.push(event);
        t.controller.abort();
      }
    })();
    await expect(run).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
  });

  it("ends without connecting when already aborted, and while waiting to retry", async () => {
    const aborted = setup([() => sse([])]);
    aborted.controller.abort();
    expect(await take(eventStream(aborted.base), 5)).toEqual([]);
    expect(aborted.fetch).not.toHaveBeenCalled();

    const waiting = setup([() => new Response("", { status: 500 })]);
    const events = await take(
      eventStream({
        ...waiting.base,
        sleep: async () => {
          waiting.controller.abort();
        },
      }),
      5,
    );
    expect(events).toEqual([]);
  });

  it("ends when the fetch itself is aborted", async () => {
    const t = setup([
      () => {
        t.controller.abort();
        throw new DOMException("aborted", "AbortError");
      },
    ]);
    expect(await take(eventStream(t.base), 5)).toEqual([]);
  });

  it("defaults to the global fetch, the real sleep and the page's token", async () => {
    const original = globalThis.fetch;
    const controller = new AbortController();
    const fetch = vi.fn(async () => sse([status("g")]));
    globalThis.fetch = fetch as unknown as typeof globalThis.fetch;
    try {
      const events = await take(eventStream({ signal: controller.signal }), 1);
      expect(events).toHaveLength(1);
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("sleep", () => {
  it("resolves after the time, or at once when aborted", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AbortController();
      const done = vi.fn();
      void sleep(1000, controller.signal).then(done);
      await vi.advanceTimersByTimeAsync(999);
      expect(done).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      expect(done).toHaveBeenCalledTimes(1);

      const other = new AbortController();
      const stopped = vi.fn();
      void sleep(60_000, other.signal).then(stopped);
      other.abort();
      await vi.advanceTimersByTimeAsync(0);
      expect(stopped).toHaveBeenCalledTimes(1);

      await expect(sleep(60_000, other.signal)).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
