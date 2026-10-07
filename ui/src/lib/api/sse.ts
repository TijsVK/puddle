// SPDX-License-Identifier: GPL-3.0-or-later
// The event stream reader (ADR 0004). `EventSource` can't send the bearer token, so this reads
// `GET /api/events` with `fetch` and feeds the bytes to eventsource-parser. It is an async
// iterator of `Event`: it reconnects with backoff, tells the caller when a refetch is needed
// (`lagged`, or any reconnect, because events may have been missed), and ends when aborted.
import { createParser } from "eventsource-parser";
import { authHeaders, bootstrapToken } from "./connection.ts";
import type { components } from "./schema.d.ts";

export type PuddleEvent = components["schemas"]["Event"];
export type Lagged = components["schemas"]["Lagged"];

export type StreamState = "connecting" | "connected" | "reconnecting";

export interface EventStreamOptions {
  /** Ends the stream; the iterator then returns without throwing. */
  signal: AbortSignal;
  /** Only this workspace's events (global ones always come through). */
  sandbox?: string;
  /** Looked up per connection attempt. */
  getToken?: () => string | undefined;
  /** Called when events were or may have been missed: refetch what the screen shows. */
  onResync?: (reason: "lagged" | "reconnect", lagged?: Lagged) => void;
  /** Called on every connection state change, for a "reconnecting" hint. */
  onState?: (state: StreamState) => void;
  /** Wait times between attempts; the last repeats. */
  backoffMs?: readonly number[];
  /** For tests. */
  fetch?: typeof fetch;
  /** For tests: resolves after `ms` or when the signal aborts. */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** The stream's URL; for tests. */
  url?: string;
}

export const DEFAULT_BACKOFF_MS: readonly number[] = [1000, 2000, 5000, 10_000];

export function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done);
  });
}

function parseEvent(data: string): PuddleEvent | undefined {
  try {
    const value: unknown = JSON.parse(data);
    if (typeof value === "object" && value !== null && "type" in value) {
      return value as PuddleEvent;
    }
  } catch {
    // A frame that isn't JSON is skipped; the stream carries on.
  }
  return undefined;
}

function streamUrl(options: EventStreamOptions): string {
  const base = options.url ?? "/api/events";
  return options.sandbox === undefined
    ? base
    : `${base}?sandbox=${encodeURIComponent(options.sandbox)}`;
}

/** Yields events until `signal` aborts. Never throws for network or HTTP errors: it retries. */
export async function* eventStream(
  options: EventStreamOptions,
): AsyncGenerator<PuddleEvent, void> {
  const doFetch =
    options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const wait = options.sleep ?? sleep;
  const backoff = options.backoffMs?.length
    ? options.backoffMs
    : DEFAULT_BACKOFF_MS;
  const { signal } = options;
  let failures = 0;
  let everConnected = false;
  options.onState?.("connecting");

  while (!signal.aborted) {
    try {
      const response = await doFetch(streamUrl(options), {
        signal,
        headers: {
          Accept: "text/event-stream",
          ...authHeaders((options.getToken ?? bootstrapToken)()),
        },
      });
      if (!response.ok || response.body === null) {
        throw new Error(`event stream answered ${response.status}`);
      }
      if (everConnected) options.onResync?.("reconnect");
      everConnected = true;
      failures = 0;
      options.onState?.("connected");

      const queue: PuddleEvent[] = [];
      const parser = createParser({
        onEvent(message) {
          if (message.event === "lagged") {
            let lagged: Lagged | undefined;
            try {
              lagged = JSON.parse(message.data) as Lagged;
            } catch {
              lagged = undefined;
            }
            options.onResync?.("lagged", lagged);
            return;
          }
          const event = parseEvent(message.data);
          if (event) queue.push(event);
        },
      });
      const reader = response.body
        .pipeThrough(new TextDecoderStream())
        .getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          parser.feed(value);
          while (queue.length > 0) yield queue.shift() as PuddleEvent;
        }
      } finally {
        reader.cancel().catch(() => undefined);
      }
    } catch {
      if (signal.aborted) break;
    }
    if (signal.aborted) break;
    options.onState?.("reconnecting");
    const delay = backoff[Math.min(failures, backoff.length - 1)] ?? 1000;
    failures += 1;
    await wait(delay, signal);
  }
}
