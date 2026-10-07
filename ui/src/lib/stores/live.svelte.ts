// SPDX-License-Identifier: GPL-3.0-or-later
/* eslint-disable svelte/prefer-svelte-reactivity -- the maps and sets here are bookkeeping that no template reads, so they need no reactivity */
// Shell-level live state: the pending-request count for the nav badge and the document title,
// and how the event stream is doing. Screens that need more subscribe to `eventStream` themselves.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import {
  eventStream,
  type EventStreamOptions,
  type StreamState,
} from "#lib/api/sse.ts";

/** Why the count could not be read. */
export type LiveProblem = "unauthorized" | "unreachable";

/** What a screen hears from the shell's one event stream. */
export interface LiveListener {
  event?: (event: unknown) => void;
  /** Events were or may have been missed (`lagged`, reconnect): refetch what the screen shows. */
  resync?: () => void;
}

/** Where a screen subscribes to the shell's stream instead of opening a second connection. */
export interface LiveSource {
  subscribe(listener: LiveListener): () => void;
}

export interface LiveDeps {
  api?: Pick<ApiClient, "GET">;
  events?: (options: EventStreamOptions) => AsyncIterable<unknown>;
  /** Interim refresh while the API has no pending-request events. */
  pollMs?: number;
}

export class LiveState implements LiveSource {
  pending = $state(0);
  stream = $state<StreamState>("connecting");
  problem = $state<LiveProblem | null>(null);

  readonly #api: Pick<ApiClient, "GET">;
  readonly #events: (options: EventStreamOptions) => AsyncIterable<unknown>;
  readonly #pollMs: number;
  readonly #listeners = new Set<LiveListener>();

  constructor(deps: LiveDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#events = deps.events ?? eventStream;
    this.#pollMs = deps.pollMs ?? 15_000;
  }

  /** Screens that show more than the count listen here; returns the function that stops it. */
  subscribe(listener: LiveListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** A screen that knows the count (the inbox, after a decision) tells the badge at once. */
  setPending(count: number): void {
    this.pending = count;
  }

  /** Reads the open-request count. Never throws: a failure sets `problem`. */
  async refresh(): Promise<void> {
    try {
      const { data, response } = await this.#api.GET("/api/pending");
      if (data) {
        this.pending = data.requests.length;
        this.problem = null;
      } else {
        this.problem = response.status === 401 ? "unauthorized" : "unreachable";
      }
    } catch {
      this.problem = "unreachable";
    }
  }

  /** Starts the stream and the poll; returns the function that stops both. */
  start(): () => void {
    const controller = new AbortController();
    void this.refresh();
    const timer = setInterval(() => void this.refresh(), this.#pollMs);
    void (async () => {
      const stream = this.#events({
        signal: controller.signal,
        onState: (state) => {
          this.stream = state;
        },
        onResync: () => {
          void this.refresh();
          for (const l of [...this.#listeners]) l.resync?.();
        },
      });
      for await (const event of stream) {
        // The count itself still comes from the poll until the API sends pending events.
        for (const l of [...this.#listeners]) l.event?.(event);
      }
    })();
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }
}

export const live = new LiveState();
