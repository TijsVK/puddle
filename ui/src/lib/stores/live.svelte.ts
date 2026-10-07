// SPDX-License-Identifier: GPL-3.0-or-later
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

export interface LiveDeps {
  api?: Pick<ApiClient, "GET">;
  events?: (options: EventStreamOptions) => AsyncIterable<unknown>;
  /** Interim refresh while the API has no pending-request events (T-172). */
  pollMs?: number;
}

export class LiveState {
  pending = $state(0);
  stream = $state<StreamState>("connecting");
  problem = $state<LiveProblem | null>(null);

  readonly #api: Pick<ApiClient, "GET">;
  readonly #events: (options: EventStreamOptions) => AsyncIterable<unknown>;
  readonly #pollMs: number;

  constructor(deps: LiveDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#events = deps.events ?? eventStream;
    this.#pollMs = deps.pollMs ?? 15_000;
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
        onResync: () => void this.refresh(),
      });
      for await (const _event of stream) {
        // Today's events (status, OOM) don't change the count; pending events arrive with T-172.
      }
    })();
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }
}

export const live = new LiveState();
