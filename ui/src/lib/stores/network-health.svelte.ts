// SPDX-License-Identifier: GPL-3.0-or-later
// The network-health report, kept current: read at start, read again on `network_changed` and
// after a resync (`lagged`, reconnect). Reads that overlap share one run and one more follows,
// so the last answer always reflects the last event.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import { isNetworkChanged } from "#lib/network/events.ts";
import type { NetworkHealth } from "#lib/network/model.ts";
import { live, type LiveSource } from "./live.svelte.ts";

/** `unavailable`: this puddle has no network service (the API answers 503). */
export type Status = "loading" | "ready" | "unavailable" | "failed";

type StoreApi = Pick<ApiClient, "GET">;

export interface NetworkHealthDeps {
  api?: StoreApi;
  source?: LiveSource;
}

export class NetworkHealthStore {
  report = $state.raw<NetworkHealth | null>(null);
  status = $state<Status>("loading");
  /** A read is running (the page shows it next to "Check again"). */
  reading = $state(false);

  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;
  #running: Promise<void> | null = null;
  #again = false;

  constructor(deps: NetworkHealthDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#source = deps.source;
  }

  /** Reads the report; never throws. Overlapping calls share one run, and one more follows. */
  refresh(): Promise<void> {
    if (this.#running) {
      this.#again = true;
      return this.#running;
    }
    this.reading = true;
    this.#running = this.#load().finally(() => {
      this.#running = null;
      this.reading = false;
      if (this.#again) {
        this.#again = false;
        void this.refresh();
      }
    });
    return this.#running;
  }

  async #load(): Promise<void> {
    try {
      const { data, response } = await this.#api.GET("/api/network-health");
      if (data) {
        this.report = data;
        this.status = "ready";
      } else if (response.status === 503) {
        this.status = "unavailable";
      } else if (this.report === null) {
        this.status = "failed";
      }
    } catch {
      if (this.report === null) this.status = "failed";
    }
  }

  /** Starts listening; returns the function that stops it. */
  start(): () => void {
    const unsubscribe = this.#source?.subscribe({
      event: (event) => {
        if (isNetworkChanged(event)) void this.refresh();
      },
      resync: () => void this.refresh(),
    });
    void this.refresh();
    return () => unsubscribe?.();
  }
}

export const networkHealth = new NetworkHealthStore({ source: live });
