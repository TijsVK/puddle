// SPDX-License-Identifier: GPL-3.0-or-later
// The repository lists of one screen: the repositories the identities' credentials reach (`GET
// /api/repos`) and how current each credential's list is. The host reads a list from the Git host
// when a screen asks and it is missing or old, so a first read can take many seconds: the store
// says it is `slow` after a moment so the screen can show progress, and it asks again by itself when
// a host said to wait (`retry_at`), since no event announces a list becoming readable. Each screen
// makes its own instance; nothing here holds a secret, and every string the host sends is rendered
// as text by the screens.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import { sentence } from "#lib/rules/model.ts";
import {
  nextRetryDelay,
  type RepoListing,
  type RepoQuery,
} from "#lib/repos/model.ts";

type StoreApi = Pick<ApiClient, "GET" | "POST">;

export type RepoStatus = "idle" | "loading" | "ready" | "failed";

export interface RepoListsDeps {
  api?: StoreApi;
  /** Milliseconds a read takes before it counts as slow. */
  slowAfterMs?: number;
  now?: () => number;
}

const DOWN = "puddle's service isn't answering.";
const PAGE = 100;

export class RepoLists {
  /** The newest answer; kept on show while a newer one is read. */
  listing = $state.raw<RepoListing | null>(null);
  status = $state<RepoStatus>("idle");
  /** A read has taken longer than a moment: show that puddle is still asking the Git host. */
  slow = $state(false);
  refreshing = $state(false);
  loadingMore = $state(false);
  /** Why the last read or refresh failed outright (a list that fails says so in `listing.sources`). */
  message = $state<string | null>(null);
  /** The time the screen words ages against; moves on every answer. */
  now = $state(0);

  readonly #api: StoreApi;
  readonly #slowAfter: number;
  readonly #clock: () => number;
  #query: RepoQuery = {};
  #ticket = 0;
  #slowTimer: ReturnType<typeof setTimeout> | undefined;
  #retryTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(deps: RepoListsDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#slowAfter = deps.slowAfterMs ?? 1500;
    this.#clock = deps.now ?? Date.now;
    this.now = this.#clock();
  }

  /** Reads the repositories `query` asks for. `quiet` keeps the screen as it is while it does. */
  async load(query: RepoQuery, quiet = false): Promise<void> {
    this.#query = query;
    const ticket = ++this.#ticket;
    clearTimeout(this.#retryTimer);
    if (!quiet) this.#startWaiting();
    try {
      const { data, error } = await this.#api.GET("/api/repos", {
        params: { query: { ...query, limit: query.limit ?? PAGE } },
      });
      if (ticket !== this.#ticket) return;
      if (data) {
        this.listing = data;
        this.message = null;
        this.status = "ready";
        this.now = this.#clock();
        this.#schedule();
      } else {
        this.message = sentence(
          error?.message ?? "puddle couldn't read the lists",
        );
        this.status = "failed";
      }
    } catch {
      if (ticket !== this.#ticket) return;
      this.message = DOWN;
      this.status = "failed";
    } finally {
      if (ticket === this.#ticket) this.#stopWaiting();
    }
  }

  /** Reads the next page of the same search and puts it after what is shown. */
  async more(): Promise<void> {
    const shown = this.listing;
    if (!shown || this.loadingMore || shown.repos.length >= shown.total) return;
    const ticket = this.#ticket;
    this.loadingMore = true;
    try {
      const { data } = await this.#api.GET("/api/repos", {
        params: {
          query: {
            ...this.#query,
            limit: this.#query.limit ?? PAGE,
            offset: shown.repos.length,
          },
        },
      });
      if (data && ticket === this.#ticket && this.listing === shown) {
        this.listing = { ...data, repos: [...shown.repos, ...data.repos] };
        this.now = this.#clock();
      }
    } catch {
      this.message = DOWN;
    } finally {
      this.loadingMore = false;
    }
  }

  /** Asks the host to read the lists again now (`identity`: only that one's), then shows them. */
  async refresh(identity?: number): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    this.#startWaiting();
    const ticket = this.#ticket;
    try {
      const { data, error } = await this.#api.POST("/api/repos/refresh", {
        body: identity === undefined ? {} : { identity_id: identity },
      });
      if (!data) {
        this.message = sentence(
          error?.message ?? "puddle couldn't refresh the lists",
        );
        return;
      }
      this.message = null;
    } catch {
      this.message = DOWN;
      return;
    } finally {
      if (ticket === this.#ticket) this.#stopWaiting();
      this.refreshing = false;
    }
    await this.load(this.#query, true);
  }

  /** Stops waiting and asking: the screen is gone. */
  stop(): void {
    this.#ticket++;
    this.#stopWaiting();
    clearTimeout(this.#retryTimer);
  }

  #startWaiting(): void {
    if (this.status !== "ready") this.status = "loading";
    clearTimeout(this.#slowTimer);
    this.slow = false;
    this.#slowTimer = setTimeout(() => {
      this.slow = true;
    }, this.#slowAfter);
  }

  #stopWaiting(): void {
    clearTimeout(this.#slowTimer);
    this.slow = false;
  }

  /** Asks again when the soonest host that said to wait allows it. */
  #schedule(): void {
    const sources = this.listing?.sources ?? [];
    const delay = nextRetryDelay(sources, this.#clock());
    if (delay === null) return;
    this.#retryTimer = setTimeout(() => {
      void this.load(this.#query, true);
    }, delay);
  }
}
