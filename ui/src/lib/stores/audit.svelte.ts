// SPDX-License-Identifier: GPL-3.0-or-later
// The activity screen's state: the audit records that match the filter, newest first, read a page
// at a time from the API, and the live tail.
//
// The server does the filtering (nothing is filtered here). Older pages come with `before`; new
// records come with `after`, one read per `audit_appended` event (reads that overlap share one run,
// and one more follows). New records are held back while the user has scrolled away from the top
// or switched Live off, and shown when they come back. A resync (`lagged`, reconnect) catches up
// the same way, so no event is needed to be right.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import { isAuditAppended } from "#lib/audit/events.ts";
import {
  EXPORT_PAGE_SIZE,
  NO_FILTER,
  PAGE_SIZE,
  toQuery,
  type AuditEntry,
  type AuditRecord,
  type Filter,
} from "#lib/audit/model.ts";
import { live, type LiveSource } from "./live.svelte.ts";

export type Status = "loading" | "ready" | "failed";

type StoreApi = Pick<ApiClient, "GET">;

export interface AuditDeps {
  api?: StoreApi;
  source?: LiveSource;
  now?: () => number;
}

/** What an export does along the way; `cancelled` is read before every page. */
export interface ExportOptions {
  filter: Filter;
  onProgress?: (records: number) => void;
  cancelled?: () => boolean;
}

export type ExportResult =
  | { ok: true; lines: string[]; records: number }
  | { ok: false; message: string }
  | { ok: false; cancelled: true };

const DOWN = "puddle's service isn't answering.";
/** Pages one catch-up reads at most; the rest comes with the next event. */
const MAX_TAIL_PAGES = 20;

export class AuditStore {
  /** Newest first. */
  entries = $state.raw<AuditEntry[]>([]);
  status = $state<Status>("loading");
  /** Older records exist than the ones loaded. */
  hasMore = $state(false);
  loadingMore = $state(false);
  /** Records that arrived while the view was not following the tail (newest first). */
  held = $state.raw<AuditEntry[]>([]);
  /** Switched off, the log is not read again until it is switched on (or the filter changes). */
  live = $state(true);
  /** False while the user is scrolled away from the top: new records wait in `held`. */
  following = $state(true);
  /** A read for a new filter is running; the old records stay until its answer arrives. */
  reloading = $state(false);
  /** Counts the lists that replaced the whole one (a filter applied); a view starts over on it. */
  epoch = $state(0);
  /** Workspace names for the filter. */
  workspaces = $state.raw<string[]>([]);

  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;
  readonly #now: () => number;
  #filter: Filter | null = null;
  /** Bumped by every `load`, so an answer to an older filter is dropped. */
  #generation = 0;
  #nextBefore: number | null = null;
  #cursor = 0;
  #from: number | undefined;
  #tailing: Promise<void> | null = null;
  #again = false;

  constructor(deps: AuditDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#source = deps.source;
    this.#now = deps.now ?? Date.now;
  }

  /** Reads the newest page for a filter; never throws. A range is measured from now. */
  async load(filter: Filter): Promise<void> {
    const generation = (this.#generation += 1);
    this.#filter = filter;
    this.#from = toQuery(filter, this.#now()).from;
    this.held = [];
    this.hasMore = false;
    this.loadingMore = false;
    if (this.status !== "ready") this.status = "loading";
    this.reloading = true;
    try {
      const { data } = await this.#api.GET("/api/audit", {
        params: { query: { ...this.#query(), limit: PAGE_SIZE } },
      });
      if (generation !== this.#generation) return;
      this.reloading = false;
      if (!data) {
        this.status = "failed";
        return;
      }
      this.entries = data.entries;
      this.epoch += 1;
      // A new list starts at the top.
      this.following = true;
      this.#nextBefore = data.next_before;
      this.hasMore = data.next_before !== null;
      this.#cursor = data.next_after;
      this.status = "ready";
    } catch {
      if (generation === this.#generation) {
        this.reloading = false;
        this.status = "failed";
      }
    }
  }

  #query() {
    const query = toQuery(this.#filter ?? NO_FILTER, this.#now());
    if (this.#from === undefined) delete query.from;
    else query.from = this.#from;
    return query;
  }

  /** Reads the next older page. Several calls at once read one page. */
  async loadMore(): Promise<void> {
    if (this.loadingMore || this.#nextBefore === null || !this.#filter) return;
    const generation = this.#generation;
    this.loadingMore = true;
    try {
      const { data } = await this.#api.GET("/api/audit", {
        params: {
          query: {
            ...this.#query(),
            before: this.#nextBefore,
            limit: PAGE_SIZE,
          },
        },
      });
      if (generation !== this.#generation || !data) return;
      this.entries = [...this.entries, ...data.entries];
      this.#nextBefore = data.next_before;
      this.hasMore = data.next_before !== null;
    } catch {
      // The next scroll tries again.
    } finally {
      if (generation === this.#generation) this.loadingMore = false;
    }
  }

  /** Reads what was committed since the newest record seen. Overlapping calls share one run. */
  catchUp(): Promise<void> {
    if (this.#tailing) {
      this.#again = true;
      return this.#tailing;
    }
    this.#tailing = this.#tail().finally(() => {
      this.#tailing = null;
      if (this.#again) {
        this.#again = false;
        void this.catchUp();
      }
    });
    return this.#tailing;
  }

  async #tail(): Promise<void> {
    if (this.status !== "ready" || this.reloading || !this.#filter) return;
    const generation = this.#generation;
    const fresh: AuditEntry[] = [];
    try {
      let cursor = this.#cursor;
      for (let page = 0; page < MAX_TAIL_PAGES; page += 1) {
        const { data } = await this.#api.GET("/api/audit", {
          params: {
            query: { ...this.#query(), after: cursor, limit: EXPORT_PAGE_SIZE },
          },
        });
        if (generation !== this.#generation) return;
        if (!data) break;
        fresh.push(...data.entries);
        cursor = data.next_after;
        if (data.entries.length < EXPORT_PAGE_SIZE) break;
      }
      this.#cursor = cursor;
    } catch {
      // The next event or resync tries again from the same place.
    }
    if (generation !== this.#generation || fresh.length === 0) return;
    this.held = [...fresh.reverse(), ...this.held];
    if (this.following) this.show();
  }

  /** Puts the held records on top of the list. */
  show(): void {
    if (this.held.length === 0) return;
    this.entries = [...this.held, ...this.entries];
    this.held = [];
  }

  /** The page tells the store whether the user is at the top of the list. */
  setFollowing(following: boolean): void {
    this.following = following;
    if (following) this.show();
  }

  /** Live off stops reading the tail; on, it catches up at once. */
  setLive(on: boolean): void {
    this.live = on;
    if (on) void this.catchUp();
  }

  /** The workspaces the filter offers; keeps the old list if the read fails. */
  async loadWorkspaces(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/workspaces");
      if (data) this.workspaces = data.workspaces.map((w) => w.name).sort();
    } catch {
      // The filter still offers the workspace it is set to.
    }
  }

  /**
   * Every record the filter matches, oldest first, as export lines. The range is measured from
   * now. Pages of 500, so nothing is held but the lines themselves.
   */
  async export(options: ExportOptions): Promise<ExportResult> {
    const base = toQuery(options.filter, this.#now());
    const lines: string[] = [];
    let cursor = 0;
    try {
      for (;;) {
        if (options.cancelled?.()) return { ok: false, cancelled: true };
        const { data } = await this.#api.GET("/api/audit", {
          params: {
            query: { ...base, after: cursor, limit: EXPORT_PAGE_SIZE },
          },
        });
        if (!data)
          return { ok: false, message: "puddle couldn't read the log." };
        for (const entry of data.entries) {
          lines.push(`${JSON.stringify(entry.record satisfies AuditRecord)}\n`);
        }
        options.onProgress?.(lines.length);
        cursor = data.next_after;
        if (data.entries.length < EXPORT_PAGE_SIZE) break;
      }
    } catch {
      return { ok: false, message: DOWN };
    }
    return { ok: true, lines, records: lines.length };
  }

  /** Starts listening; returns the function that stops it. */
  start(): () => void {
    const unsubscribe = this.#source?.subscribe({
      event: (event) => {
        if (this.live && isAuditAppended(event)) void this.catchUp();
      },
      resync: () => {
        if (this.live) void this.catchUp();
      },
    });
    void this.loadWorkspaces();
    return () => unsubscribe?.();
  }
}

export const auditStore = new AuditStore({ source: live });
