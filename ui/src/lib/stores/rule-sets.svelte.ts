// SPDX-License-Identifier: GPL-3.0-or-later
// The rule sets and the System managed hosts (`GET /api/rule-sets`), and what a user does to a
// set: make one, rename it, delete it, switch it. Entries are rules (`/api/rules`, scope `set`).
// It refetches on `rules_changed`
// and on a resync, and polls slowly as a safety net.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import { isRulesChanged } from "#lib/rules/events.ts";
import { sentence } from "#lib/rules/model.ts";
import type { RuleSet, SystemHost } from "#lib/rules/sets.ts";
import { live, type LiveSource } from "./live.svelte.ts";

type StoreApi = Pick<ApiClient, "GET" | "POST" | "PUT" | "DELETE">;

export type Status = "loading" | "ready" | "failed";
export type Result<T = undefined> =
  | ({ ok: true } & (T extends undefined ? object : { value: T }))
  | { ok: false; message: string };

export interface RuleSetsDeps {
  api?: StoreApi;
  source?: LiveSource;
  pollMs?: number;
  /** Told after a switch closed waiting requests (the nav badge). */
  onDecidedElsewhere?: () => void;
}

const DOWN = "puddle's service isn't answering.";

export class RuleSetsStore {
  sets = $state.raw<RuleSet[]>([]);
  system = $state.raw<SystemHost[]>([]);
  status = $state<Status>("loading");

  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;
  readonly #pollMs: number;
  readonly #onChange: (() => void) | undefined;

  constructor(deps: RuleSetsDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#source = deps.source;
    this.#pollMs = deps.pollMs ?? 60_000;
    this.#onChange = deps.onDecidedElsewhere;
  }

  /** Reads the sets and the System managed hosts; never throws. */
  async refresh(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/rule-sets");
      if (data) {
        this.sets = data.sets;
        this.system = data.system_managed;
        this.status = "ready";
      } else if (this.status === "loading") {
        this.status = "failed";
      }
    } catch {
      if (this.status === "loading") this.status = "failed";
    }
  }

  #put(set: RuleSet): void {
    const known = this.sets.some((s) => s.id === set.id);
    this.sets = known
      ? this.sets.map((s) => (s.id === set.id ? set : s))
      : [...this.sets, set];
  }

  /** Makes an empty set of your own, on everywhere. */
  async create(name: string, description: string): Promise<Result<RuleSet>> {
    try {
      const { data, error } = await this.#api.POST("/api/rule-sets", {
        body: { name, description },
      });
      if (!data) {
        return {
          ok: false,
          message: sentence(error?.message ?? "puddle refused the name"),
        };
      }
      this.#put(data);
      return { ok: true, value: data };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Renames one of your sets or changes its description. */
  async rename(
    id: string,
    name: string,
    description: string,
  ): Promise<Result<RuleSet>> {
    try {
      const { data, error } = await this.#api.PUT("/api/rule-sets/{id}", {
        params: { path: { id } },
        body: { name, description },
      });
      if (!data) {
        return {
          ok: false,
          message: sentence(error?.message ?? "puddle refused the name"),
        };
      }
      this.#put(data);
      return { ok: true, value: data };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Deletes one of your sets with its entries. A set that is already gone counts as deleted. */
  async remove(id: string): Promise<Result> {
    try {
      const { response } = await this.#api.DELETE("/api/rule-sets/{id}", {
        params: { path: { id } },
      });
      if (!response.ok && response.status !== 404) {
        return { ok: false, message: "puddle couldn't delete that rule set." };
      }
      this.sets = this.sets.filter((s) => s.id !== id);
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /**
   * Switches a set on or off for every workspace (`workspace` `null`) or for one; `enabled`
   * `null` makes that level follow the next one. Returns how many waiting requests it closed.
   */
  async switchSet(
    id: string,
    workspace: string | null,
    enabled: boolean | null,
  ): Promise<Result<number>> {
    try {
      const { data, error } = await this.#api.PUT(
        "/api/rule-sets/{id}/switch",
        {
          params: { path: { id } },
          body: {
            sandbox: workspace as components["schemas"]["SandboxName"] | null,
            enabled,
          },
        },
      );
      if (!data) {
        return {
          ok: false,
          message: sentence(error?.message ?? "puddle refused the switch"),
        };
      }
      this.#put(data.set);
      if (data.closed.length > 0) this.#onChange?.();
      return { ok: true, value: data.closed.length };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Starts listening and polling; returns the function that stops both. */
  start(): () => void {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unsubscribe = this.#source?.subscribe({
      event: (event) => {
        if (isRulesChanged(event)) void this.refresh();
      },
      resync: () => void this.refresh(),
    });
    const tick = () => {
      timer = setTimeout(() => {
        if (stopped) return;
        void this.refresh().finally(tick);
      }, this.#pollMs);
    };
    void this.refresh().finally(() => {
      if (!stopped) tick();
    });
    return () => {
      stopped = true;
      clearTimeout(timer);
      unsubscribe?.();
    };
  }
}

export const ruleSets = new RuleSetsStore({
  source: live,
  onDecidedElsewhere: () => void live.refresh(),
});
