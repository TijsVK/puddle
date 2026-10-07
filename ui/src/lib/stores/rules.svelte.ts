// SPDX-License-Identifier: GPL-3.0-or-later
// The rules screen's state: every rule the API holds, and the three things a user does to one
// (add, change the expiry, delete).
//
// Live data: it listens to the shell's event stream for `rules_changed` and refetches. Until the
// API sends that event it polls every 10 s; the first one it sees turns the poll down to a slow
// safety refresh. A resync (`lagged`, reconnect) refetches too.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import { isRulesChanged } from "#lib/rules/events.ts";
import { sentence, type Rule } from "#lib/rules/model.ts";
import { live, type LiveSource } from "./live.svelte.ts";

export type NewRule = components["schemas"]["NewRuleRequest"];
export type Status = "loading" | "ready" | "failed";

/** `pattern`: the server refused the pattern or expiry; `form`: anything else. */
export interface ServerError {
  field: "pattern" | "form";
  message: string;
}

export type AddResult =
  { ok: true; rule: Rule } | ({ ok: false } & ServerError);

export type ChangeResult = { ok: true } | { ok: false; message: string };

type StoreApi = Pick<ApiClient, "GET" | "POST" | "PUT" | "DELETE">;

export interface RulesDeps {
  api?: StoreApi;
  source?: LiveSource;
  /** Poll while the API sends no rule events. */
  pollMs?: number;
  /** Poll once rule events have been seen. */
  slowPollMs?: number;
  /** Told after a change that may have closed open requests (the nav badge). */
  onDecidedElsewhere?: () => void;
}

const DOWN = "puddle's service isn't answering.";

export class RulesStore {
  rules = $state.raw<Rule[]>([]);
  status = $state<Status>("loading");

  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;
  readonly #pollMs: number;
  readonly #slowPollMs: number;
  readonly #onChange: (() => void) | undefined;
  #sawEvents = false;
  #refreshing: Promise<void> | null = null;
  #again = false;

  constructor(deps: RulesDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#source = deps.source;
    this.#pollMs = deps.pollMs ?? 10_000;
    this.#slowPollMs = deps.slowPollMs ?? 60_000;
    this.#onChange = deps.onDecidedElsewhere;
  }

  /** Reads every rule; never throws. Calls that overlap share one run, and one more follows. */
  refresh(): Promise<void> {
    if (this.#refreshing) {
      this.#again = true;
      return this.#refreshing;
    }
    this.#refreshing = this.#load().finally(() => {
      this.#refreshing = null;
      if (this.#again) {
        this.#again = false;
        void this.refresh();
      }
    });
    return this.#refreshing;
  }

  async #load(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/rules");
      if (data) {
        this.rules = data.rules;
        this.status = "ready";
      } else if (this.status === "loading") {
        this.status = "failed";
      }
    } catch {
      if (this.status === "loading") this.status = "failed";
    }
  }

  /** Creates a rule. The server's refusals (public suffix, bad pattern) come back as text. */
  async add(rule: NewRule): Promise<AddResult> {
    try {
      const { data, error, response } = await this.#api.POST("/api/rules", {
        body: rule,
      });
      if (!data) {
        const field = response.status === 422 ? "pattern" : "form";
        return {
          ok: false,
          field,
          message: sentence(error?.message ?? "puddle refused the rule"),
        };
      }
      this.rules = [data, ...this.rules.filter((r) => r.id !== data.id)];
      this.#onChange?.();
      return { ok: true, rule: data };
    } catch {
      return { ok: false, field: "form", message: DOWN };
    }
  }

  /** Changes when a rule ends; `null` makes it permanent. */
  async setExpiry(id: number, expiresAt: number | null): Promise<ChangeResult> {
    try {
      const { data, error, response } = await this.#api.PUT(
        "/api/rules/{id}/expiry",
        { params: { path: { id } }, body: { expires_at: expiresAt } },
      );
      if (!data) {
        if (response.status === 404) {
          this.rules = this.rules.filter((r) => r.id !== id);
          return { ok: false, message: "That rule is already gone." };
        }
        return {
          ok: false,
          message: sentence(error?.message ?? "puddle refused the change"),
        };
      }
      this.rules = this.rules.map((r) => (r.id === id ? data : r));
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Deletes a rule. A rule that is already gone counts as deleted. */
  async remove(id: number): Promise<ChangeResult> {
    try {
      const { response } = await this.#api.DELETE("/api/rules/{id}", {
        params: { path: { id } },
      });
      if (!response.ok && response.status !== 404) {
        return { ok: false, message: "puddle couldn't delete that rule." };
      }
      this.rules = this.rules.filter((r) => r.id !== id);
      return { ok: true };
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
        if (!isRulesChanged(event)) return;
        this.#sawEvents = true;
        void this.refresh();
      },
      resync: () => void this.refresh(),
    });
    const tick = () => {
      timer = setTimeout(
        () => {
          if (stopped) return;
          void this.refresh().finally(tick);
        },
        this.#sawEvents ? this.#slowPollMs : this.#pollMs,
      );
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

export const rulesStore = new RulesStore({
  source: live,
  onDecidedElsewhere: () => void live.refresh(),
});
