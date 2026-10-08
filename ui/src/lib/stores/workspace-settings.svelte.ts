// SPDX-License-Identifier: GPL-3.0-or-later
// One workspace's settings: its overrides, what is in effect, and the global values the
// "use the global setting" choices name. A change is saved at once and replaces the overrides
// (the API replaces, so every save sends the whole layer).
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import type { Layer } from "#lib/workspaces/settings.ts";

type Effective = components["schemas"]["EffectiveSettings"];
type StoreApi = Pick<ApiClient, "GET" | "PUT">;

export type Status = "loading" | "ready" | "failed";
export type SaveResult = { ok: true } | { ok: false; message: string };

export class WorkspaceSettings {
  status = $state<Status>("loading");
  overrides = $state.raw<Layer | null>(null);
  effective = $state.raw<Effective | null>(null);
  /** What a workspace with no overrides gets: the global values. */
  global = $state.raw<Effective | null>(null);
  #name = "";
  /** Calls to `load` and `change` in order, so a slow answer never overwrites a newer one. */
  #ticket = 0;
  readonly #api: StoreApi;

  constructor(api: StoreApi = defaultApi) {
    this.#api = api;
  }

  /** Reads both layers. `quiet` keeps the form on screen while it does (after a failed save). */
  async load(name: string, quiet = false): Promise<void> {
    this.#name = name;
    if (!quiet) this.status = "loading";
    const ticket = ++this.#ticket;
    try {
      const [mine, global] = await Promise.all([
        this.#api.GET("/api/settings/workspaces/{workspace}", {
          params: { path: { workspace: name } },
        }),
        this.#api.GET("/api/settings"),
      ]);
      if (ticket !== this.#ticket) return;
      if (mine.data && global.data) {
        this.overrides = mine.data.overrides;
        this.effective = mine.data.effective;
        this.global = global.data.effective;
        this.status = "ready";
      } else if (!quiet) {
        this.status = "failed";
      }
    } catch {
      if (ticket === this.#ticket && !quiet) this.status = "failed";
    }
  }

  /** Saves one override (or several); `null` makes a setting inherit again. */
  async change(patch: Partial<Layer>): Promise<SaveResult> {
    if (!this.overrides)
      return { ok: false, message: "Settings aren't loaded." };
    const body: Layer = { ...this.overrides, ...patch };
    const ticket = ++this.#ticket;
    try {
      const { data, error } = await this.#api.PUT(
        "/api/settings/workspaces/{workspace}",
        {
          params: { path: { workspace: this.#name } },
          body: { overrides: body },
        },
      );
      if (!data) {
        return {
          ok: false,
          message: error?.message ?? "puddle couldn't save that.",
        };
      }
      if (ticket === this.#ticket) {
        this.overrides = data.overrides;
        this.effective = data.effective;
      }
      return { ok: true };
    } catch {
      return { ok: false, message: "puddle's service isn't answering." };
    }
  }
}
