// SPDX-License-Identifier: GPL-3.0-or-later
// Whether the first-run flow has been through, as the API keeps it (in puddle's settings).
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";

export type FirstRun = components["schemas"]["FirstRun"];
export type Status = "loading" | "ready" | "failed";

type StoreApi = Pick<ApiClient, "GET" | "PUT">;

export class FirstRunStore {
  state = $state.raw<FirstRun | null>(null);
  status = $state<Status>("loading");

  readonly #api: StoreApi;

  constructor(api: StoreApi = defaultApi) {
    this.#api = api;
  }

  /** Reads the state; never throws. */
  async load(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/first-run");
      if (data) {
        this.state = data;
        this.status = "ready";
      } else if (this.state === null) {
        this.status = "failed";
      }
    } catch {
      if (this.state === null) this.status = "failed";
    }
  }

  /** Records that the flow was finished or skipped; says why when puddle could not keep that. */
  async complete(): Promise<{ ok: true } | { ok: false; message: string }> {
    try {
      const { data, error } = await this.#api.PUT("/api/first-run", {
        body: { completed: true },
      });
      if (!data) {
        return {
          ok: false,
          message:
            error?.error === "newer_settings"
              ? "These settings were saved by a newer puddle. Update puddle to change them."
              : (error?.message ?? "puddle refused that."),
        };
      }
      this.state = data;
      this.status = "ready";
      return { ok: true };
    } catch {
      return { ok: false, message: "puddle's service isn't answering." };
    }
  }
}

export const firstRun = new FirstRunStore();
