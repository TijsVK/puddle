// SPDX-License-Identifier: GPL-3.0-or-later
// The user's global settings and consents, as the API holds them (nothing is kept in the page:
// the API port changes on every launch). Every change replaces the whole settings document, so
// saves run one after another, each built from the answer to the one before.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import {
  bodyFrom,
  MS_TERMS_VERSION,
  type GlobalBody,
  type GlobalView,
} from "#lib/settings/model.ts";

type Consents = components["schemas"]["Consents"];
type StoreApi = Pick<ApiClient, "GET" | "PUT">;

export type Status = "loading" | "ready" | "failed" | "newer";
export type SaveResult = { ok: true } | { ok: false; message: string };
type Patch = Parameters<typeof bodyFrom>[1];

export class GlobalSettings {
  status = $state<Status>("loading");
  view = $state.raw<GlobalView | null>(null);
  consents = $state.raw<Consents | null>(null);
  readonly #api: StoreApi;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(api: StoreApi = defaultApi) {
    this.#api = api;
  }

  /** Reads settings and consents. `quiet` keeps what is on screen if it fails. */
  async load(quiet = false): Promise<void> {
    if (!quiet) this.status = "loading";
    try {
      const [settings, consents] = await Promise.all([
        this.#api.GET("/api/settings"),
        this.#api.GET("/api/consents"),
      ]);
      if (settings.data && consents.data) {
        this.view = settings.data;
        this.consents = consents.data;
        this.status = "ready";
      } else if (!quiet) {
        this.status =
          settings.error?.error === "newer_settings" ? "newer" : "failed";
      }
    } catch {
      if (!quiet) this.status = "failed";
    }
  }

  /** Saves a change to the settings document. */
  save(patch: Patch): Promise<SaveResult> {
    return this.#serial(() => this.#put(patch));
  }

  /**
   * Records the user's agreement to Microsoft's terms, then chooses its server and sets the
   * telemetry choice from the popup. Declining records nothing: the popup just closes.
   */
  grantMicrosoft(telemetry: boolean): Promise<SaveResult> {
    return this.#serial(async () => {
      try {
        const { data, error } = await this.#api.PUT("/api/consents/{kind}", {
          params: { path: { kind: "vscode_server" } },
          body: { decision: "granted", terms_version: MS_TERMS_VERSION },
        });
        if (!data) return refused(error?.message);
        this.consents = data;
      } catch {
        return unreachable();
      }
      return this.#put({ server: { server: "microsoft", telemetry } });
    });
  }

  #serial<T>(run: () => Promise<T>): Promise<T> {
    const next = this.#queue.then(run, run);
    this.#queue = next.catch(() => undefined);
    return next;
  }

  async #put(patch: Patch): Promise<SaveResult> {
    if (!this.view) return { ok: false, message: "Settings aren't loaded." };
    const body: GlobalBody = bodyFrom(this.view, patch);
    try {
      const { data, error } = await this.#api.PUT("/api/settings", { body });
      if (!data) {
        return error?.error === "newer_settings"
          ? {
              ok: false,
              message:
                "These settings were saved by a newer puddle. Update puddle to change them.",
            }
          : refused(error?.message);
      }
      this.view = data;
      return { ok: true };
    } catch {
      return unreachable();
    }
  }
}

const refused = (message?: string): SaveResult => ({
  ok: false,
  message: message ?? "puddle couldn't save that.",
});
const unreachable = (): SaveResult => ({
  ok: false,
  message: "puddle's service isn't answering.",
});

export const globalSettings = new GlobalSettings();
