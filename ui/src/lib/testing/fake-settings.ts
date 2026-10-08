// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's global settings and consents endpoints, in the shape openapi-fetch
// returns them. Like the API it refuses Microsoft's server without a granted consent. Not
// shipped (tests import it).
import type { components } from "#lib/api/schema.d.ts";

type S = components["schemas"];
type Body = S["GlobalSettingsRequest"];

const noLayer = (): S["SettingsLayer"] => ({
  clipboard_read: null,
  local_toggles: {
    link_local: null,
    loopback: null,
    metadata: null,
    private: null,
    special: null,
  },
  memory: null,
  reconnection_grace: null,
  wildcards_reach_local: null,
  zoom_hotkeys: null,
  direct_ssh: null,
});

export class FakeSettings {
  layer = noLayer();
  /** Fields the stored document has that puddle doesn't know. */
  unknown: string[] = [];
  vscode: S["VsCodeServer"] = {
    server: null,
    telemetry: null,
    auto_update: null,
  };
  ui: S["UiPrefs"] = {
    theme: null,
    density: null,
    notifications: null,
    sound: null,
    close_behaviour: null,
  };
  consent: S["Consent"] = { state: "not_asked" };
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Refuse the next call to a path (`"PUT /api/settings"`). */
  refuse = new Map<
    string,
    { status: number; error: string; message: string }
  >();
  version = "0.1.0";

  /** Back to a fresh backend, keeping the object (a module mock holds on to it). */
  reset(): void {
    const fresh = new FakeSettings();
    this.layer = fresh.layer;
    this.vscode = fresh.vscode;
    this.ui = fresh.ui;
    this.consent = fresh.consent;
    this.calls = [];
    this.bodies = [];
    this.down = false;
    this.refuse = new Map();
    this.version = fresh.version;
  }

  private reply(
    status: number,
    data?: unknown,
    error = "invalid",
    message = "",
  ) {
    const response = { status, ok: status < 400 } as Response;
    return status < 400
      ? { data, response }
      : { error: { error, message }, response };
  }

  private refusal(key: string) {
    const r = this.refuse.get(key);
    if (!r) return null;
    this.refuse.delete(key);
    return this.reply(r.status, undefined, r.error, r.message);
  }

  private pick(v: boolean | null, fallback = false) {
    return {
      value: v ?? fallback,
      source: v === null ? "default" : "global",
    } as const;
  }

  private view(): S["GlobalSettingsView"] {
    const l = this.layer;
    return {
      workspace_defaults: l,
      vscode_server: this.vscode,
      ui: this.ui,
      unknown_fields: this.unknown,
      effective: {
        memory: {
          value: l.memory ?? 8192,
          source: l.memory === null ? "default" : "global",
        },
        local_toggles: {
          loopback: this.pick(l.local_toggles.loopback),
          private: this.pick(l.local_toggles.private),
          link_local: this.pick(l.local_toggles.link_local),
          metadata: this.pick(l.local_toggles.metadata),
          special: this.pick(l.local_toggles.special),
        },
        wildcards_reach_local: this.pick(l.wildcards_reach_local),
        reconnection_grace: {
          value: l.reconnection_grace ?? 300,
          source: l.reconnection_grace === null ? "default" : "global",
        },
        zoom_hotkeys: this.pick(l.zoom_hotkeys, true),
        direct_ssh: this.pick(l.direct_ssh),
        clipboard_read: {
          value: l.clipboard_read ?? "ask",
          source: l.clipboard_read === null ? "default" : "global",
        },
      },
    };
  }

  private consents(): S["Consents"] {
    return {
      telemetry: { state: "not_asked" },
      crash_reports: { state: "not_asked" },
      vscode_server: this.consent,
    };
  }

  GET = async (path: string) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`GET ${path}`);
    if (refused) return refused;
    switch (path) {
      case "/api/settings":
        return this.reply(200, this.view());
      case "/api/consents":
        return this.reply(200, this.consents());
      case "/api/health":
        return this.reply(200, { version: this.version, api_version: "0.3.0" });
    }
    throw new Error(`unexpected GET ${path}`);
  };

  PUT = async (
    path: string,
    init: { params?: { path?: { kind?: string } }; body: unknown },
  ) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`PUT ${path}`);
    if (refused) return refused;
    if (path === "/api/consents/{kind}") {
      const b = init.body as S["ConsentRequest"];
      this.consent =
        b.decision === "granted"
          ? {
              state: "granted",
              at: 1_700_000_000_000,
              terms_version: b.terms_version,
            }
          : {
              state: "declined",
              at: 1_700_000_000_000,
              terms_version: b.terms_version,
            };
      return this.reply(200, this.consents());
    }
    const b = init.body as Body;
    if (
      b.vscode_server?.server === "microsoft" &&
      this.consent.state !== "granted"
    ) {
      return this.reply(
        422,
        undefined,
        "invalid",
        "Microsoft's server needs the user's consent first",
      );
    }
    this.layer = { ...noLayer(), ...b.workspace_defaults };
    this.vscode = {
      server: null,
      telemetry: null,
      auto_update: null,
      ...b.vscode_server,
    };
    this.ui = {
      theme: null,
      density: null,
      notifications: null,
      sound: null,
      close_behaviour: null,
      ...b.ui,
    };
    return this.reply(200, this.view());
  };
}
