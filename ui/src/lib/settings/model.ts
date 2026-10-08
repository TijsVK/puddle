// SPDX-License-Identifier: GPL-3.0-or-later
// The global settings as the screen shows them: the wording of the Microsoft server consent,
// what each control offers, and how an edit becomes the whole document the API replaces.
import type { components } from "#lib/api/schema.d.ts";
import { formatMib } from "#lib/workspaces/model.ts";

type S = components["schemas"];
export type GlobalView = S["GlobalSettingsView"];
export type GlobalBody = Required<S["GlobalSettingsRequest"]>;
export type Layer = S["SettingsLayer"];
export type Ui = S["UiPrefs"];
export type VsCodeServer = S["VsCodeServer"];
export type Consent = S["Consent"];
export type ServerChoice = NonNullable<VsCodeServer["server"]>;
export type CloseBehaviour = NonNullable<Ui["close_behaviour"]>;

/** The licence the user accepts. Its URL is also the version of the terms recorded with the consent. */
export const MS_TERMS_URL = "https://code.visualstudio.com/license/server";
export const MS_TERMS_VERSION = MS_TERMS_URL;

/** The words of the enable popup. The first sentence is fixed: the user's licensee consent covers it. */
export const MS_POPUP = {
  title: "Use Microsoft's VS Code server?",
  statement: "puddle downloads the server from Microsoft",
  rest: "and starts it in your workspace. By continuing you accept the Microsoft VS Code Server licence terms as your own licence. puddle does not ship, change or keep a copy of the server.",
  licenceLink: "Microsoft VS Code Server licence terms",
  telemetry: "Allow the server to send telemetry to Microsoft",
  accept: "Accept and use Microsoft's server",
  decline: "Keep code-server",
} as const;

export const CODE_SERVER_NOTE =
  "code-server (bundled). Some extensions may not be listed: it is not Microsoft's official VS Code, so it uses the Open VSX registry instead of Microsoft's Marketplace.";
export const MICROSOFT_NOTE =
  "Microsoft's VS Code server, downloaded by puddle from Microsoft.";

export const serverNote = (server: ServerChoice): string =>
  server === "microsoft" ? MICROSOFT_NOTE : CODE_SERVER_NOTE;

/** Whether choosing Microsoft's server must first show the popup: no consent for these exact terms. */
export function needsMicrosoftConsent(consent: Consent): boolean {
  return !(
    consent.state === "granted" && consent.terms_version === MS_TERMS_VERSION
  );
}

/** The server in use: an unset choice is code-server. */
export const serverOf = (view: GlobalView): ServerChoice =>
  view.vscode_server.server ?? "code_server";

export const GLOBAL_MEMORY_MIB: readonly number[] = [
  2048, 4096, 8192, 12_288, 16_384, 24_576, 32_768,
];

/** Sizes to offer for the default memory, with the one in effect added when it is not standard. */
export function memorySizes(
  current: number,
): { value: number; label: string }[] {
  const sizes = new Set([...GLOBAL_MEMORY_MIB, current]);
  return [...sizes]
    .sort((a, b) => a - b)
    .map((mib) => ({ value: mib, label: formatMib(mib) }));
}

export const GRACE_MIN = 30;
export const GRACE_MAX = 86_400;

/** The reconnection grace in seconds from what was typed, or the reason it cannot be used. */
export function parseGrace(
  text: string,
): { ok: true; secs: number } | { ok: false; message: string } {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed))
    return { ok: false, message: "Enter a whole number of seconds." };
  const secs = Number(trimmed);
  if (secs < GRACE_MIN || secs > GRACE_MAX)
    return {
      ok: false,
      message: `Use between ${GRACE_MIN} and ${GRACE_MAX} seconds.`,
    };
  return { ok: true, secs };
}

export const CLOSE_OPTIONS: { value: CloseBehaviour; label: string }[] = [
  { value: "tray", label: "Keep running in the tray" },
  { value: "quit", label: "Quit puddle" },
];

export const LOCAL_EXPLAIN: Record<string, string> = {
  loopback: "Services on your own machine, like a database in Docker Desktop.",
  private: "Your home or office network (10.x, 192.168.x, ...).",
  link_local: "169.254.x.x and fe80::, usually device discovery.",
  metadata: "Instance metadata endpoints such as 169.254.169.254.",
  special: "Carrier-grade NAT, benchmarking and similar ranges.",
};

/** The document a save sends: today's values, with the parts being changed replaced. */
export function bodyFrom(
  view: GlobalView,
  patch: {
    layer?: Partial<Layer>;
    server?: Partial<VsCodeServer>;
    ui?: Partial<Ui>;
  } = {},
): GlobalBody {
  return {
    workspace_defaults: { ...view.workspace_defaults, ...patch.layer },
    vscode_server: { ...view.vscode_server, ...patch.server },
    ui: { ...view.ui, ...patch.ui },
  };
}

/** What a toggle shows: the stored value, else puddle's default (off). */
export const toggleOn = (value: boolean | null | undefined): boolean =>
  value === true;
