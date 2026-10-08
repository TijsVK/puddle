// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { FakeSettings } from "#lib/testing/fake-settings.ts";
import {
  bodyFrom,
  CODE_SERVER_NOTE,
  MICROSOFT_NOTE,
  MS_POPUP,
  MS_TERMS_URL,
  MS_TERMS_VERSION,
  memorySizes,
  needsMicrosoftConsent,
  parseGrace,
  serverNote,
  serverOf,
  toggleOn,
} from "./model.ts";

async function view() {
  return (await new FakeSettings().GET("/api/settings"))
    .data as never as Parameters<typeof bodyFrom>[0];
}

describe("the consent wording", () => {
  it("states the download exactly and links Microsoft's server licence", () => {
    expect(MS_POPUP.statement).toBe(
      "puddle downloads the server from Microsoft",
    );
    expect(MS_TERMS_URL).toBe("https://code.visualstudio.com/license/server");
    expect(MS_TERMS_VERSION).toBe(MS_TERMS_URL);
  });

  it("asks until the exact terms were accepted", () => {
    const at = 1;
    expect(needsMicrosoftConsent({ state: "not_asked" })).toBe(true);
    expect(
      needsMicrosoftConsent({
        state: "declined",
        at,
        terms_version: MS_TERMS_VERSION,
      }),
    ).toBe(true);
    expect(
      needsMicrosoftConsent({ state: "granted", at, terms_version: "older" }),
    ).toBe(true);
    expect(
      needsMicrosoftConsent({
        state: "granted",
        at,
        terms_version: MS_TERMS_VERSION,
      }),
    ).toBe(false);
  });

  it("says why some extensions may be missing in code-server only", () => {
    expect(serverNote("code_server")).toBe(CODE_SERVER_NOTE);
    expect(CODE_SERVER_NOTE).toMatch(/Open VSX/);
    expect(serverNote("microsoft")).toBe(MICROSOFT_NOTE);
  });
});

describe("choices", () => {
  it("serverOf defaults to code-server", async () => {
    const v = await view();
    expect(serverOf(v)).toBe("code_server");
    expect(
      serverOf({
        ...v,
        vscode_server: { ...v.vscode_server, server: "microsoft" },
      }),
    ).toBe("microsoft");
  });

  it("memory sizes include a non-standard value in order", () => {
    expect(memorySizes(8192).map((s) => s.label)).toEqual([
      "2 GiB",
      "4 GiB",
      "8 GiB",
      "12 GiB",
      "16 GiB",
      "24 GiB",
      "32 GiB",
    ]);
    expect(memorySizes(3000).map((s) => s.value)).toEqual([
      2048, 3000, 4096, 8192, 12288, 16384, 24576, 32768,
    ]);
  });

  it("grace accepts whole seconds from 30 to a day", () => {
    expect(parseGrace(" 300 ")).toEqual({ ok: true, secs: 300 });
    expect(parseGrace("30")).toEqual({ ok: true, secs: 30 });
    expect(parseGrace("86400")).toEqual({ ok: true, secs: 86_400 });
    for (const bad of ["", "abc", "1.5", "-5", "29", "86401"]) {
      expect(parseGrace(bad).ok, bad).toBe(false);
    }
    expect(parseGrace("5")).toEqual({
      ok: false,
      message: "Use between 30 and 86400 seconds.",
    });
    expect(parseGrace("x")).toEqual({
      ok: false,
      message: "Enter a whole number of seconds.",
    });
  });

  it("toggleOn treats unset as off", () => {
    expect([
      toggleOn(true),
      toggleOn(false),
      toggleOn(null),
      toggleOn(undefined),
    ]).toEqual([true, false, false, false]);
  });
});

describe("bodyFrom", () => {
  it("keeps what is stored and replaces only the patched parts", async () => {
    const v = await view();
    const body = bodyFrom(v, {
      layer: { memory: 4096 },
      server: { telemetry: true },
      ui: { sound: true },
    });
    expect(body.workspace_defaults.memory).toBe(4096);
    expect(body.workspace_defaults.zoom_hotkeys).toBeNull();
    expect(body.vscode_server).toEqual({
      server: null,
      telemetry: true,
      auto_update: null,
    });
    expect(body.ui.sound).toBe(true);
    expect(bodyFrom(v)).toEqual({
      workspace_defaults: v.workspace_defaults,
      vscode_server: v.vscode_server,
      ui: v.ui,
    });
  });
});
