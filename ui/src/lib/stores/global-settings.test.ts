// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { MS_TERMS_VERSION } from "#lib/settings/model.ts";
import { FakeSettings } from "#lib/testing/fake-settings.ts";
import { GlobalSettings } from "./global-settings.svelte.ts";

let api: FakeSettings;
let store: GlobalSettings;

beforeEach(() => {
  api = new FakeSettings();
  store = new GlobalSettings(api as never);
});

describe("loading", () => {
  it("reads settings and consents", async () => {
    expect(store.status).toBe("loading");
    await store.load();
    expect(store.status).toBe("ready");
    expect(store.view?.effective.memory.value).toBe(8192);
    expect(store.consents?.vscode_server.state).toBe("not_asked");
  });

  it("fails without a service or on a refusal, and says when a newer puddle wrote them", async () => {
    api.down = true;
    await store.load();
    expect(store.status).toBe("failed");
    api.down = false;
    api.refuse.set("GET /api/settings", {
      status: 500,
      error: "internal",
      message: "x",
    });
    await store.load();
    expect(store.status).toBe("failed");
    api.refuse.set("GET /api/settings", {
      status: 409,
      error: "newer_settings",
      message: "newer",
    });
    await store.load();
    expect(store.status).toBe("newer");
  });

  it("a quiet load keeps what it has when it fails", async () => {
    await store.load();
    api.down = true;
    await store.load(true);
    expect(store.status).toBe("ready");
    api.down = false;
    api.refuse.set("GET /api/consents", {
      status: 500,
      error: "internal",
      message: "x",
    });
    await store.load(true);
    expect(store.status).toBe("ready");
    expect(store.view).not.toBeNull();
  });
});

describe("saving", () => {
  it("needs the settings loaded first", async () => {
    expect(await store.save({ ui: { sound: true } })).toEqual({
      ok: false,
      message: "Settings aren't loaded.",
    });
  });

  it("sends the whole document with the change and keeps the answer", async () => {
    await store.load();
    expect(await store.save({ layer: { memory: 4096 } })).toEqual({ ok: true });
    expect(store.view?.effective.memory).toEqual({
      value: 4096,
      source: "global",
    });
    expect(await store.save({ ui: { theme: "dark" } })).toEqual({ ok: true });
    // The second save still carries the first change.
    expect(store.view?.sandbox_defaults.memory).toBe(4096);
    expect(store.view?.ui.theme).toBe("dark");
  });

  it("runs saves one after another, each from the answer before", async () => {
    await store.load();
    const results = await Promise.all([
      store.save({ ui: { sound: true } }),
      store.save({ ui: { notifications: false } }),
    ]);
    expect(results).toEqual([{ ok: true }, { ok: true }]);
    expect(store.view?.ui.sound).toBe(true);
    expect(store.view?.ui.notifications).toBe(false);
  });

  it("reports a refusal, a newer puddle and a missing service", async () => {
    await store.load();
    api.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "too small",
    });
    expect(await store.save({ layer: { memory: 1 } })).toEqual({
      ok: false,
      message: "too small",
    });
    api.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "",
    });
    expect((await store.save({})).ok).toBe(false);
    api.refuse.set("PUT /api/settings", {
      status: 409,
      error: "newer_settings",
      message: "x",
    });
    const newer = await store.save({});
    expect(!newer.ok && newer.message).toMatch(/newer puddle/);
    api.down = true;
    expect(await store.save({})).toEqual({
      ok: false,
      message: "puddle's service isn't answering.",
    });
  });
});

describe("Microsoft's server", () => {
  it("records the consent with the terms version, then chooses the server", async () => {
    await store.load();
    expect(await store.grantMicrosoft(true)).toEqual({ ok: true });
    expect(api.consent).toMatchObject({
      state: "granted",
      terms_version: MS_TERMS_VERSION,
    });
    expect(store.consents?.vscode_server.state).toBe("granted");
    expect(store.view?.vscode_server).toMatchObject({
      server: "microsoft",
      telemetry: true,
    });
  });

  it("leaves telemetry off when the box was not checked", async () => {
    await store.load();
    await store.grantMicrosoft(false);
    expect(store.view?.vscode_server.telemetry).toBe(false);
  });

  it("stops at a refused or unreachable consent and chooses nothing", async () => {
    await store.load();
    api.refuse.set("PUT /api/consents/{kind}", {
      status: 422,
      error: "invalid",
      message: "no",
    });
    expect(await store.grantMicrosoft(false)).toEqual({
      ok: false,
      message: "no",
    });
    api.down = true;
    expect((await store.grantMicrosoft(false)).ok).toBe(false);
    api.down = false;
    expect(store.view?.vscode_server.server).toBeNull();
    expect(api.consent.state).toBe("not_asked");
  });
});
