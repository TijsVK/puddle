// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { FakeWorkspaces } from "#lib/testing/fake-workspaces.ts";
import { WorkspaceSettings } from "./workspace-settings.svelte.ts";

let api: FakeWorkspaces;
let settings: WorkspaceSettings;

beforeEach(() => {
  api = new FakeWorkspaces();
  settings = new WorkspaceSettings(api as never);
});

describe("loading", () => {
  it("reads the overrides, what is in effect and the global values", async () => {
    expect(settings.status).toBe("loading");
    await settings.load("demo");
    expect(settings.status).toBe("ready");
    expect(settings.overrides?.memory).toBeNull();
    expect(settings.effective?.memory).toEqual({
      value: 8192,
      source: "global",
    });
    expect(settings.global?.memory.value).toBe(8192);
  });

  it("fails without a service, and on a refusal", async () => {
    api.down = true;
    await settings.load("demo");
    expect(settings.status).toBe("failed");
    api.down = false;
    api.refuse.set("GET /api/settings", { status: 500, message: "x" });
    await settings.load("demo");
    expect(settings.status).toBe("failed");
  });

  it("a quiet reload keeps the form on screen even when it fails", async () => {
    await settings.load("demo");
    api.down = true;
    await settings.load("demo", true);
    expect(settings.status).toBe("ready");
    api.down = false;
    api.refuse.set("GET /api/settings", { status: 500, message: "x" });
    await settings.load("demo", true);
    expect(settings.status).toBe("ready");
  });

  it("ignores an answer that a newer load has overtaken", async () => {
    await settings.load("seed");
    api.overrides["old"] = { ...settings.overrides!, memory: 1024 };
    const real = api.GET;
    let slow = true;
    api.GET = async (
      path: string,
      init?: { params?: { path?: Record<string, unknown> } },
    ) => {
      const result = await real(path, init);
      if (slow && path === "/api/settings/sandboxes/{sandbox}") {
        slow = false;
        await new Promise((r) => setTimeout(r, 20));
      }
      return result;
    };
    const first = settings.load("old");
    await settings.load("new");
    await first;
    expect(settings.overrides?.memory).toBeNull();
  });
});

describe("saving", () => {
  it("sends the whole layer with the change and keeps what the service answers", async () => {
    await settings.load("demo");
    expect(await settings.change({ memory: 4096 })).toEqual({ ok: true });
    expect(api.bodies.at(-1)).toMatchObject({
      overrides: { memory: 4096, clipboard_read: null, zoom_hotkeys: null },
    });
    expect(settings.overrides?.memory).toBe(4096);
    expect(settings.effective?.memory).toEqual({
      value: 4096,
      source: "sandbox",
    });
    await settings.change({ memory: null });
    expect(settings.effective?.memory.source).toBe("global");
  });

  it("keeps what it had when the service refuses, and says why", async () => {
    await settings.load("demo");
    api.refuse.set("PUT /api/settings/sandboxes/{sandbox}", {
      status: 422,
      message: "memory is too small",
    });
    expect(await settings.change({ memory: 1 })).toEqual({
      ok: false,
      message: "memory is too small",
    });
    expect(settings.overrides?.memory).toBeNull();
  });

  it("says the service is down", async () => {
    await settings.load("demo");
    api.down = true;
    expect(await settings.change({ memory: 4096 })).toEqual({
      ok: false,
      message: "puddle's service isn't answering.",
    });
  });

  it("can't save before it has loaded", async () => {
    expect(await settings.change({ memory: 4096 })).toEqual({
      ok: false,
      message: "Settings aren't loaded.",
    });
  });
});
