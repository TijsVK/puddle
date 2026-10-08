// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from "vitest";

const api = await vi.hoisted(async () => {
  const mod = await import("#lib/testing/fake-settings.ts");
  return new mod.FakeSettings();
});
vi.mock("#lib/api/client.ts", () => ({ api }));

import { globalSettings } from "#lib/stores/global-settings.svelte.ts";
import { density } from "./density.svelte.ts";

beforeEach(() => {
  api.reset();
  globalSettings.view = null;
  localStorage.clear();
  delete document.documentElement.dataset["density"];
  density.choice = "comfortable";
});

describe("the density and the settings", () => {
  it("applies the choice stored in the settings, whatever the page remembered", async () => {
    localStorage.setItem("puddle.density", "comfortable");
    density.init();
    api.ui.density = "compact";
    await density.sync();
    expect(density.choice).toBe("compact");
    expect(document.documentElement.dataset["density"]).toBe("compact");
    expect(localStorage.getItem("puddle.density")).toBe("compact");
  });

  it("applies the hint first, an unset choice means comfortable, and an unreadable service keeps the hint", async () => {
    localStorage.setItem("puddle.density", "compact");
    density.init();
    expect(document.documentElement.dataset["density"]).toBe("compact");
    api.down = true;
    await density.sync();
    expect(density.choice).toBe("compact");
    api.down = false;
    await density.sync();
    expect(density.choice).toBe("comfortable");
    expect(document.documentElement.dataset["density"]).toBeUndefined();
  });

  it("stores a new choice through the API, loading the settings first when needed", async () => {
    expect(await density.set("compact")).toBe(true);
    expect(api.ui.density).toBe("compact");
    expect(density.choice).toBe("compact");
  });

  it("applies a choice even when it can't be stored", async () => {
    api.down = true;
    expect(await density.set("compact")).toBe(false);
    expect(density.choice).toBe("compact");
    expect(document.documentElement.dataset["density"]).toBe("compact");
  });
});
