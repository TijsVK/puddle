// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  applyDensity,
  DENSITY_KEY,
  isDensityChoice,
  loadDensity,
  saveDensity,
} from "./density.ts";

function memory(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

const broken = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
};

describe("density choice", () => {
  it("knows its two values", () => {
    expect(["comfortable", "compact"].every(isDensityChoice)).toBe(true);
    expect(isDensityChoice("tight")).toBe(false);
    expect(isDensityChoice(null)).toBe(false);
  });

  it("reads the hint, and falls back to comfortable when it is missing, wrong or unreadable", () => {
    expect(loadDensity(memory({ [DENSITY_KEY]: "compact" }))).toBe("compact");
    expect(loadDensity(memory({ [DENSITY_KEY]: "tight" }))).toBe("comfortable");
    expect(loadDensity(memory())).toBe("comfortable");
    expect(loadDensity(undefined)).toBe("comfortable");
    expect(loadDensity(broken)).toBe("comfortable");
  });

  it("writes the hint, and survives storage that throws or is missing", () => {
    const storage = memory();
    saveDensity(storage, "compact");
    expect(storage.data.get(DENSITY_KEY)).toBe("compact");
    expect(() => saveDensity(broken, "compact")).not.toThrow();
    expect(() => saveDensity(undefined, "compact")).not.toThrow();
  });

  it("marks compact on the root element and leaves comfortable unmarked", () => {
    const root = document.createElement("html");
    applyDensity(root, "compact");
    expect(root.dataset["density"]).toBe("compact");
    applyDensity(root, "comfortable");
    expect(root.dataset["density"]).toBeUndefined();
  });
});
