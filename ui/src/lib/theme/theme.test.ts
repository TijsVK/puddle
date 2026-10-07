// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  applyTheme,
  browserStorage,
  isThemeChoice,
  loadTheme,
  saveTheme,
  THEME_KEY,
} from "./theme.ts";

function memory(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    data,
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

describe("theme choice", () => {
  it("accepts only the three choices", () => {
    expect(["system", "light", "dark"].every(isThemeChoice)).toBe(true);
    expect(isThemeChoice("blue")).toBe(false);
    expect(isThemeChoice(null)).toBe(false);
  });

  it("loads a stored choice, and follows the OS for anything else", () => {
    expect(loadTheme(memory({ [THEME_KEY]: "dark" }))).toBe("dark");
    expect(loadTheme(memory({ [THEME_KEY]: "neon" }))).toBe("system");
    expect(loadTheme(memory())).toBe("system");
    expect(loadTheme(undefined)).toBe("system");
  });

  it("survives storage that throws", () => {
    expect(loadTheme(broken)).toBe("system");
    expect(() => saveTheme(broken, "dark")).not.toThrow();
  });

  it("saves the choice", () => {
    const storage = memory();
    saveTheme(storage, "light");
    expect(storage.data.get(THEME_KEY)).toBe("light");
    expect(() => saveTheme(undefined, "light")).not.toThrow();
  });

  it("sets data-theme for an override and clears it for system", () => {
    const root = document.createElement("html");
    applyTheme(root, "dark");
    expect(root.dataset["theme"]).toBe("dark");
    applyTheme(root, "light");
    expect(root.dataset["theme"]).toBe("light");
    applyTheme(root, "system");
    expect(root.dataset["theme"]).toBeUndefined();
  });

  it("finds the browser's storage", () => {
    expect(browserStorage()).toBe(globalThis.localStorage);
  });
});
