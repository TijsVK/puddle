// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  CLIPBOARD_OPTIONS,
  clipboardOptions,
  memoryFromChoice,
  memoryOptions,
  memoryToChoice,
  sourceLabel,
  toggleFromChoice,
  switchOptions,
  toggleOptions,
  toggleToChoice,
} from "./settings.ts";

describe("memory", () => {
  it("offers the global default first, then the sizes in order", () => {
    const options = memoryOptions(null, 8192);
    expect(options[0]).toEqual({
      value: "",
      label: "Use the global default (8 GiB)",
    });
    expect(options.slice(1).map((o) => o.label)).toEqual([
      "2 GiB",
      "4 GiB",
      "8 GiB",
      "12 GiB",
      "16 GiB",
      "24 GiB",
      "32 GiB",
    ]);
  });

  it("keeps an override that is not a standard size, in its place", () => {
    const labels = memoryOptions(5120, 8192).map((o) => o.label);
    expect(labels).toContain("5 GiB");
    expect(labels.indexOf("5 GiB")).toBeGreaterThan(labels.indexOf("4 GiB"));
    expect(labels.indexOf("5 GiB")).toBeLessThan(labels.indexOf("8 GiB"));
    expect(memoryOptions(4096, 8192)).toHaveLength(8);
  });

  it("converts between a choice and an override", () => {
    expect(memoryFromChoice("")).toBeNull();
    expect(memoryFromChoice("16384")).toBe(16_384);
    expect(memoryToChoice(null)).toBe("");
    expect(memoryToChoice(16_384)).toBe("16384");
  });
});

describe("toggles", () => {
  it("is inherit, on or off", () => {
    expect(toggleToChoice(null)).toBe("inherit");
    expect(toggleToChoice(true)).toBe("on");
    expect(toggleToChoice(false)).toBe("off");
    expect(toggleFromChoice("inherit")).toBeNull();
    expect(toggleFromChoice("on")).toBe(true);
    expect(toggleFromChoice("off")).toBe(false);
  });

  it("names what the global setting is", () => {
    expect(toggleOptions(false)[0]?.label).toBe(
      "Use the global setting (not allowed)",
    );
    expect(toggleOptions(true)[0]?.label).toBe(
      "Use the global setting (allowed)",
    );
    expect(toggleOptions(true).map((o) => o.value)).toEqual([
      "inherit",
      "on",
      "off",
    ]);
  });
});

describe("the login capture switch", () => {
  it("names what the global setting is, in the words of a switch", () => {
    expect(switchOptions(true)[0]?.label).toBe("Use the global setting (on)");
    expect(switchOptions(false)[0]?.label).toBe("Use the global setting (off)");
    expect(switchOptions(true).map((o) => [o.value, o.label])).toEqual([
      ["inherit", "Use the global setting (on)"],
      ["on", "On"],
      ["off", "Off"],
    ]);
  });
});

describe("clipboard", () => {
  it("names the global choice in the inherit option", () => {
    expect(clipboardOptions("ask")[0]).toEqual({
      value: "inherit",
      label: "Use the global setting (ask me each time)",
    });
    expect(clipboardOptions("deny")[0]?.label).toBe(
      "Use the global setting (never allow)",
    );
    expect(clipboardOptions("ask").slice(1)).toEqual(CLIPBOARD_OPTIONS);
  });
});

describe("sources", () => {
  it("are said in words", () => {
    expect(sourceLabel("workspace")).toBe("this workspace");
    expect(sourceLabel("global")).toBe("global setting");
    expect(sourceLabel("default")).toBe("puddle's default");
  });
});
