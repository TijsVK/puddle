// SPDX-License-Identifier: GPL-3.0-or-later
// A workspace's own settings as the form shows them: what each control offers and how a choice
// becomes an override (a value, or `null` to inherit).
import type { components } from "#lib/api/schema.d.ts";
import { formatMib } from "./model.ts";

export type Layer = components["schemas"]["SettingsLayer"];
export type Source = components["schemas"]["SettingSource"];
export type Clipboard = components["schemas"]["ClipboardRead"];

/** `""` inherits, anything else is a memory size in MiB. */
export const MEMORY_CHOICES_MIB: readonly number[] = [
  2048, 4096, 8192, 12_288, 16_384, 24_576, 32_768,
];

export interface Option<V extends string> {
  value: V;
  label: string;
}

/** The memory choices, with the current override added when it is not a standard size. */
export function memoryOptions(
  override: number | null,
  globalMib: number,
): Option<string>[] {
  const sizes = new Set(MEMORY_CHOICES_MIB);
  if (override !== null) sizes.add(override);
  return [
    { value: "", label: `Use the global default (${formatMib(globalMib)})` },
    ...[...sizes]
      .sort((a, b) => a - b)
      .map((mib) => ({ value: String(mib), label: formatMib(mib) })),
  ];
}

export function memoryFromChoice(value: string): number | null {
  return value === "" ? null : Number(value);
}

export const memoryToChoice = (value: number | null): string =>
  value === null ? "" : String(value);

/** A tri-state toggle as a select value: inherit, on or off. */
export type ToggleChoice = "inherit" | "on" | "off";

export const toggleToChoice = (value: boolean | null): ToggleChoice =>
  value === null ? "inherit" : value ? "on" : "off";

export const toggleFromChoice = (choice: string): boolean | null =>
  choice === "on" ? true : choice === "off" ? false : null;

export function toggleOptions(globalOn: boolean): Option<ToggleChoice>[] {
  return [
    {
      value: "inherit",
      label: `Use the global setting (${globalOn ? "allowed" : "not allowed"})`,
    },
    { value: "on", label: "Allowed" },
    { value: "off", label: "Not allowed" },
  ];
}

export const CLIPBOARD_OPTIONS: Option<Clipboard>[] = [
  { value: "ask", label: "Ask me each time" },
  { value: "allow", label: "Always allow" },
  { value: "deny", label: "Never allow" },
];

export function clipboardOptions(
  globalValue: Clipboard,
): Option<Clipboard | "inherit">[] {
  const named = CLIPBOARD_OPTIONS.find((o) => o.value === globalValue);
  return [
    {
      value: "inherit",
      label: `Use the global setting (${named?.label.toLowerCase() ?? globalValue})`,
    },
    ...CLIPBOARD_OPTIONS,
  ];
}

const SOURCE_WORDS: Record<Source, string> = {
  sandbox: "this workspace",
  global: "global setting",
  default: "puddle's default",
};

/** Where a value in effect comes from, in words for a chip. */
export const sourceLabel = (source: Source): string => SOURCE_WORDS[source];
