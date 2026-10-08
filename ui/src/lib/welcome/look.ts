// SPDX-License-Identifier: GPL-3.0-or-later
// The options of the "Look" step, with the words that go with them.
import type { DensityChoice } from "#lib/theme/density.ts";
import type { ThemeChoice } from "#lib/theme/theme.ts";

export interface Option<T extends string> {
  value: T;
  label: string;
  hint: string;
}

export const THEME_OPTIONS: readonly Option<ThemeChoice>[] = [
  {
    value: "system",
    label: "Follow my system",
    hint: "Light or dark as your computer is set.",
  },
  { value: "light", label: "Light", hint: "Always light." },
  { value: "dark", label: "Dark", hint: "Always dark." },
];

export const DENSITY_OPTIONS: readonly Option<DensityChoice>[] = [
  {
    value: "comfortable",
    label: "Comfortable",
    hint: "More room around things.",
  },
  {
    value: "compact",
    label: "Compact",
    hint: "Tighter spacing, so more fits on screen. Buttons stay easy to hit.",
  },
];
