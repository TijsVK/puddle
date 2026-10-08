// SPDX-License-Identifier: GPL-3.0-or-later
// Comfortable or compact spacing for the whole app. Like the theme, the stored choice lives in
// puddle's settings; localStorage only holds a hint so the first paint is already right, and
// every access is guarded because storage can be unavailable.
import type { StorageLike } from "./theme.ts";

export type DensityChoice = "comfortable" | "compact";

export const DENSITY_KEY = "puddle.density";
export const DENSITY_CHOICES: readonly DensityChoice[] = [
  "comfortable",
  "compact",
];

export function isDensityChoice(value: unknown): value is DensityChoice {
  return (
    typeof value === "string" &&
    (DENSITY_CHOICES as readonly string[]).includes(value)
  );
}

export function loadDensity(storage: StorageLike | undefined): DensityChoice {
  try {
    const stored = storage?.getItem(DENSITY_KEY);
    return isDensityChoice(stored) ? stored : "comfortable";
  } catch {
    return "comfortable";
  }
}

export function saveDensity(
  storage: StorageLike | undefined,
  choice: DensityChoice,
): void {
  try {
    storage?.setItem(DENSITY_KEY, choice);
  } catch {
    // Not persisted; the choice still applies for this page.
  }
}

/** Sets or clears `data-density` on the root element; comfortable is the unmarked default. */
export function applyDensity(root: HTMLElement, choice: DensityChoice): void {
  if (choice === "comfortable") {
    delete root.dataset["density"];
  } else {
    root.dataset["density"] = choice;
  }
}
