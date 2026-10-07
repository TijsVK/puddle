// SPDX-License-Identifier: GPL-3.0-or-later
// Light/dark: follow the OS by default, with a stored override. The choice is a per-viewer
// convenience kept in localStorage; every access is guarded because storage can be unavailable.

export type ThemeChoice = "system" | "light" | "dark";

export const THEME_KEY = "puddle.theme";
export const THEME_CHOICES: readonly ThemeChoice[] = [
  "system",
  "light",
  "dark",
];

export function isThemeChoice(value: unknown): value is ThemeChoice {
  return (
    typeof value === "string" &&
    (THEME_CHOICES as readonly string[]).includes(value)
  );
}

type StorageLike = Pick<Storage, "getItem" | "setItem">;

export function loadTheme(storage: StorageLike | undefined): ThemeChoice {
  try {
    const stored = storage?.getItem(THEME_KEY);
    return isThemeChoice(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

export function saveTheme(
  storage: StorageLike | undefined,
  choice: ThemeChoice,
): void {
  try {
    storage?.setItem(THEME_KEY, choice);
  } catch {
    // Not persisted; the choice still applies for this page.
  }
}

/** Sets or clears `data-theme` on the root element; "system" leaves it to `prefers-color-scheme`. */
export function applyTheme(root: HTMLElement, choice: ThemeChoice): void {
  if (choice === "system") {
    delete root.dataset["theme"];
  } else {
    root.dataset["theme"] = choice;
  }
}

/** The browser's storage, or undefined where touching it throws. */
export function browserStorage(): StorageLike | undefined {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
}
