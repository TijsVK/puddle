// SPDX-License-Identifier: GPL-3.0-or-later
import {
  applyTheme,
  browserStorage,
  loadTheme,
  saveTheme,
  type ThemeChoice,
} from "./theme.ts";

/** The reactive theme choice. `init()` once in the root layout. */
class ThemeState {
  choice = $state<ThemeChoice>("system");

  init(): void {
    this.choice = loadTheme(browserStorage());
    applyTheme(document.documentElement, this.choice);
  }

  set(choice: ThemeChoice): void {
    this.choice = choice;
    saveTheme(browserStorage(), choice);
    applyTheme(document.documentElement, choice);
  }
}

export const theme = new ThemeState();
