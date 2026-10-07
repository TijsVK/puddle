// SPDX-License-Identifier: GPL-3.0-or-later
import { globalSettings } from "#lib/stores/global-settings.svelte.ts";
import {
  applyTheme,
  browserStorage,
  isThemeChoice,
  loadTheme,
  saveTheme,
  type ThemeChoice,
} from "./theme.ts";

/**
 * The reactive theme choice. The stored choice lives in puddle's settings (the API's address
 * changes on every launch, so the page can't keep it); localStorage only holds a hint that is
 * applied before the first paint. `init()` once in the root layout, then `sync()`.
 */
class ThemeState {
  choice = $state<ThemeChoice>("system");

  init(): void {
    this.choice = loadTheme(browserStorage());
    applyTheme(document.documentElement, this.choice);
  }

  /** Applies the choice stored in the settings, once they are read. */
  async sync(): Promise<void> {
    await globalSettings.load(true);
    const view = globalSettings.view;
    if (!view) return; // not readable: the hint stays
    const stored = view.ui.theme ?? "system";
    if (isThemeChoice(stored)) this.#apply(stored);
  }

  /** Applies a choice at once and stores it in the settings; on failure it still applies this time. */
  async set(choice: ThemeChoice): Promise<boolean> {
    this.#apply(choice);
    if (!globalSettings.view) await globalSettings.load(true);
    const result = await globalSettings.save({ ui: { theme: choice } });
    return result.ok;
  }

  #apply(choice: ThemeChoice): void {
    this.choice = choice;
    saveTheme(browserStorage(), choice);
    applyTheme(document.documentElement, choice);
  }
}

export const theme = new ThemeState();
