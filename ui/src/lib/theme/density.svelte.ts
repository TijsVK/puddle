// SPDX-License-Identifier: GPL-3.0-or-later
import { globalSettings } from "#lib/stores/global-settings.svelte.ts";
import {
  applyDensity,
  isDensityChoice,
  loadDensity,
  saveDensity,
  type DensityChoice,
} from "./density.ts";
import { browserStorage } from "./theme.ts";

/**
 * The reactive density choice, kept the way the theme is: the stored choice lives in puddle's
 * settings and a localStorage hint is applied before the first paint. `init()` once in the root
 * layout, then `sync()`.
 */
class DensityState {
  choice = $state<DensityChoice>("comfortable");

  init(): void {
    this.choice = loadDensity(browserStorage());
    applyDensity(document.documentElement, this.choice);
  }

  /** Applies the choice stored in the settings, once they are read. */
  async sync(): Promise<void> {
    await globalSettings.load(true);
    const view = globalSettings.view;
    if (!view) return; // not readable: the hint stays
    const stored = view.ui.density ?? "comfortable";
    if (isDensityChoice(stored)) this.#apply(stored);
  }

  /** Applies a choice at once and stores it in the settings; on failure it still applies this time. */
  async set(choice: DensityChoice): Promise<boolean> {
    this.#apply(choice);
    if (!globalSettings.view) await globalSettings.load(true);
    const result = await globalSettings.save({ ui: { density: choice } });
    return result.ok;
  }

  #apply(choice: DensityChoice): void {
    this.choice = choice;
    saveDensity(browserStorage(), choice);
    applyDensity(document.documentElement, choice);
  }
}

export const density = new DensityState();
