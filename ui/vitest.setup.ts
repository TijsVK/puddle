// SPDX-License-Identifier: GPL-3.0-or-later
import "@testing-library/jest-dom/vitest";

// jsdom has no ResizeObserver (Svelte's `bind:clientHeight` needs one); nothing is ever
// resized there, so one that never reports is enough.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  };
}
