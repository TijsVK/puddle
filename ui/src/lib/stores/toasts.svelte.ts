// SPDX-License-Identifier: GPL-3.0-or-later
/* eslint-disable svelte/prefer-svelte-reactivity -- the maps and sets here are bookkeeping that no template reads, so they need no reactivity */
// Short messages with an optional action ("Undo"), shown by Toast.svelte. A toast leaves after
// `ms`; hovering or focusing it holds it, so the action can be reached without a race (WCAG 2.2.1).

export interface ToastAction {
  label: string;
  run: () => void | Promise<void>;
}

export interface ToastItem {
  id: number;
  message: string;
  action?: ToastAction;
  tone: "info" | "error";
}

export interface ToastOptions {
  action?: ToastAction;
  /** How long it stays; default 5 s. */
  ms?: number;
  tone?: "info" | "error";
}

export class ToastQueue {
  items = $state.raw<ToastItem[]>([]);
  #next = 1;
  readonly #timers = new Map<number, ReturnType<typeof setTimeout>>();
  readonly #durations = new Map<number, number>();

  push(message: string, options: ToastOptions = {}): number {
    const id = this.#next++;
    const item: ToastItem = {
      id,
      message,
      tone: options.tone ?? "info",
      ...(options.action ? { action: options.action } : {}),
    };
    this.items = [...this.items, item];
    this.#durations.set(id, options.ms ?? 5000);
    this.resume(id);
    return id;
  }

  /** Stops the clock of a toast (pointer or focus is on it). */
  hold(id: number): void {
    const timer = this.#timers.get(id);
    if (timer !== undefined) clearTimeout(timer);
    this.#timers.delete(id);
  }

  /** Restarts the full wait of a toast. */
  resume(id: number): void {
    this.hold(id);
    const ms = this.#durations.get(id);
    if (ms === undefined) return;
    this.#timers.set(
      id,
      setTimeout(() => this.dismiss(id), ms),
    );
  }

  dismiss(id: number): void {
    this.hold(id);
    this.#durations.delete(id);
    this.items = this.items.filter((t) => t.id !== id);
  }

  /** Runs a toast's action and removes the toast. */
  async act(id: number): Promise<void> {
    const item = this.items.find((t) => t.id === id);
    this.dismiss(id);
    await item?.action?.run();
  }
}

export const toasts = new ToastQueue();
