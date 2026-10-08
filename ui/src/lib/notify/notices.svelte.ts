// SPDX-License-Identifier: GPL-3.0-or-later
// App-level notices: things that happened outside what the user is looking at (a workspace ran
// out of memory, stopped on its own, the network got worse). They stay in a list until dismissed
// or until the cause is gone. A notice with a key already in the list replaces it, so a repeat
// moves the old one instead of piling up.
//
// Showing a notice never moves focus; the list is a polite live region (Notices.svelte).

export type NoticeTone = "info" | "warning";

export interface NoticeLink {
  href: string;
  label: string;
}

/** A button on a notice: one deliberate click does the thing the notice says is missing. */
export interface NoticeAction {
  label: string;
  run: () => void | Promise<void>;
}

export interface NoticeInput {
  /** What the notice is about; a second notice with this key replaces the first. */
  key: string;
  tone: NoticeTone;
  /** One sentence. May quote names from a workspace: it is only ever drawn as text. */
  title: string;
  /** More, shown under the title. */
  detail?: string;
  link?: NoticeLink;
  action?: NoticeAction;
}

export interface Notice extends NoticeInput {
  id: number;
  /** Epoch ms it was raised. */
  at: number;
}

export class NoticeCenter {
  items = $state.raw<Notice[]>([]);
  #next = 1;
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  /** Newest last. Returns the notice's id. */
  add(input: NoticeInput): number {
    const id = this.#next++;
    const notice: Notice = { ...input, id, at: this.#now() };
    this.items = [...this.items.filter((n) => n.key !== input.key), notice];
    return id;
  }

  dismiss(id: number): void {
    this.items = this.items.filter((n) => n.id !== id);
  }

  /** Removes the notice of a key when its cause has gone. */
  resolve(key: string): void {
    if (this.items.some((n) => n.key === key)) {
      this.items = this.items.filter((n) => n.key !== key);
    }
  }

  clear(): void {
    this.items = [];
  }
}

export const notices = new NoticeCenter();
