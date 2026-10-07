// SPDX-License-Identifier: GPL-3.0-or-later
// Where a notice goes. The in-app implementation puts it in the notice list; operating-system
// notifications are raised by the desktop shell from the same events, not from here.
import {
  notices as defaultCenter,
  type NoticeCenter,
  type NoticeInput,
} from "./notices.svelte.ts";

export interface Notifier {
  notify(notice: NoticeInput): void;
  /** The cause of the notice with this key is gone. */
  resolve(key: string): void;
}

export class InAppNotifier implements Notifier {
  readonly #center: Pick<NoticeCenter, "add" | "resolve">;

  constructor(center: Pick<NoticeCenter, "add" | "resolve"> = defaultCenter) {
    this.#center = center;
  }

  notify(notice: NoticeInput): void {
    this.#center.add(notice);
  }

  resolve(key: string): void {
    this.#center.resolve(key);
  }
}
