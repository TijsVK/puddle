// SPDX-License-Identifier: GPL-3.0-or-later
// What a click on a workspace does, shared by the list and the detail page: start, stop,
// reclaim, connect (the "how do you want to connect" step, with the direct-SSH switch and its
// trust text), delete (with the check of what would be lost) and the create dialog. The dialogs themselves are drawn by
// `WorkspaceDialogs.svelte`, which reads the state here.
import {
  workspaces as defaultStore,
  type Settled,
  type WorkspaceStore,
} from "./workspaces.svelte.ts";
import { toasts as defaultToasts, type ToastQueue } from "./toasts.svelte.ts";
import {
  operationLabel,
  type DeleteCheck,
  type Workspace,
} from "#lib/workspaces/model.ts";

export interface DeleteState {
  workspace: Workspace;
  check: DeleteCheck;
  /** A delete request is in flight. */
  working: boolean;
  /** Why the last delete request failed, when it did (a changed workspace shows the new list). */
  error: string | null;
}

type Toasts = Pick<ToastQueue, "push">;
type Store = Pick<
  WorkspaceStore,
  | "startWorkspace"
  | "stopWorkspace"
  | "reclaim"
  | "attach"
  | "setDirectSsh"
  | "checkDelete"
  | "remove"
  | "refresh"
  | "dismissProgress"
>;

const DONE_WORDS: Record<string, (name: string) => string> = {
  creating: (name) => `Created ${name}.`,
  starting: (name) => `${name} is running.`,
  stopping: (name) => `Stopped ${name}.`,
  reclaiming: (name) => `Reclaimed free space on ${name}.`,
  deleting: (name) => `Deleted ${name}.`,
};

/** The toast for a finished operation. */
export function settledMessage(settled: Settled): string {
  if (settled.failed) {
    const what = settled.operation
      ? `${operationLabel(settled.operation)} ${settled.name} failed`
      : `Something went wrong with ${settled.name}`;
    return settled.detail ? `${what}: ${settled.detail}` : `${what}.`;
  }
  return (DONE_WORDS[settled.operation ?? ""] ?? ((n) => `${n}: done.`))(
    settled.name,
  );
}

export class WorkspaceActions {
  createOpen = $state(false);
  /** The workspace the connect step is open for (a snapshot: read live data by its id). */
  connectFor = $state.raw<Workspace | null>(null);
  connectOpen = $state(false);
  /** The workspace whose direct-SSH trust text is being asked. */
  trustFor = $state.raw<Workspace | null>(null);
  trustOpen = $state(false);
  deleting = $state.raw<DeleteState | null>(null);
  deleteOpen = $state(false);
  /** The workspace whose delete check is being read. */
  checking = $state<string | null>(null);

  readonly #store: Store;
  readonly #toasts: Toasts;

  constructor(store: Store = defaultStore, toasts: Toasts = defaultToasts) {
    this.#store = store;
    this.#toasts = toasts;
  }

  #fail(message: string): void {
    this.#toasts.push(message, { tone: "error", ms: 8000 });
  }

  /** The toast for an operation's end; the store calls it. */
  settled = (settled: Settled): void => {
    this.#toasts.push(settledMessage(settled), {
      tone: settled.failed ? "error" : "info",
      ms: settled.failed ? 8000 : 5000,
    });
  };

  openCreate = (): void => {
    this.createOpen = true;
  };

  start = async (w: Workspace): Promise<void> => {
    const result = await this.#store.startWorkspace(w.id);
    if (!result.ok) this.#fail(result.message);
  };

  stop = async (w: Workspace): Promise<void> => {
    const result = await this.#store.stopWorkspace(w.id);
    if (!result.ok) this.#fail(result.message);
  };

  reclaim = async (w: Workspace): Promise<void> => {
    const result = await this.#store.reclaim(w.id);
    if (!result.ok) this.#fail(result.message);
  };

  /** Opens the connect step. */
  connect = (w: Workspace): void => {
    this.connectFor = w;
    this.connectOpen = true;
  };

  /** The switch in the connect step or the settings: off at once, on after the trust text. */
  requestDirectSsh = (w: Workspace, on: boolean): void => {
    if (on) {
      this.trustFor = w;
      this.trustOpen = true;
      return;
    }
    void this.#setDirectSsh(w, false);
  };

  confirmTrust = (): void => {
    const w = this.trustFor;
    this.trustFor = null;
    if (w) void this.#setDirectSsh(w, true);
  };

  async #setDirectSsh(w: Workspace, on: boolean): Promise<void> {
    const result = await this.#store.setDirectSsh(w.name, on);
    if (!result.ok) {
      this.#fail(result.message);
      return;
    }
    this.#toasts.push(
      on
        ? `Direct SSH is on for ${w.name}: it is trusted now.`
        : `Direct SSH is off for ${w.name}.`,
    );
  }

  /** Opens desktop VS Code; the connect step only offers it while direct SSH is on. */
  openDesktop = (w: Workspace): void => {
    void this.#openDesktop(w);
  };

  async #openDesktop(w: Workspace): Promise<void> {
    const result = await this.#store.attach(w.id, "desktop");
    if (!result.ok) {
      this.#fail(result.message);
      return;
    }
    const { opened, message } = result.value;
    if (opened) {
      this.#toasts.push(`Opening ${w.name} in VS Code.`);
    } else {
      this.#toasts.push(
        message ?? `puddle couldn't open VS Code for ${w.name}.`,
        {
          tone: "error",
          ms: 8000,
        },
      );
    }
  }

  /** Reads what deleting would lose, then asks. */
  askDelete = async (w: Workspace): Promise<void> => {
    if (this.checking !== null) return;
    this.checking = w.name;
    const result = await this.#store.checkDelete(w.id);
    this.checking = null;
    if (!result.ok) {
      this.#fail(result.message);
      return;
    }
    this.deleting = {
      workspace: w,
      check: result.value,
      working: false,
      error: null,
    };
    this.deleteOpen = true;
  };

  /** Deletes what the user saw listed. If it changed meanwhile, shows the new list instead. */
  confirmDelete = async (): Promise<void> => {
    const state = this.deleting;
    if (!state || state.working) return;
    this.deleting = { ...state, working: true, error: null };
    const result = await this.#store.remove(
      state.workspace.id,
      state.check.fingerprint,
    );
    if (result.ok) {
      this.deleteOpen = false;
      this.#toasts.push(`Deleting ${state.workspace.name}.`);
      return;
    }
    if (result.reason === "gone") {
      this.deleteOpen = false;
      this.#fail(result.message);
      return;
    }
    if (result.reason === "conflict") {
      const again = await this.#store.checkDelete(state.workspace.id);
      if (again.ok) {
        this.deleting = {
          ...state,
          check: again.value,
          working: false,
          error: result.message,
        };
        return;
      }
    }
    this.deleting = { ...state, working: false, error: result.message };
  };

  dismissProgress = (w: Workspace): void => {
    this.#store.dismissProgress(w.name);
  };
}

export const workspaceActions = new WorkspaceActions();
