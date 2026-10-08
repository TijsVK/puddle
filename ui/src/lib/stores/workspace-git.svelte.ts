// SPDX-License-Identifier: GPL-3.0-or-later
// One workspace's Git settings, for its Git tab: the identities it has in order, its repository
// table with a Pull and a Push toggle per repository, and the two "only listed" switches. Every
// change is saved at once; the page refetches on `workspace_git_changed` (also when an identity it
// has changes) and on a resync.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import {
  isIdentitiesChanged,
  isWorkspaceGitChanged,
} from "#lib/identities/events.ts";
import { sentence } from "#lib/rules/model.ts";
import type { LiveSource } from "./live.svelte.ts";
import { live } from "./live.svelte.ts";
import type { Result } from "./identities.svelte.ts";

export type WorkspaceGit = components["schemas"]["WorkspaceGitView"];
export type RepoRow = components["schemas"]["GitRepoView"];
export type NewRepo = components["schemas"]["GitRepoRequest"];

type StoreApi = Pick<ApiClient, "GET" | "POST" | "PUT" | "DELETE">;
export type Status = "loading" | "ready" | "failed";

const DOWN = "puddle's service isn't answering.";

export class WorkspaceGitStore {
  git = $state.raw<WorkspaceGit | null>(null);
  status = $state<Status>("loading");
  #name = "";
  /** Calls to `load` in order, so a slow answer never overwrites a newer one. */
  #ticket = 0;
  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;

  constructor(
    api: StoreApi = defaultApi,
    source: LiveSource | undefined = live,
  ) {
    this.#api = api;
    this.#source = source;
  }

  /** Reads the workspace's Git settings. `quiet` keeps the page as it is while it does. */
  async load(name: string, quiet = false): Promise<void> {
    this.#name = name;
    if (!quiet) this.status = "loading";
    const ticket = ++this.#ticket;
    try {
      const { data } = await this.#api.GET("/api/workspaces/{id}/git", {
        params: { path: { id: name } },
      });
      if (ticket !== this.#ticket) return;
      if (data) {
        this.git = data;
        this.status = "ready";
      } else if (!quiet) {
        this.status = "failed";
      }
    } catch {
      if (ticket === this.#ticket && !quiet) this.status = "failed";
    }
  }

  /** Reads `name` now and keeps it current; returns the function that stops listening. */
  start(name: string): () => void {
    void this.load(name);
    const unsubscribe = this.#source?.subscribe({
      event: (event) => {
        if (isWorkspaceGitChanged(event, name) || isIdentitiesChanged(event)) {
          void this.load(name, true);
        }
      },
      resync: () => void this.load(name, true),
    });
    return () => unsubscribe?.();
  }

  async #send<T>(
    run: () => Promise<{ data?: T; error?: { message?: string } }>,
    fallback: string,
    apply: (data: T) => void | Promise<void>,
  ): Promise<Result> {
    try {
      const { data, error } = await run();
      if (data === undefined) {
        return { ok: false, message: sentence(error?.message ?? fallback) };
      }
      await apply(data);
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  #path() {
    return { params: { path: { id: this.#name } } };
  }

  /** Puts the identities of the workspace in this order (every one once). */
  setIdentities(ids: number[]): Promise<Result> {
    return this.#send(
      () =>
        this.#api.PUT("/api/workspaces/{id}/identities", {
          ...this.#path(),
          body: { ids },
        }),
      "puddle refused the change",
      (git) => {
        this.git = git;
      },
    );
  }

  /** Adds an identity, last in the order. */
  attach(identity: number): Promise<Result> {
    return this.#send(
      () =>
        this.#api.POST("/api/workspaces/{id}/identities", {
          ...this.#path(),
          body: { identity },
        }),
      "puddle refused the identity",
      (git) => {
        this.git = git;
      },
    );
  }

  /** Takes an identity off the workspace. */
  async detach(identity: number): Promise<Result> {
    try {
      const { data, error } = await this.#api.DELETE(
        "/api/workspaces/{id}/identities/{identity}",
        { params: { path: { id: this.#name, identity } } },
      );
      if (!data) {
        return {
          ok: false,
          message: sentence(
            error?.message ?? "puddle couldn't remove the identity",
          ),
        };
      }
      this.git = data;
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Sets "only push to listed repos" and/or "only pull from listed repos". */
  setSwitches(switches: {
    only_push_listed?: boolean;
    only_pull_listed?: boolean;
  }): Promise<Result> {
    return this.#send(
      () =>
        this.#api.PUT("/api/workspaces/{id}/git/switches", {
          ...this.#path(),
          body: switches,
        }),
      "puddle refused the switch",
      (git) => {
        this.git = git;
      },
    );
  }

  /** Lists a repository. */
  addRepo(repo: NewRepo): Promise<Result> {
    return this.#send(
      () =>
        this.#api.POST("/api/workspaces/{id}/git/repos", {
          ...this.#path(),
          body: repo,
        }),
      "puddle refused the repository",
      () => this.load(this.#name, true),
    );
  }

  /** Sets a row's Pull and Push toggles. */
  setToggles(row: RepoRow, pull: boolean, push: boolean): Promise<Result> {
    return this.#send(
      () =>
        this.#api.PUT("/api/workspaces/{id}/git/repos/{repo}", {
          params: { path: { id: this.#name, repo: row.id } },
          body: { pull, push },
        }),
      "puddle refused the change",
      (updated) => {
        if (this.git) {
          this.git = {
            ...this.git,
            repos: this.git.repos.map((r) => (r.id === row.id ? updated : r)),
          };
        }
      },
    );
  }

  /** Removes a row. A row that is already gone counts as removed. */
  async removeRepo(row: RepoRow): Promise<Result> {
    try {
      const { response } = await this.#api.DELETE(
        "/api/workspaces/{id}/git/repos/{repo}",
        { params: { path: { id: this.#name, repo: row.id } } },
      );
      if (!response.ok && response.status !== 404) {
        return { ok: false, message: "puddle couldn't remove the repository." };
      }
      if (this.git) {
        this.git = {
          ...this.git,
          repos: this.git.repos.filter((r) => r.id !== row.id),
        };
      }
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }
}
