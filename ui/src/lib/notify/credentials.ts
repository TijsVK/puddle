// SPDX-License-Identifier: GPL-3.0-or-later
// Two stream events become notices: a credential a workspace asked for that puddle can't read
// ("sign in"), and a push or fetch the workspace's repository table refused ("allow it").
// Neither opens a window or changes a list by itself: the sign-in is a link to the page with its
// button, and the table changes only when the user clicks the notice's action.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import {
  asCredentialEvent,
  type CredentialSignInNeeded,
  type GitAccessDenied,
} from "#lib/identities/events.ts";
import { repoName } from "#lib/identities/repo.ts";
import { sentence } from "#lib/rules/model.ts";
import type { Notifier } from "./notifier.ts";

/** What the sign-in notice needs to know of the identities. */
export interface IdentityLookup {
  bySource(description: string): { id: number } | undefined;
  /** Remembers that a workspace could not read this source, so the identity screens say "Sign in needed". */
  markSignedOut(description: string): void;
  onReadable(listener: (description: string) => void): () => void;
}

export interface CredentialNoticeDeps {
  notifier: Notifier;
  identities: IdentityLookup;
  api?: Pick<ApiClient, "GET" | "POST" | "PUT">;
}

const signInKey = (source: string) => `sign-in:${source}`;
const deniedKey = (e: GitAccessDenied) =>
  `git-denied:${e.workspace}:${e.access}:${e.host}/${e.owner}/${e.repo}`;

export class CredentialNotices {
  readonly #notifier: Notifier;
  readonly #identities: IdentityLookup;
  readonly #api: Pick<ApiClient, "GET" | "POST" | "PUT">;

  constructor(deps: CredentialNoticeDeps) {
    this.#notifier = deps.notifier;
    this.#identities = deps.identities;
    this.#api = deps.api ?? defaultApi;
  }

  /** Raises the notice an event calls for; false when the event is not one of these. */
  handle(raw: unknown): boolean {
    const event = asCredentialEvent(raw);
    if (!event) return false;
    if (event.type === "credential_sign_in_needed") this.#signIn(event);
    else this.#denied(event);
    return true;
  }

  /** Listens for credentials that read again, and withdraws their notices. */
  start(): () => void {
    return this.#identities.onReadable((source) =>
      this.#notifier.resolve(signInKey(source)),
    );
  }

  #signIn(event: CredentialSignInNeeded): void {
    this.#identities.markSignedOut(event.source);
    const identity = this.#identities.bySource(event.source);
    this.#notifier.notify({
      key: signInKey(event.source),
      tone: "warning",
      title: `Sign-in needed: puddle can't read ${event.source}.`,
      detail: `A workspace asked ${event.host} for it, so that request failed. Sign in from Identities; puddle never opens a sign-in window by itself.`,
      link: {
        href: identity ? `/identities/${identity.id}` : "/identities",
        label: "Sign in",
      },
    });
  }

  #denied(event: GitAccessDenied, failure?: string): void {
    const name = repoName(event);
    const refused = event.access === "push" ? "a push to" : "a fetch from";
    this.#notifier.notify({
      key: deniedKey(event),
      tone: "warning",
      title: `${event.workspace}: ${refused} ${name} was refused.`,
      detail: `${failure ? `${failure} ` : ""}It is not on the workspace's ${event.access} list. Allow ${event.access} for it, or turn the list off on the workspace's Git tab.`,
      action: {
        label: `Allow ${event.access} for ${event.repo}`,
        run: () => this.#allow(event),
      },
      link: {
        href: `/workspaces/${encodeURIComponent(event.workspace)}/git`,
        label: "Git tab",
      },
    });
  }

  /** Lists the repository with the refused access on (and a row that exists keeps its other toggle). */
  async #allow(event: GitAccessDenied): Promise<void> {
    const name = repoName(event);
    try {
      const path = { params: { path: { id: event.workspace } } };
      const { data: git } = await this.#api.GET(
        "/api/workspaces/{id}/git",
        path,
      );
      if (!git) throw new Error("no answer");
      const row = git.repos.find(
        (r) =>
          r.host === event.host &&
          r.owner === event.owner &&
          r.repo === event.repo,
      );
      const pull = event.access === "pull";
      const result = row
        ? await this.#api.PUT("/api/workspaces/{id}/git/repos/{repo}", {
            params: { path: { id: event.workspace, repo: row.id } },
            body: { pull: pull || row.pull, push: !pull || row.push },
          })
        : await this.#api.POST("/api/workspaces/{id}/git/repos", {
            ...path,
            body: {
              host: event.host,
              owner: event.owner,
              repo: event.repo,
              pull,
              push: !pull,
            },
          });
      if (!result.data) {
        this.#denied(
          event,
          sentence(result.error?.message ?? `puddle couldn't list ${name}`),
        );
        return;
      }
      // The notice says what changed, where the user is looking, whatever page that is.
      this.#notifier.notify({
        key: deniedKey(event),
        tone: "info",
        title: `${event.workspace} may now ${event.access} ${name}.`,
        link: {
          href: `/workspaces/${encodeURIComponent(event.workspace)}/git`,
          label: "Git tab",
        },
      });
    } catch {
      this.#denied(
        event,
        `puddle couldn't list ${name}: its service isn't answering.`,
      );
    }
  }
}
