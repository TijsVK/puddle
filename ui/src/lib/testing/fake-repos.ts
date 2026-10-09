// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for `GET /api/repos` and `POST /api/repos/refresh`, for unit and component tests, in
// the shape openapi-fetch returns. It filters by identity and by words and pages like the host
// does, can be held (a slow list) and records what was asked. Not shipped (tests import it).
import type { RepoListing, RepoSource, RepoView } from "#lib/repos/model.ts";

export function repoView(
  owner: string,
  name: string,
  over: Partial<RepoView> = {},
): RepoView {
  return {
    archived: false,
    fork: false,
    full_name: `${owner}/${name}`,
    host: "github.com",
    identities: [1],
    name,
    owner,
    project: null,
    role: "write",
    url: `https://github.com/${owner}/${name}`,
    visibility: "private",
    ...over,
  };
}

export function repoSource(over: Partial<RepoSource> = {}): RepoSource {
  return {
    credential: 0,
    host: "github.com",
    identity_id: 1,
    notes: [],
    organisation: null,
    problem: null,
    refreshed_at: 1_000_000,
    repo_count: 0,
    retry_at: null,
    state: "ok",
    ...over,
  };
}

interface Query {
  identity?: number;
  query?: string;
  limit?: number;
  offset?: number;
}

export class FakeRepos {
  repos: RepoView[] = [];
  sources: RepoSource[] = [];
  /** Asked, in order, as `GET {query}` and `POST refresh`. */
  calls: string[] = [];
  queries: Query[] = [];
  refreshBodies: unknown[] = [];
  down = false;
  /** The error the next call answers with (status and message), once. */
  refuse: { status: number; message: string } | null = null;
  #hold: Promise<void> | null = null;
  #release: (() => void) | null = null;

  /** Keeps answers waiting until `release`. */
  hold(): void {
    this.#hold = new Promise((resolve) => {
      this.#release = resolve;
    });
  }

  release(): void {
    this.#release?.();
    this.#hold = null;
  }

  #refused() {
    const refusal = this.refuse;
    this.refuse = null;
    return {
      error: { error: "unavailable", message: refusal?.message ?? "refused" },
      response: { status: refusal?.status ?? 503, ok: false } as Response,
    };
  }

  GET = async (_path: string, init: { params?: { query?: Query } } = {}) => {
    const query = init.params?.query ?? {};
    this.calls.push(`GET ${JSON.stringify(query)}`);
    this.queries.push(query);
    if (this.#hold) await this.#hold;
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.#refused();
    const words = (query.query ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    const matching = this.repos.filter(
      (r) =>
        (query.identity === undefined ||
          r.identities.includes(query.identity)) &&
        words.every((w) => r.full_name.toLowerCase().includes(w)),
    );
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    const data: RepoListing = {
      limit,
      offset,
      repos: matching.slice(offset, offset + limit),
      sources: this.sources.filter(
        (s) => query.identity === undefined || s.identity_id === query.identity,
      ),
      total: matching.length,
    };
    return { data, response: { status: 200, ok: true } as Response };
  };

  POST = async (_path: string, init: { body?: unknown } = {}) => {
    this.calls.push("POST refresh");
    this.refreshBodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.#refused();
    return {
      data: { sources: this.sources },
      response: { status: 200, ok: true } as Response,
    };
  };
}
