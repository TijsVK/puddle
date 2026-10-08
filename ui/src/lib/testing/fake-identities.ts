// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the identities, workspace Git and credentials endpoints, for unit and component
// tests, in the shape openapi-fetch returns them. It keeps real state (so a change shows up in the
// next read) and refuses a collision the way the host does. Not shipped (tests import it).
import type {
  Credential,
  FoundAccounts,
  Identity,
  Source,
} from "#lib/identities/model.ts";
import { describeSource } from "#lib/identities/model.ts";
import type {
  RepoRow,
  WorkspaceGit,
} from "#lib/stores/workspace-git.svelte.ts";

export function ghSource(account = "me", host = "github.com"): Source {
  return { kind: "gh", host, account };
}

export function credential(
  over: Partial<Credential> & { owners?: string[]; rest?: boolean } = {},
): Credential {
  const { owners, rest, ...fields } = over;
  return {
    host: "github.com",
    source: ghSource(),
    covers: { owners: owners ?? [], rest_of_host: rest ?? true },
    ...fields,
  };
}

export function identity(id: number, over: Partial<Identity> = {}): Identity {
  return {
    id,
    label: `Identity ${id}`,
    author: { name: `Name ${id}`, email: `id${id}@example.com` },
    credentials: [credential()],
    signing: "none",
    is_default: id === 1,
    workspaces: [],
    created_at: 1_000,
    changed_at: 1_000,
    ...over,
  };
}

export function repoRow(id: number, over: Partial<RepoRow> = {}): RepoRow {
  return {
    id,
    host: "github.com",
    owner: "acme",
    repo: `repo-${id}`,
    pull: true,
    push: true,
    created_at: 1_000,
    ...over,
  };
}

interface Git {
  ids: number[];
  repos: RepoRow[];
  push: boolean;
  pull: boolean;
}

type Body = Record<string, unknown>;
interface Init {
  params?: { path: Record<string, string | number> };
  body?: Body;
}

export class FakeIdentities {
  identities: Identity[] = [];
  git: Record<string, Git> = {};
  found: FoundAccounts = { accounts: [], problems: [] };
  /** Lines (`describeSource`) of the credentials that cannot be read. */
  unreadable = new Set<string>();
  signIn: { code: string | null; url: string | null } = {
    code: "ABCD-1234",
    url: "https://github.com/login/device",
  };
  /** What a sign-in does to `unreadable`: it makes the credential readable, as a finished one does. */
  signInFixes = true;
  tokens: string[] = [];
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Refuse the next write with this status and message. */
  refuse: { status: number; message: string; error?: string } | null = null;
  #id = 100;
  #row = 500;

  private reply(status: number, data?: unknown, error?: string) {
    const response = { status, ok: status < 400 } as Response;
    if (status < 400) return { data, response };
    const refusal = this.refuse;
    this.refuse = null;
    return {
      error: {
        error:
          refusal?.error ?? error ?? (status === 422 ? "invalid" : "internal"),
        message: refusal?.message ?? "refused",
      },
      response,
    };
  }

  #ws(name: string | number | undefined): Git {
    const key = String(name);
    return (this.git[key] ??= { ids: [], repos: [], push: true, pull: false });
  }

  #view(name: string): WorkspaceGit {
    const g = this.#ws(name);
    return {
      workspace: name,
      identities: g.ids
        .map((id) => this.identities.find((i) => i.id === id))
        .filter((i): i is Identity => i !== undefined),
      repos: g.repos,
      only_push_listed: g.push,
      only_pull_listed: g.pull,
    };
  }

  /** The host's refusal when two identities of one list cover the same place, or `null`. */
  #collision(ids: number[]): string | null {
    const list = ids
      .map((id) => this.identities.find((i) => i.id === id))
      .filter((i): i is Identity => i !== undefined);
    for (const [at, a] of list.entries()) {
      for (const b of list.slice(at + 1)) {
        for (const x of a.credentials) {
          for (const y of b.credentials) {
            if (x.host !== y.host) continue;
            const owner = x.covers.owners.find((o) =>
              y.covers.owners.includes(o),
            );
            if (owner) {
              return `${a.label} and ${b.label} both cover ${x.host}/${owner}; narrow one`;
            }
            if (x.covers.rest_of_host && y.covers.rest_of_host) {
              return `${a.label} and ${b.label} both cover the rest of ${x.host}; narrow one`;
            }
          }
        }
      }
    }
    return null;
  }

  #sync(): void {
    this.identities = this.identities.map((i) => ({
      ...i,
      workspaces: Object.entries(this.git)
        .filter(([, g]) => g.ids.includes(i.id))
        .map(([name]) => name),
    }));
  }

  GET = async (path: string, init: Init = {}) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    this.#sync();
    if (path === "/api/identities")
      return this.reply(200, { identities: this.identities });
    if (path === "/api/credentials/found") return this.reply(200, this.found);
    if (path === "/api/workspaces/{id}/git") {
      return this.reply(200, this.#view(String(init.params?.path["id"])));
    }
    return this.reply(404);
  };

  POST = async (path: string, init: Init = {}) => {
    this.calls.push(`POST ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const body = init.body ?? {};
    switch (path) {
      case "/api/identities": {
        const made = identity(this.#id++, {
          label: String(body["label"]),
          author: body["author"] as Identity["author"],
          credentials: body["credentials"] as Credential[],
          is_default: this.identities.length === 0,
        });
        if (
          this.identities.some(
            (i) => i.label.toLowerCase() === made.label.toLowerCase(),
          )
        ) {
          return this.reply(409, undefined, "conflict");
        }
        this.identities = [...this.identities, made];
        return this.reply(201, made);
      }
      case "/api/credentials/check": {
        const line = describeSource(body["source"] as Source);
        return this.reply(
          200,
          this.unreadable.has(line)
            ? {
                readable: false,
                problem: "not signed in, or the sign-in has expired",
                needs_sign_in: true,
              }
            : { readable: true, problem: null, needs_sign_in: false },
        );
      }
      case "/api/credentials/stored": {
        const id = `tok-fake-${this.#id++}`;
        this.tokens.push(id);
        return this.reply(201, {
          source: {
            kind: "stored",
            id,
            host: body["host"],
            org: body["org"] ?? null,
          },
        });
      }
      case "/api/credentials/sign-in": {
        const source = body["source"] as Source;
        if (source.kind === "stored") return this.reply(422);
        if (this.signInFixes) this.unreadable.delete(describeSource(source));
        return this.reply(200, this.signIn);
      }
      case "/api/workspaces/{id}/identities": {
        const g = this.#ws(init.params?.path["id"]);
        const next = [...g.ids, Number(body["identity"])];
        const clash = this.#collision(next);
        if (clash) return this.#clash(clash);
        g.ids = next;
        this.#sync();
        return this.reply(200, this.#view(String(init.params?.path["id"])));
      }
      case "/api/workspaces/{id}/git/repos": {
        const g = this.#ws(init.params?.path["id"]);
        const dup = g.repos.some(
          (r) =>
            r.host === body["host"] &&
            r.owner === body["owner"] &&
            r.repo === body["repo"],
        );
        if (dup)
          return this.#clash(
            "that repository is already listed",
            "conflict",
            409,
          );
        const row = repoRow(this.#row++, body as Partial<RepoRow>);
        g.repos = [...g.repos, row];
        return this.reply(201, row);
      }
    }
    return this.reply(404);
  };

  #clash(message: string, error = "identity_collision", status = 409) {
    return {
      error: { error, message },
      response: { status, ok: false } as Response,
    };
  }

  PUT = async (path: string, init: Init = {}) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const body = init.body ?? {};
    const id = Number(init.params?.path["id"]);
    switch (path) {
      case "/api/identities/order": {
        const ids = body["ids"] as number[];
        this.identities = ids.map((i) =>
          this.identities.find((x) => x.id === i)!,
        );
        return this.reply(200, { identities: this.identities });
      }
      case "/api/identities/{id}": {
        const found = this.identities.find((i) => i.id === id);
        if (!found) return this.reply(404);
        const next = {
          ...found,
          label: String(body["label"]),
          author: body["author"] as Identity["author"],
          credentials: body["credentials"] as Credential[],
        };
        this.identities = this.identities.map((i) => (i.id === id ? next : i));
        return this.reply(200, next);
      }
      case "/api/identities/{id}/default": {
        if (!this.identities.some((i) => i.id === id)) return this.reply(404);
        this.identities = this.identities.map((i) => ({
          ...i,
          is_default: i.id === id,
        }));
        return this.reply(
          200,
          this.identities.find((i) => i.id === id),
        );
      }
      case "/api/workspaces/{id}/identities": {
        const ids = body["ids"] as number[];
        const clash = this.#collision(ids);
        if (clash) return this.#clash(clash);
        this.#ws(init.params?.path["id"]).ids = ids;
        this.#sync();
        return this.reply(200, this.#view(String(init.params?.path["id"])));
      }
      case "/api/workspaces/{id}/git/switches": {
        const g = this.#ws(init.params?.path["id"]);
        if (typeof body["only_push_listed"] === "boolean")
          g.push = body["only_push_listed"];
        if (typeof body["only_pull_listed"] === "boolean")
          g.pull = body["only_pull_listed"];
        return this.reply(200, this.#view(String(init.params?.path["id"])));
      }
      case "/api/workspaces/{id}/git/repos/{repo}": {
        const g = this.#ws(init.params?.path["id"]);
        const row = g.repos.find(
          (r) => r.id === Number(init.params?.path["repo"]),
        );
        if (!row) return this.reply(404);
        const next = {
          ...row,
          pull: Boolean(body["pull"]),
          push: Boolean(body["push"]),
        };
        g.repos = g.repos.map((r) => (r.id === row.id ? next : r));
        return this.reply(200, next);
      }
    }
    return this.reply(404);
  };

  DELETE = async (path: string, init: Init = {}) => {
    this.calls.push(`DELETE ${path}`);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const id = Number(init.params?.path["id"]);
    switch (path) {
      case "/api/identities/{id}": {
        const found = this.identities.find((i) => i.id === id);
        if (!found) return this.reply(404);
        this.identities = this.identities.filter((i) => i.id !== id);
        const detached = Object.entries(this.git)
          .filter(([, g]) => g.ids.includes(id))
          .map(([name]) => name);
        for (const g of Object.values(this.git))
          g.ids = g.ids.filter((i) => i !== id);
        return this.reply(200, { detached_from: detached });
      }
      case "/api/credentials/stored/{id}": {
        this.tokens = this.tokens.filter((t) => t !== init.params?.path["id"]);
        return this.reply(204);
      }
      case "/api/workspaces/{id}/identities/{identity}": {
        const g = this.#ws(init.params?.path["id"]);
        const identity = Number(init.params?.path["identity"]);
        if (!g.ids.includes(identity)) return this.reply(404);
        g.ids = g.ids.filter((i) => i !== identity);
        return this.reply(200, this.#view(String(init.params?.path["id"])));
      }
      case "/api/workspaces/{id}/git/repos/{repo}": {
        const g = this.#ws(init.params?.path["id"]);
        const row = Number(init.params?.path["repo"]);
        if (!g.repos.some((r) => r.id === row)) return this.reply(404);
        g.repos = g.repos.filter((r) => r.id !== row);
        return this.reply(204);
      }
    }
    return this.reply(404);
  };
}
