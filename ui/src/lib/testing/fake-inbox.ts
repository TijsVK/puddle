// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's inbox endpoints, for unit and component tests: it answers the calls
// the inbox store makes in the shape openapi-fetch returns them. Not shipped (tests import it).
import type { components } from "#lib/api/schema.d.ts";
import type { LiveListener, LiveSource } from "#lib/stores/live.svelte.ts";

type Req = components["schemas"]["PendingRequest"];

export function request(id: number, over: Partial<Req> = {}): Req {
  return {
    id,
    workspace: "demo" as Req["workspace"],
    host: `h${id}.example.com`,
    port: 443,
    first_seen: 1_000_000 + id,
    last_seen: 1_000_000 + id,
    attempts: 1,
    state: "requested",
    decided_at: null,
    decided_by: null,
    rule_id: null,
    rule_set: null,
    blocked_by: null,
    ...over,
  };
}

export class FakeInbox {
  open: { request: Req; domain: string }[] = [];
  suppression: Record<string, { active: boolean; count: number }> = {};
  toggles: Record<string, Partial<Record<string, boolean>>> = {};
  calls: string[] = [];
  /** Set to make every call fail the way a stopped service does. */
  down = false;
  /** Status for the next decision (`approve`/`deny`), then back to success. */
  nextDecisionStatus: number | null = null;
  rules: components["schemas"]["Rule"][] = [];
  #rule = 100;

  add(req: Req, domain?: string): void {
    this.open.push({
      request: req,
      domain: domain ?? req.host.split(".").slice(-2).join("."),
    });
  }

  private reply(status: number, data?: unknown) {
    const response = { status, ok: status < 400 } as Response;
    return status < 400
      ? { data, response }
      : {
          error: {
            error: status === 409 ? "conflict" : "internal",
            message: "refused",
          },
          response,
        };
  }

  GET = async (
    path: string,
    init?: { params?: { path?: Record<string, unknown> } },
  ) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    if (path === "/api/inbox") {
      const groups = new Map<string, Req[]>();
      for (const { request: r, domain } of this.open)
        groups.set(domain, [...(groups.get(domain) ?? []), r]);
      return this.reply(200, {
        groups: [...groups].map(([registrable_domain, requests]) => ({
          registrable_domain,
          requests,
        })),
      });
    }
    if (path === "/api/workspaces/{workspace}/suppression") {
      const workspace = String(init?.params?.path?.["workspace"]);
      const s = this.suppression[workspace] ?? { active: false, count: 0 };
      return this.reply(200, { workspace, ...s });
    }
    if (path === "/api/settings/workspaces/{workspace}") {
      const workspace = String(init?.params?.path?.["workspace"]);
      const t = this.toggles[workspace];
      if (t === undefined) return this.reply(500);
      const v = (name: string) => ({
        value: t[name] ?? false,
        source: "default",
      });
      return this.reply(200, {
        workspace,
        effective: {
          local_toggles: {
            loopback: v("loopback"),
            private: v("private"),
            link_local: v("link_local"),
            metadata: v("metadata"),
            special: v("special"),
          },
        },
      });
    }
    throw new Error(`unexpected GET ${path}`);
  };

  POST = async (
    path: string,
    init: {
      params: { path: { id: number } };
      body: components["schemas"]["DecisionRequest"];
    },
  ) => {
    this.calls.push(`POST ${path}`);
    if (this.down) throw new TypeError("down");
    const status = this.nextDecisionStatus;
    this.nextDecisionStatus = null;
    if (status !== null) return this.reply(status);
    const id = init.params.path.id;
    const found = this.open.find((o) => o.request.id === id);
    if (!found) return this.reply(404);
    const effect = path.endsWith("approve") ? "allow" : "deny";
    const global = init.body.scope === "global";
    const suffix = init.body.suffix ?? null;
    const covers = (o: { request: Req; domain: string }) =>
      (global || o.request.workspace === found.request.workspace) &&
      (suffix === null
        ? o.request.host === found.request.host
        : o.request.host.endsWith(suffix));
    const closed = this.open
      .filter((o) => covers(o) && o.request.id !== id)
      .map((o) => o.request.id);
    this.open = this.open.filter((o) => !covers(o));
    const rule: components["schemas"]["Rule"] = {
      id: this.#rule++,
      scope:
        init.body.rule_set !== undefined && init.body.rule_set !== null
          ? { type: "set", set: init.body.rule_set }
          : global
            ? { type: "global" }
            : { type: "workspace", workspace: found.request.workspace },
      pattern: suffix ?? found.request.host,
      pattern_kind: suffix === null ? "exact" : "suffix",
      effect,
      expires_at: init.body.expires_in_secs ? 5_000_000 : null,
      created_at: 1,
      created_by: "api",
      source_pending_id: id,
    };
    this.rules.push(rule);
    return this.reply(200, {
      request: {
        ...found.request,
        state: effect === "allow" ? "allowed" : "denied",
      },
      rule,
      also_closed: closed,
    });
  };

  DELETE = async (path: string, init: { params: { path: { id: number } } }) => {
    this.calls.push(`DELETE ${path}`);
    if (this.down) throw new TypeError("down");
    const id = init.params.path.id;
    const known = this.rules.some((r) => r.id === id);
    this.rules = this.rules.filter((r) => r.id !== id);
    return known ? this.reply(200, {}) : this.reply(404);
  };
}

/** A LiveSource the test drives by hand. */
export class FakeSource implements LiveSource {
  listeners = new Set<LiveListener>();
  subscribe(listener: LiveListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  emit(event: unknown): void {
    for (const l of this.listeners) l.event?.(event);
  }
  resync(): void {
    for (const l of this.listeners) l.resync?.();
  }
}
