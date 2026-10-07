// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's rules endpoints, for unit and component tests, in the shape
// openapi-fetch returns them. Not shipped (tests import it).
import type { components } from "#lib/api/schema.d.ts";

export type Rule = components["schemas"]["Rule"];

export function rule(id: number, over: Partial<Rule> = {}): Rule {
  return {
    id,
    scope: { type: "global" },
    pattern: `h${id}.example.com`,
    pattern_kind: "exact",
    effect: "allow",
    expires_at: null,
    created_at: 1_000_000 + id,
    created_by: "ui",
    source_pending_id: null,
    ...over,
  };
}

export class FakeRules {
  rules: Rule[] = [];
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Refuse the next write with this status and message. */
  refuse: { status: number; message: string } | null = null;
  #id = 500;

  private reply(status: number, data?: unknown) {
    const response = { status, ok: status < 400 } as Response;
    if (status < 400) return { data, response };
    const refusal = this.refuse;
    this.refuse = null;
    return {
      error: {
        error: status === 422 ? "invalid" : "internal",
        message: refusal?.message ?? "refused",
      },
      response,
    };
  }

  GET = async (path: string) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    return this.reply(200, { rules: this.rules });
  };

  POST = async (path: string, init: { body: Record<string, unknown> }) => {
    this.calls.push(`POST ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const pattern = String(init.body["pattern"]).replace(/^\*/, "");
    const created = rule(this.#id++, {
      pattern,
      pattern_kind: pattern.startsWith(".") ? "suffix" : "exact",
      effect: init.body["effect"] as Rule["effect"],
      scope: init.body["scope"] as Rule["scope"],
      expires_at: (init.body["expires_at"] as number | null) ?? null,
    });
    this.rules.push(created);
    return this.reply(201, created);
  };

  PUT = async (
    path: string,
    init: { params: { path: { id: number } }; body: Record<string, unknown> },
  ) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const found = this.rules.find((r) => r.id === init.params.path.id);
    if (!found) return this.reply(404);
    found.expires_at = init.body["expires_at"] as number | null;
    return this.reply(200, { ...found });
  };

  DELETE = async (path: string, init: { params: { path: { id: number } } }) => {
    this.calls.push(`DELETE ${path}`);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const id = init.params.path.id;
    const known = this.rules.some((r) => r.id === id);
    this.rules = this.rules.filter((r) => r.id !== id);
    return known ? this.reply(200, {}) : this.reply(404);
  };
}
