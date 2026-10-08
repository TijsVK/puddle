// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's rule set endpoints, for unit and component tests, in the shape
// openapi-fetch returns them. Not shipped (tests import it).
import type { RuleSet, SystemHost } from "#lib/rules/sets.ts";

export function builtIn(slug: string, over: Partial<RuleSet> = {}): RuleSet {
  return {
    id: `builtin:${slug}`,
    kind: "built_in",
    name: slug,
    description: `The ${slug} hosts.`,
    default_on: false,
    global: null,
    overrides: [],
    entries: [
      {
        pattern: `${slug}.example`,
        pattern_kind: "exact",
        effect: "allow",
        note: "main host",
        rule_id: null,
        expires_at: null,
      },
    ],
    changed_at: null,
    created_at: null,
    ...over,
  };
}

export function mine(id: number, over: Partial<RuleSet> = {}): RuleSet {
  return {
    id: `user:${id}`,
    kind: "user",
    name: `Set ${id}`,
    description: "",
    default_on: true,
    global: null,
    overrides: [],
    entries: [],
    changed_at: null,
    created_at: 1_000,
    ...over,
  };
}

export function systemHost(
  pattern: string,
  over: Partial<SystemHost> = {},
): SystemHost {
  return {
    pattern,
    note: "extensions",
    reason: "code_server",
    reason_text: "The browser editor runs the bundled code-server.",
    workspace: null,
    ...over,
  };
}

type Body = Record<string, unknown>;
type Init = { params?: { path: { id: string } }; body?: Body };

export class FakeRuleSets {
  sets: RuleSet[] = [];
  system: SystemHost[] = [];
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Waiting requests the next switch closes. */
  closes: number[] = [];
  /** Refuse the next write with this status and message. */
  refuse: { status: number; message: string } | null = null;
  #id = 50;

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

  #find(init: Init): RuleSet | undefined {
    return this.sets.find((s) => s.id === init.params?.path.id);
  }

  GET = async (path: string) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    return this.reply(200, { sets: this.sets, system_managed: this.system });
  };

  POST = async (path: string, init: Init) => {
    this.calls.push(`POST ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const made = mine(this.#id++, {
      name: String(init.body?.["name"]),
      description: String(init.body?.["description"] ?? ""),
    });
    this.sets = [...this.sets, made];
    return this.reply(201, made);
  };

  PUT = async (path: string, init: Init) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const found = this.#find(init);
    if (!found) return this.reply(404);
    let next: RuleSet;
    if (path.endsWith("/switch")) {
      const workspace = (init.body?.["workspace"] as string | null) ?? null;
      const enabled = init.body?.["enabled"] as boolean | null;
      if (workspace === null) next = { ...found, global: enabled };
      else {
        const rest = found.overrides.filter((o) => o.workspace !== workspace);
        next = {
          ...found,
          overrides:
            enabled === null
              ? rest
              : [...rest, { workspace: workspace as never, enabled }],
        };
      }
      this.sets = this.sets.map((s) => (s.id === found.id ? next : s));
      const closed = this.closes;
      this.closes = [];
      return this.reply(200, { set: next, closed });
    }
    next = {
      ...found,
      name: String(init.body?.["name"]),
      description: String(init.body?.["description"] ?? ""),
    };
    this.sets = this.sets.map((s) => (s.id === found.id ? next : s));
    return this.reply(200, next);
  };

  DELETE = async (path: string, init: Init) => {
    this.calls.push(`DELETE ${path}`);
    if (this.down) throw new TypeError("down");
    if (this.refuse) return this.reply(this.refuse.status);
    const found = this.#find(init);
    this.sets = this.sets.filter((s) => s !== found);
    return found ? this.reply(200, found) : this.reply(404);
  };
}
