// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's workspace and per-workspace settings endpoints, for unit and
// component tests, in the shape openapi-fetch returns them. Not shipped (tests import it).
import type { components } from "#lib/api/schema.d.ts";
import type { DeleteCheck, Workspace } from "#lib/workspaces/model.ts";

type Layer = components["schemas"]["SettingsLayer"];

export function workspace(
  name: string,
  over: Partial<Workspace> = {},
): Workspace {
  return {
    id: name,
    name,
    repo_url: `https://github.com/acme/${name}.git`,
    image: "mcr.microsoft.com/devcontainers/base:debian",
    memory_mib: 8192,
    status: "stopped",
    busy: null,
    created_at: 1_000_000,
    disk_size_mib: 32_768,
    disk_used_mib: 2048,
    first_connect_notice_due: false,
    ...over,
  };
}

export function cleanCheck(
  name: string,
  over: Partial<DeleteCheck> = {},
): DeleteCheck {
  return {
    workspace: name,
    clean: true,
    repos: [],
    other: { items: [], more: 0 },
    errors: [],
    removes_sandbox: null,
    fingerprint: "fp-clean",
    ...over,
  };
}

export function dirtyCheck(name: string): DeleteCheck {
  return cleanCheck(name, {
    clean: false,
    fingerprint: "fp-dirty",
    repos: [
      {
        dir: name,
        clean: false,
        uncommitted: { items: [" M a.md", "?? b.md"], more: 3 },
        unpushed: { items: ["abc123 Fix it"], more: 0 },
        stashes: { items: [], more: 0 },
      },
    ],
    other: { items: ["scratch"], more: 0 },
  });
}

const noLayer = (): Layer => ({
  clipboard_read: null,
  local_toggles: {
    link_local: null,
    loopback: null,
    metadata: null,
    private: null,
    special: null,
  },
  memory: null,
  reconnection_grace: null,
  wildcards_reach_local: null,
  zoom_hotkeys: null,
});

const resolved = <T>(value: T, source: "sandbox" | "global" | "default") => ({
  value,
  source,
});

export class FakeWorkspaces {
  list: Workspace[] = [];
  overrides: Record<string, Layer> = {};
  globalMemory = 8192;
  check: DeleteCheck | null = null;
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Refuse the next call to a path (`"POST /api/workspaces"`) with this status and text. */
  refuse = new Map<string, { status: number; message: string }>();
  attachReply: components["schemas"]["AttachResponse"] = {
    opened: true,
    url: null,
    message: null,
  };

  private reply(status: number, data?: unknown, message = "refused") {
    const response = { status, ok: status < 400 } as Response;
    return status < 400
      ? { data, response }
      : {
          error: {
            error:
              status === 409
                ? "conflict"
                : status === 404
                  ? "not_found"
                  : "invalid",
            message,
          },
          response,
        };
  }

  private refusal(key: string) {
    const r = this.refuse.get(key);
    if (!r) return null;
    this.refuse.delete(key);
    return this.reply(r.status, undefined, r.message);
  }

  private find(id: unknown) {
    return this.list.find((w) => w.id === id);
  }

  private effective(name: string) {
    const o = this.overrides[name] ?? noLayer();
    const pick = (v: boolean | null) =>
      v === null ? resolved(false, "default") : resolved(v, "sandbox");
    return {
      clipboard_read:
        o.clipboard_read === null
          ? resolved("ask" as const, "default")
          : resolved(o.clipboard_read, "sandbox"),
      local_toggles: {
        link_local: pick(o.local_toggles.link_local),
        loopback: pick(o.local_toggles.loopback),
        metadata: pick(o.local_toggles.metadata),
        private: pick(o.local_toggles.private),
        special: pick(o.local_toggles.special),
      },
      memory:
        o.memory === null
          ? resolved(this.globalMemory, "global")
          : resolved(o.memory, "sandbox"),
      reconnection_grace: resolved(300, "default"),
      wildcards_reach_local: resolved(false, "default"),
      zoom_hotkeys: resolved(true, "default"),
    };
  }

  GET = async (
    path: string,
    init?: { params?: { path?: Record<string, unknown> } },
  ) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`GET ${path}`);
    if (refused) return refused;
    const id = init?.params?.path?.["id"] ?? init?.params?.path?.["sandbox"];
    switch (path) {
      case "/api/workspaces":
        return this.reply(200, { workspaces: this.list });
      case "/api/workspaces/{id}/delete-check":
        return this.find(id)
          ? this.reply(200, this.check ?? cleanCheck(String(id)))
          : this.reply(404, undefined, "no such workspace");
      case "/api/settings":
        return this.reply(200, {
          effective: this.effective("-"),
          sandbox_defaults: noLayer(),
          unknown_fields: [],
          vscode_server: {},
        });
      case "/api/settings/sandboxes/{sandbox}": {
        const name = String(id);
        return this.reply(200, {
          sandbox: name,
          overrides: this.overrides[name] ?? noLayer(),
          effective: this.effective(name),
          unknown_fields: [],
        });
      }
    }
    throw new Error(`unexpected GET ${path}`);
  };

  POST = async (
    path: string,
    init: {
      params?: { path?: Record<string, unknown> };
      body?: Record<string, unknown>;
    },
  ) => {
    this.calls.push(`POST ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`POST ${path}`);
    if (refused) return refused;
    if (path === "/api/workspaces") {
      const body = init.body ?? {};
      const name = String(body["name"]);
      if (this.find(name))
        return this.reply(
          409,
          undefined,
          `a workspace named ${name} already exists`,
        );
      const created = workspace(name, {
        repo_url: String(body["repo_url"]),
        status: "created",
        busy: "creating",
        memory_mib: Number(body["memory_mib"] ?? 8192),
      });
      this.list.push(created);
      return this.reply(202, created);
    }
    const id = init.params?.path?.["id"];
    const found = this.find(id);
    if (!found) return this.reply(404, undefined, "no such workspace");
    const verb = path.split("/").pop();
    if (verb === "attach") return this.reply(200, this.attachReply);
    const next: Workspace =
      verb === "start"
        ? { ...found, status: "starting", busy: "starting" }
        : verb === "stop"
          ? { ...found, status: "draining", busy: "stopping" }
          : { ...found, busy: "reclaiming" };
    this.list = this.list.map((w) => (w.id === found.id ? next : w));
    return this.reply(202, next);
  };

  DELETE = async (
    path: string,
    init: { params: { path: { id: string } }; body: Record<string, unknown> },
  ) => {
    this.calls.push(`DELETE ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`DELETE ${path}`);
    if (refused) return refused;
    const found = this.find(init.params.path.id);
    if (!found) return this.reply(404, undefined, "no such workspace");
    const next: Workspace = { ...found, busy: "deleting" };
    this.list = this.list.map((w) => (w.id === found.id ? next : w));
    return this.reply(202, next);
  };

  PUT = async (
    path: string,
    init: { params: { path: { sandbox: string } }; body: { overrides: Layer } },
  ) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    const refused = this.refusal(`PUT ${path}`);
    if (refused) return refused;
    const name = init.params.path.sandbox;
    this.overrides[name] = init.body.overrides;
    return this.reply(200, {
      sandbox: name,
      overrides: this.overrides[name],
      effective: this.effective(name),
      unknown_fields: [],
    });
  };
}
