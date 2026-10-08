// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import {
  FakeWorkspaces,
  cleanCheck,
  workspace,
} from "#lib/testing/fake-workspaces.ts";
import { WorkspaceStore, fieldOf, type Settled } from "./workspaces.svelte.ts";

let api: FakeWorkspaces;
let source: FakeSource;
let store: WorkspaceStore;
let settled: Settled[];

beforeEach(() => {
  api = new FakeWorkspaces();
  api.list = [workspace("b-site"), workspace("a-shop", { status: "running" })];
  source = new FakeSource();
  settled = [];
  store = new WorkspaceStore({
    api: api as never,
    source,
    now: () => 777,
    pollMs: 1000,
  });
  store.onSettled = (s) => settled.push(s);
});
afterEach(() => vi.useRealTimers());

const status = (workspace: string, state: string) => ({
  type: "status_changed",
  workspace,
  status: state,
});
const step = (
  workspace: string,
  name: string,
  detail: string | null = null,
) => ({
  type: "workspace_progress",
  workspace,
  step: name,
  detail,
});

describe("reading the list", () => {
  it("loads it sorted by name", async () => {
    expect(store.status).toBe("loading");
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.list.map((w) => w.name)).toEqual(["a-shop", "b-site"]);
    expect(store.byName("a-shop")?.status).toBe("running");
    expect(store.byName("nope")).toBeUndefined();
  });

  it("fails quietly while it has never worked, and keeps what it has after", async () => {
    api.down = true;
    await store.refresh();
    expect(store.status).toBe("failed");
    api.down = false;
    await store.refresh();
    expect(store.status).toBe("ready");
    api.down = true;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.list).toHaveLength(2);
  });

  it("fails on a refusal as well as on a dead service", async () => {
    api.refuse.set("GET /api/workspaces", { status: 500, message: "broken" });
    await store.refresh();
    expect(store.status).toBe("failed");
    await store.refresh();
    api.refuse.set("GET /api/workspaces", { status: 500, message: "broken" });
    await store.refresh();
    expect(store.status).toBe("ready");
  });

  it("shares overlapping reads, then reads once more", async () => {
    const first = store.refresh();
    const second = store.refresh();
    expect(second).toBe(first);
    await first;
    await vi.waitFor(() =>
      expect(api.calls.filter((c) => c === "GET /api/workspaces")).toHaveLength(
        2,
      ),
    );
  });
});

describe("events", () => {
  beforeEach(async () => {
    await store.refresh();
  });

  it("applies a status change in place and keeps the order", () => {
    store.handleEvent(status("b-site", "running"));
    expect(store.byName("b-site")?.status).toBe("running");
    expect(store.list.map((w) => w.name)).toEqual(["a-shop", "b-site"]);
  });

  it("reads the list when a workspace it doesn't know changes", async () => {
    api.list.push(workspace("c-new", { status: "created" }));
    store.handleEvent(status("c-new", "starting"));
    await vi.waitFor(() => expect(store.byName("c-new")).toBeDefined());
  });

  it("remembers the last out-of-memory kill with the time the page heard it", () => {
    store.handleEvent({
      type: "oom_kill",
      workspace: "a-shop",
      pid: 9,
      process: "node",
    });
    expect(store.oom["a-shop"]).toEqual({ process: "node", pid: 9, at: 777 });
  });

  it("ignores events about nothing it shows", () => {
    store.handleEvent({ type: "rules_changed" });
    store.handleEvent("nonsense");
    expect(store.progress).toEqual({});
  });

  it("shows a step, and the record's operation with it", async () => {
    api.list = api.list.map((w) =>
      w.name === "b-site" ? { ...w, busy: "starting" } : w,
    );
    await store.refresh();
    store.handleEvent(step("b-site", "syncing", "files"));
    expect(store.progress["b-site"]).toEqual({
      step: "syncing",
      detail: "files",
      operation: "starting",
      failed: false,
    });
  });

  it("reads the record when progress arrives for a workspace that isn't marked busy", async () => {
    const before = api.calls.length;
    store.handleEvent(step("b-site", "starting"));
    await vi.waitFor(() => expect(api.calls.length).toBeGreaterThan(before));
  });

  it("clears the step on done, reads the list and tells who finished what", async () => {
    store.handleEvent(step("b-site", "starting"));
    await store.refresh(); // the step made it read the record; events wait for the read
    api.list = api.list.map((w) =>
      w.name === "b-site" ? { ...w, busy: null, status: "running" } : w,
    );
    store.handleEvent(step("b-site", "done"));
    expect(store.progress["b-site"]).toBeUndefined();
    await vi.waitFor(() =>
      expect(store.byName("b-site")?.status).toBe("running"),
    );
    expect(settled).toEqual([
      { name: "b-site", operation: "starting", failed: false, detail: null },
    ]);
  });

  it("keeps a failure, with its reason, until it is dismissed", () => {
    store.handleEvent(step("b-site", "failed", "no boot"));
    expect(store.progress["b-site"]).toMatchObject({
      step: "failed",
      detail: "no boot",
      failed: true,
    });
    expect(settled[0]).toMatchObject({ failed: true, detail: "no boot" });
    store.dismissProgress("b-site");
    expect(store.progress["b-site"]).toBeUndefined();
  });

  it("applies events that arrive during a read after it, so the read can't undo them", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const slow = api.GET;
    api.GET = async (
      path: string,
      init?: { params?: { path?: Record<string, unknown> } },
    ) => {
      const result = await slow(path, init);
      await gate;
      return result;
    };
    const reading = store.refresh();
    await vi.waitFor(() => expect(api.calls.length).toBeGreaterThan(1));
    store.handleEvent(status("b-site", "running"));
    expect(store.byName("b-site")?.status).toBe("stopped");
    release();
    await reading;
    expect(store.byName("b-site")?.status).toBe("running");
  });
});

describe("actions", () => {
  beforeEach(async () => {
    await store.refresh();
  });

  it("creates a workspace and lists it as busy", async () => {
    store.progress = {
      "new-one": {
        step: "failed",
        detail: "old",
        operation: "creating",
        failed: true,
      },
    };
    const result = await store.create({
      name: "new-one",
      repo_url: "https://github.com/acme/new-one.git",
    });
    expect(result).toMatchObject({
      ok: true,
      value: { name: "new-one", busy: "creating" },
    });
    expect(store.byName("new-one")?.busy).toBe("creating");
    expect(store.progress["new-one"]).toBeUndefined();
    expect(api.bodies.at(-1)).toEqual({
      name: "new-one",
      repo_url: "https://github.com/acme/new-one.git",
    });
  });

  it("puts a name that is taken on the name field", async () => {
    const result = await store.create({
      name: "a-shop",
      repo_url: "https://x.org/a.git",
    });
    expect(result).toMatchObject({
      ok: false,
      reason: "conflict",
      field: "name",
    });
  });

  it("puts a refusal on the field it is about", async () => {
    api.refuse.set("POST /api/workspaces", {
      status: 422,
      message:
        "SSH remotes are not supported yet; use the repository's HTTPS URL instead",
    });
    const result = await store.create({ name: "x", repo_url: "git@x:y" });
    expect(result).toMatchObject({ ok: false, field: "repo_url" });
  });

  it("says the service is down", async () => {
    api.down = true;
    expect(await store.create({ name: "x", repo_url: "https://x/y" })).toEqual({
      ok: false,
      message: "puddle's service isn't answering.",
    });
  });

  it.each([
    ["startWorkspace", "starting", "starting"],
    ["stopWorkspace", "draining", "stopping"],
    ["reclaim", "stopped", "reclaiming"],
  ] as const)(
    "%s marks the workspace busy at once",
    async (method, state, busy) => {
      store.progress = {
        "b-site": {
          step: "failed",
          detail: null,
          operation: null,
          failed: true,
        },
      };
      const result = await store[method]("b-site");
      expect(result.ok).toBe(true);
      const w = store.byName("b-site");
      expect(w?.busy).toBe(busy);
      expect(w?.status).toBe(state);
      expect(store.progress["b-site"]).toBeUndefined();
    },
  );

  it("takes the operation from its first step when the answer to the request is late", async () => {
    // The service finished before its answer reached the page: steps, then done.
    const real = api.POST;
    api.POST = async (path: string, init: Parameters<typeof real>[1]) => {
      const answer = await real(path, init);
      store.handleEvent(step("b-site", "starting"));
      store.handleEvent(step("b-site", "syncing"));
      store.handleEvent(status("b-site", "running"));
      api.list = api.list.map((w) =>
        w.name === "b-site" ? { ...w, busy: null, status: "running" } : w,
      );
      store.handleEvent(step("b-site", "done"));
      return answer;
    };
    await store.startWorkspace("b-site");
    await store.refresh();
    // The answer said "busy starting"; it is older than the end of the operation, so it is not shown.
    expect(store.byName("b-site")).toMatchObject({
      busy: null,
      status: "running",
    });
    expect(settled.at(-1)).toMatchObject({
      name: "b-site",
      operation: "starting",
      failed: false,
    });
  });

  it("keeps the steps of a new operation but forgets the last one's failure", async () => {
    store.progress = {
      "b-site": {
        step: "failed",
        detail: "old",
        operation: "starting",
        failed: true,
      },
    };
    await store.startWorkspace("b-site");
    expect(store.progress["b-site"]).toBeUndefined();
    store.handleEvent(step("b-site", "syncing"));
    await store.stopWorkspace("b-site");
    expect(store.progress["b-site"]).toMatchObject({
      step: "syncing",
      failed: false,
    });
  });

  it("reads the list again after a 409 and after a 404, and says which", async () => {
    api.refuse.set("POST /api/workspaces/{id}/start", {
      status: 409,
      message: "already running",
    });
    const conflict = await store.startWorkspace("b-site");
    expect(conflict).toEqual({
      ok: false,
      message: "already running",
      reason: "conflict",
    });
    const gone = await store.startWorkspace("ghost");
    expect(gone).toEqual({
      ok: false,
      message: "That workspace no longer exists.",
      reason: "gone",
    });
  });

  it("reads what a delete would lose", async () => {
    api.check = cleanCheck("b-site");
    const result = await store.checkDelete("b-site");
    expect(result).toMatchObject({
      ok: true,
      value: { fingerprint: "fp-clean" },
    });
    expect(await store.checkDelete("ghost")).toMatchObject({
      ok: false,
      reason: "gone",
    });
  });

  it("deletes with the fingerprint the user saw", async () => {
    const result = await store.remove("b-site", "fp-1");
    expect(result.ok).toBe(true);
    expect(api.bodies.at(-1)).toEqual({ confirm: true, fingerprint: "fp-1" });
    expect(store.byName("b-site")?.busy).toBe("deleting");
  });

  it("passes on a refused delete", async () => {
    api.refuse.set("DELETE /api/workspaces/{id}", {
      status: 409,
      message: "changed since",
    });
    expect(await store.remove("b-site", "old")).toMatchObject({
      ok: false,
      reason: "conflict",
      message: "changed since",
    });
  });

  it("attaches in the mode asked", async () => {
    const result = await store.attach("a-shop", "desktop");
    expect(result).toMatchObject({ ok: true, value: { opened: true } });
    expect(api.bodies.at(-1)).toEqual({ mode: "desktop" });
  });
});

describe("listening", () => {
  it("reads at the start, on a resync and on the slow poll, and applies events", async () => {
    vi.useFakeTimers();
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(store.status).toBe("ready");
    const reads = () =>
      api.calls.filter((c) => c === "GET /api/workspaces").length;
    expect(reads()).toBe(1);
    source.emit(status("b-site", "running"));
    expect(store.byName("b-site")?.status).toBe("running");
    source.resync();
    await vi.advanceTimersByTimeAsync(0);
    expect(reads()).toBe(2);
    await vi.advanceTimersByTimeAsync(1000);
    expect(reads()).toBeGreaterThanOrEqual(3);
    stop();
    const after = reads();
    source.emit(status("b-site", "crashed"));
    expect(store.byName("b-site")?.status).toBe("stopped");
    await vi.advanceTimersByTimeAsync(5000);
    expect(reads()).toBe(after);
  });

  it("stops before the first read finishes", async () => {
    vi.useFakeTimers();
    const stop = store.start();
    stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.calls.filter((c) => c === "GET /api/workspaces")).toHaveLength(
      1,
    );
  });
});

describe("fieldOf", () => {
  it.each([
    ["use an https:// URL for the repository", "repo_url"],
    ["SSH remotes are not supported yet", "repo_url"],
    ["bad image reference", "image"],
    ["memory must be at least 256 MiB", "memory_mib"],
    ["this name can't be a workspace: x", "name"],
    ["a workspace named x already exists", "name"],
    ["something else", "form"],
  ])("%j goes to %s", (message, field) => {
    expect(fieldOf(message)).toBe(field);
  });
});
