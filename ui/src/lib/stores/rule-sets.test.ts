// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import {
  FakeRuleSets,
  builtIn,
  mine,
  systemHost,
} from "#lib/testing/fake-rule-sets.ts";
import { RuleSetsStore } from "./rule-sets.svelte.ts";

let api: FakeRuleSets;
let source: FakeSource;
let changed: number;

function make(pollMs = 60_000) {
  return new RuleSetsStore({
    api: api as never,
    source,
    pollMs,
    onDecidedElsewhere: () => {
      changed += 1;
    },
  });
}

beforeEach(() => {
  api = new FakeRuleSets();
  source = new FakeSource();
  changed = 0;
});
afterEach(() => vi.useRealTimers());

describe("reading", () => {
  it("loads the sets and the System managed hosts", async () => {
    api.sets = [builtIn("github"), mine(1)];
    api.system = [systemHost("open-vsx.org")];
    const store = make();
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.sets.map((s) => s.id)).toEqual(["builtin:github", "user:1"]);
    expect(store.system.map((h) => h.pattern)).toEqual(["open-vsx.org"]);
  });

  it("fails the first read quietly and keeps what it has later", async () => {
    api.down = true;
    const store = make();
    await store.refresh();
    expect(store.status).toBe("failed");
    api.down = false;
    api.sets = [mine(1)];
    await store.refresh();
    api.down = true;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.sets).toHaveLength(1);
  });

  it("treats an error answer like a failure", async () => {
    api.GET = async () =>
      ({
        error: { error: "internal", message: "x" },
        response: { status: 500, ok: false } as Response,
      }) as never;
    const store = make();
    await store.refresh();
    expect(store.status).toBe("failed");
  });

  it("refetches on rules_changed and on a resync, and polls", async () => {
    vi.useFakeTimers();
    const store = make(1000);
    const stop = store.start();
    await vi.waitFor(() => expect(api.calls).toHaveLength(1));
    source.emit({ type: "rules_changed" });
    source.emit({ type: "something_else" });
    source.resync();
    await vi.waitFor(() => expect(api.calls).toHaveLength(3));
    await vi.advanceTimersByTimeAsync(1000);
    expect(api.calls).toHaveLength(4);
    stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.calls).toHaveLength(4);
  });
});

describe("changing", () => {
  it("makes, renames and deletes a set", async () => {
    const store = make();
    await store.refresh();
    const made = await store.create("Client X", "their tenant");
    expect(made.ok && made.value.name).toBe("Client X");
    expect(store.sets.map((s) => s.name)).toEqual(["Client X"]);
    const id = store.sets[0]?.id ?? "";
    const renamed = await store.rename(id, "Client Y", "");
    expect(renamed.ok).toBe(true);
    expect(store.sets[0]?.name).toBe("Client Y");
    expect(await store.remove(id)).toEqual({ ok: true });
    expect(store.sets).toEqual([]);
    // Already gone is gone.
    expect(await store.remove(id)).toEqual({ ok: true });
  });

  it("passes the server's refusals on as sentences", async () => {
    const store = make();
    api.refuse = {
      status: 422,
      message: "rule set name: another rule set has this name",
    };
    expect(await store.create("x", "")).toEqual({
      ok: false,
      message: "Rule set name: another rule set has this name.",
    });
    api.sets = [mine(1)];
    api.refuse = { status: 422, message: "too long" };
    expect(await store.rename("user:1", "x", "")).toEqual({
      ok: false,
      message: "Too long.",
    });
    api.refuse = { status: 500, message: "boom" };
    expect(await store.remove("user:1")).toEqual({
      ok: false,
      message: "puddle couldn't delete that rule set.",
    });
    api.refuse = { status: 422, message: "System managed can't be switched" };
    expect(await store.switchSet("user:1", null, true)).toEqual({
      ok: false,
      message: "System managed can't be switched.",
    });
  });

  it("says when the service is down", async () => {
    const store = make();
    api.down = true;
    const down = { ok: false, message: "puddle's service isn't answering." };
    expect(await store.create("x", "")).toEqual(down);
    expect(await store.rename("user:1", "x", "")).toEqual(down);
    expect(await store.remove("user:1")).toEqual(down);
    expect(await store.switchSet("user:1", null, true)).toEqual(down);
  });

  it("switches for every workspace or one, and tells the badge when requests closed", async () => {
    api.sets = [builtIn("github")];
    const store = make();
    await store.refresh();
    api.closes = [3, 4];
    const on = await store.switchSet("builtin:github", null, true);
    expect(on).toEqual({ ok: true, value: 2 });
    expect(store.sets[0]?.global).toBe(true);
    expect(changed).toBe(1);
    const off = await store.switchSet("builtin:github", "api", false);
    expect(off).toEqual({ ok: true, value: 0 });
    expect(store.sets[0]?.overrides).toEqual([
      { workspace: "api", enabled: false },
    ]);
    expect(changed).toBe(1);
    expect(api.bodies.at(-1)).toEqual({ workspace: "api", enabled: false });
  });
});
