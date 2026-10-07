// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { report } from "#lib/testing/fake-network.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { InAppNotifier } from "./notifier.ts";
import { NoticeCenter, type NoticeInput } from "./notices.svelte.ts";
import { NoticeWatcher } from "./watcher.ts";

const sample = (key: string, title = key): NoticeInput => ({
  key,
  tone: "info",
  title,
});

describe("NoticeCenter", () => {
  it("adds, replaces a notice with the same key, dismisses, resolves and clears", () => {
    let t = 10;
    const c = new NoticeCenter(() => t++);
    const a = c.add(sample("a"));
    c.add(sample("b"));
    t = 50;
    c.add(sample("a", "again"));
    expect(c.items.map((n) => [n.key, n.title, n.at])).toEqual([
      ["b", "b", 11],
      ["a", "again", 50],
    ]);
    c.dismiss(a);
    expect(c.items).toHaveLength(2);
    c.resolve("b");
    expect(c.items.map((n) => n.key)).toEqual(["a"]);
    const before = c.items;
    c.resolve("nothing");
    expect(c.items).toBe(before);
    c.clear();
    expect(c.items).toEqual([]);
  });

  it("uses the clock when none is given", () => {
    const c = new NoticeCenter();
    c.add(sample("a"));
    expect(c.items[0]?.at).toBeGreaterThan(1_000_000_000_000);
  });
});

describe("InAppNotifier", () => {
  it("puts notices in the list and takes them out", () => {
    const c = new NoticeCenter();
    const n = new InAppNotifier(c);
    n.notify(sample("a"));
    expect(c.items).toHaveLength(1);
    n.resolve("a");
    expect(c.items).toHaveLength(0);
  });
  it("defaults to the shared list", () => {
    expect(() => new InAppNotifier()).not.toThrow();
  });
});

describe("NoticeWatcher", () => {
  let source: FakeSource;
  let center: NoticeCenter;
  let list: unknown;
  let listFails: boolean;
  const api = {
    GET: async () => {
      if (listFails) throw new Error("down");
      return list === null
        ? { response: { status: 500 } }
        : { data: list, response: { status: 200 } };
    },
  };
  const settle = () => new Promise((r) => setTimeout(r, 0));
  const make = () =>
    new NoticeWatcher({
      source,
      notifier: new InAppNotifier(center),
      api: api as never,
    });
  const status = (sandbox: string, s: string) =>
    ({ type: "status_changed", sandbox, status: s }) as const;
  const keys = () => center.items.map((n) => n.key);

  beforeEach(() => {
    source = new FakeSource();
    center = new NoticeCenter();
    listFails = false;
    list = {
      workspaces: [
        { name: "web", status: "running" },
        { name: "docs", status: "stopped" },
      ],
    };
  });

  it("says a workspace ran out of memory, naming the process, with a link to its settings", () => {
    const w = make();
    w.handle({
      type: "oom_kill",
      sandbox: "my web",
      pid: 42,
      process: "<b>node</b>",
    });
    const [n] = center.items;
    expect(n?.title).toBe("my web ran out of memory and a process was killed.");
    expect(n?.detail).toContain("<b>node</b> (process 42)");
    expect(n?.link?.href).toBe("/workspaces/my%20web/settings");
  });

  it("calls a stop nobody asked for unexpected, from the seeded list", async () => {
    const w = make();
    w.start();
    await settle();
    source.emit(status("web", "stopped"));
    expect(keys()).toEqual(["stop:web"]);
    expect(center.items[0]?.title).toBe("web stopped without being asked to.");
    source.emit(status("web", "running"));
    expect(keys()).toEqual([]);
  });

  it("does not call a stop unexpected when it was asked for, or draining, or for a workspace not seen", async () => {
    const w = make();
    w.start();
    await settle();
    source.emit({
      type: "workspace_progress",
      sandbox: "web",
      step: "stopping",
      detail: null,
    });
    source.emit(status("web", "stopped"));
    source.emit(status("web", "running"));
    source.emit(status("web", "draining"));
    source.emit(status("web", "stopped"));
    source.emit(status("never-seen", "stopped"));
    source.emit({
      type: "workspace_progress",
      sandbox: "web",
      step: "cloning",
      detail: null,
    });
    source.emit({
      type: "workspace_progress",
      sandbox: "web",
      step: "removing",
      detail: null,
    });
    expect(keys()).toEqual([]);
    // Starting clears the expectation: the next stop is a surprise again.
    source.emit(status("web", "starting"));
    source.emit(status("web", "running"));
    source.emit(status("web", "stopped"));
    expect(keys()).toEqual(["stop:web"]);
  });

  it("reports a crash, and ignores events it has no use for", async () => {
    const w = make();
    w.handle(status("docs", "crashed"));
    expect(center.items[0]).toMatchObject({
      key: "stop:docs",
      title: "docs crashed.",
    });
    w.handle({ type: "rules_changed" });
    w.handle({ type: "network_changed", epoch: 1 });
    w.handle(null);
    expect(center.items).toHaveLength(1);
  });

  it("keeps a newer event over the list it reads later, and survives a failing list", async () => {
    const w = make();
    w.handle(status("web", "stopped"));
    await w.seed();
    w.handle(status("web", "running"));
    w.handle(status("web", "stopped"));
    expect(keys()).toEqual(["stop:web"]);
    list = null;
    await w.seed();
    listFails = true;
    await w.seed();
  });

  it("re-reads the list after a resync and stops listening when stopped", async () => {
    const w = make();
    const stop = w.start();
    await settle();
    list = { workspaces: [{ name: "late", status: "running" }] };
    source.resync();
    await settle();
    source.emit(status("late", "stopped"));
    expect(keys()).toEqual(["stop:late"]);
    stop();
    source.emit(status("web", "stopped"));
    expect(keys()).toEqual(["stop:late"]);
  });

  it("works without a stream", () => {
    const w = new NoticeWatcher({
      notifier: new InAppNotifier(center),
      api: api as never,
    });
    w.start()();
  });

  it("raises the network notice once per problem, withdraws it when it clears, and ignores no report", () => {
    const w = make();
    w.network(null);
    expect(center.items).toEqual([]);
    const bad = report();
    bad.proxy.pac_state = "unreachable";
    w.network(bad);
    const first = center.items[0];
    expect(first?.key).toBe("network");
    expect(first?.title).toMatch(/^Network trouble: The proxy script at/);
    expect(first?.link?.href).toBe("/settings/network-health");
    w.network(bad);
    expect(center.items[0]?.id).toBe(first?.id);
    bad.proxy.settings_error = "x";
    w.network(bad);
    expect(center.items[0]?.id).not.toBe(first?.id);
    w.network(report());
    expect(center.items).toEqual([]);
    w.network(bad);
    expect(center.items).toHaveLength(1);
  });

  it("uses the shared notifier and API when none is given", () => {
    expect(() => new NoticeWatcher()).not.toThrow();
  });
});
