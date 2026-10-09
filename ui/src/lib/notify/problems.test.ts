// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { InAppNotifier } from "./notifier.ts";
import { NoticeCenter } from "./notices.svelte.ts";
import { ProblemNotices } from "./problems.ts";
import { NoticeWatcher } from "./watcher.ts";

type Problem = {
  key: string;
  workspace: string | null;
  title: string;
  detail: string;
};

let center: NoticeCenter;
let listed: Problem[] | null;
let reads: number;
let readFails: boolean;
const api = {
  GET: async () => {
    reads += 1;
    if (readFails) throw new Error("down");
    return listed === null
      ? { response: { status: 500 } }
      : { data: { problems: listed }, response: { status: 200 } };
  },
};
const settle = () => new Promise((r) => setTimeout(r, 0));
const problem = (key: string, workspace: string | null = null): Problem => ({
  key,
  workspace,
  title: `title of ${key}`,
  detail: `detail of ${key}`,
});
const keys = () => center.items.map((n) => n.key);

beforeEach(() => {
  center = new NoticeCenter();
  listed = [];
  reads = 0;
  readFails = false;
});

describe("background problems", () => {
  const make = () =>
    new ProblemNotices(new InAppNotifier(center), api as never);

  it("shows each problem the host lists, with its reason and the way out, and a link for a workspace's", async () => {
    listed = [problem("sweeper"), problem("git-locks:my web", "my web")];
    await make().refresh();
    expect(keys()).toEqual(["problem:sweeper", "problem:git-locks:my web"]);
    expect(center.items[0]).toMatchObject({
      tone: "warning",
      title: "title of sweeper",
      detail: "detail of sweeper",
    });
    expect(center.items[0]?.link).toBeUndefined();
    expect(center.items[1]?.link).toEqual({
      href: "/workspaces/my%20web",
      label: "Open workspace",
    });
  });

  it("withdraws a notice when its problem leaves the list", async () => {
    const notices = make();
    listed = [problem("sweeper"), problem("reconcile")];
    await notices.refresh();
    listed = [problem("reconcile")];
    await notices.refresh();
    expect(keys()).toEqual(["problem:reconcile"]);
    listed = [];
    await notices.refresh();
    expect(keys()).toEqual([]);
  });

  it("keeps what it shows when the list cannot be read", async () => {
    const notices = make();
    listed = [problem("sweeper")];
    await notices.refresh();
    readFails = true;
    await notices.refresh();
    listed = null;
    readFails = false;
    await notices.refresh();
    expect(keys()).toEqual(["problem:sweeper"]);
  });

  it("rereads on the event that says the list changed, and on no other", async () => {
    const notices = make();
    expect(notices.handle({ type: "rules_changed" })).toBe(false);
    expect(notices.handle(null)).toBe(false);
    expect(notices.handle("problems_changed")).toBe(false);
    expect(reads).toBe(0);
    listed = [problem("sweeper")];
    expect(notices.handle({ type: "problems_changed" })).toBe(true);
    await settle();
    expect(keys()).toEqual(["problem:sweeper"]);
  });

  it("is wired into the watcher: read at start, and again on the event", async () => {
    const source = new FakeSource();
    const watcher = new NoticeWatcher({
      source,
      notifier: new InAppNotifier(center),
      api: api as never,
    });
    listed = [problem("reconcile")];
    watcher.start();
    await settle();
    expect(keys()).toContain("problem:reconcile");
    listed = [];
    source.emit({ type: "problems_changed" });
    await settle();
    expect(keys()).not.toContain("problem:reconcile");
  });
});
