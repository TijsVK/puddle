// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeRepos, repoSource, repoView } from "#lib/testing/fake-repos.ts";
import { RepoLists } from "./repos.svelte.ts";

let api: FakeRepos;
let clock: number;
const make = () =>
  new RepoLists({ api: api as never, slowAfterMs: 1500, now: () => clock });

beforeEach(() => {
  vi.useFakeTimers();
  api = new FakeRepos();
  clock = 5_000_000;
  api.repos = [
    repoView("acme", "web"),
    repoView("acme", "api"),
    repoView("tijs", "dotfiles", { identities: [2] }),
  ];
  api.sources = [
    repoSource({ repo_count: 2 }),
    repoSource({ identity_id: 2, repo_count: 1 }),
  ];
});
afterEach(() => vi.useRealTimers());

describe("load", () => {
  it("reads the repositories and the state of each list", async () => {
    const lists = make();
    expect(lists.status).toBe("idle");
    await lists.load({ identity: 1 });
    expect(lists.status).toBe("ready");
    expect(lists.listing?.repos.map((r) => r.full_name)).toEqual([
      "acme/web",
      "acme/api",
    ]);
    expect(lists.listing?.sources).toHaveLength(1);
    expect(lists.message).toBeNull();
    expect(api.queries).toEqual([{ identity: 1, limit: 100 }]);
  });

  it("passes the words and the page size", async () => {
    const lists = make();
    await lists.load({ query: "acme", limit: 20 });
    expect(api.queries).toEqual([{ query: "acme", limit: 20 }]);
  });

  it("says the read is slow only after a moment, and not once it ends", async () => {
    const lists = make();
    api.hold();
    const reading = lists.load({});
    expect(lists.status).toBe("loading");
    expect(lists.slow).toBe(false);
    await vi.advanceTimersByTimeAsync(1600);
    expect(lists.slow).toBe(true);
    api.release();
    await reading;
    expect(lists.slow).toBe(false);
    expect(lists.status).toBe("ready");
  });

  it("keeps the last list on show while a quiet read runs", async () => {
    const lists = make();
    await lists.load({});
    api.hold();
    const again = lists.load({}, true);
    expect(lists.status).toBe("ready");
    expect(lists.slow).toBe(false);
    api.release();
    await again;
  });

  it("keeps showing the old list when a later read is refused, and says why", async () => {
    const lists = make();
    await lists.load({});
    api.refuse = { status: 503, message: "repository lists are not available" };
    await lists.load({});
    expect(lists.status).toBe("failed");
    expect(lists.message).toBe("Repository lists are not available.");
    expect(lists.listing?.repos).toHaveLength(3);
  });

  it("names a service that does not answer", async () => {
    const lists = make();
    api.down = true;
    await lists.load({});
    expect(lists.status).toBe("failed");
    expect(lists.message).toBe("puddle's service isn't answering.");
  });

  it("never lets a slow older answer replace a newer one", async () => {
    const lists = make();
    api.hold();
    const first = lists.load({ query: "acme" });
    api.release();
    await lists.load({ query: "tijs" });
    await first;
    expect(lists.listing?.repos.map((r) => r.full_name)).toEqual([
      "tijs/dotfiles",
    ]);
  });

  it("drops an answer that arrives after the screen is gone", async () => {
    const lists = make();
    api.hold();
    const reading = lists.load({});
    lists.stop();
    api.release();
    await reading;
    expect(lists.listing).toBeNull();
    expect(lists.status).toBe("loading");
  });

  it("drops a failure that arrives after the screen is gone", async () => {
    const lists = make();
    api.hold();
    api.down = true;
    const reading = lists.load({});
    lists.stop();
    api.release();
    await reading;
    expect(lists.message).toBeNull();
  });
});

describe("asking again by itself", () => {
  it("reads again when a host that said to wait allows it", async () => {
    api.sources = [repoSource({ state: "stale", retry_at: clock + 60_000 })];
    const lists = make();
    await lists.load({ identity: 1 });
    expect(api.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(60_900);
    expect(api.calls).toHaveLength(1);
    clock += 61_000;
    api.sources = [repoSource()];
    await vi.advanceTimersByTimeAsync(200);
    expect(api.calls).toHaveLength(2);
    // The second answer waits for nobody, so nothing more is scheduled.
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(api.calls).toHaveLength(2);
  });

  it("stops asking when the screen is gone", async () => {
    api.sources = [repoSource({ state: "stale", retry_at: clock + 5_000 })];
    const lists = make();
    await lists.load({});
    lists.stop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(api.calls).toHaveLength(1);
  });
});

describe("more", () => {
  it("puts the next page after what is shown", async () => {
    const lists = make();
    await lists.load({ limit: 2 });
    expect(lists.listing?.repos).toHaveLength(2);
    await lists.more();
    expect(lists.listing?.repos.map((r) => r.full_name)).toEqual([
      "acme/web",
      "acme/api",
      "tijs/dotfiles",
    ]);
    expect(api.queries.at(-1)).toMatchObject({ offset: 2, limit: 2 });
    await lists.more();
    expect(api.calls).toHaveLength(2);
  });

  it("does nothing before a first read or while one more is running", async () => {
    const lists = make();
    await lists.more();
    expect(api.calls).toHaveLength(0);
    await lists.load({ limit: 1 });
    api.hold();
    const first = lists.more();
    await lists.more();
    expect(lists.loadingMore).toBe(true);
    api.release();
    await first;
    expect(lists.loadingMore).toBe(false);
    expect(api.calls).toHaveLength(2);
  });

  it("says the service is silent when the page cannot be read", async () => {
    const lists = make();
    await lists.load({ limit: 1 });
    api.down = true;
    await lists.more();
    expect(lists.message).toBe("puddle's service isn't answering.");
    expect(lists.listing?.repos).toHaveLength(1);
  });

  it("leaves the list alone when a new search replaced it meanwhile", async () => {
    const lists = make();
    await lists.load({ limit: 1 });
    api.hold();
    const next = lists.more();
    api.release();
    await lists.load({ query: "tijs" });
    await next;
    expect(lists.listing?.repos.map((r) => r.full_name)).toEqual([
      "tijs/dotfiles",
    ]);
  });
});

describe("refresh", () => {
  it("asks the host to read again, then shows what it read", async () => {
    const lists = make();
    await lists.load({ identity: 1 });
    api.repos = [...api.repos, repoView("acme", "new")];
    api.hold();
    const refreshing = lists.refresh(1);
    expect(lists.refreshing).toBe(true);
    api.release();
    await refreshing;
    expect(lists.refreshing).toBe(false);
    expect(api.refreshBodies).toEqual([{ identity_id: 1 }]);
    expect(lists.listing?.repos.map((r) => r.name)).toContain("new");
    expect(lists.status).toBe("ready");
  });

  it("refreshes every identity's lists when none is named, and only once at a time", async () => {
    const lists = make();
    await lists.load({});
    api.hold();
    const first = lists.refresh();
    await lists.refresh();
    api.release();
    await first;
    expect(api.refreshBodies).toEqual([{}]);
  });

  it("says why a refresh was refused and keeps the list", async () => {
    const lists = make();
    await lists.load({});
    api.refuse = { status: 503, message: "repository lists are not available" };
    await lists.refresh();
    expect(lists.message).toBe("Repository lists are not available.");
    expect(lists.listing).not.toBeNull();
    expect(lists.refreshing).toBe(false);
  });

  it("names a service that does not answer", async () => {
    const lists = make();
    await lists.load({});
    api.down = true;
    await lists.refresh();
    expect(lists.message).toBe("puddle's service isn't answering.");
  });

  it("does not touch a screen that is gone", async () => {
    const lists = make();
    await lists.load({});
    api.hold();
    const refreshing = lists.refresh();
    lists.stop();
    api.release();
    await refreshing;
    expect(lists.refreshing).toBe(false);
  });
});
