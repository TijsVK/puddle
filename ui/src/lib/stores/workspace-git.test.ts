// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  credential,
  FakeIdentities,
  identity,
  repoRow,
} from "#lib/testing/fake-identities.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { WorkspaceGitStore } from "./workspace-git.svelte.ts";

let api: FakeIdentities;
let source: FakeSource;

const make = () => new WorkspaceGitStore(api as never, source);

beforeEach(() => {
  api = new FakeIdentities();
  source = new FakeSource();
  api.identities = [
    identity(1, {
      label: "Work",
      credentials: [credential({ owners: ["acme"], rest: false })],
    }),
    identity(2, {
      label: "Personal",
      credentials: [credential({ rest: true })],
    }),
    identity(3, {
      label: "Other",
      credentials: [credential({ owners: ["acme"], rest: false })],
    }),
  ];
  api.git["web"] = { ids: [1], repos: [repoRow(7)], push: true, pull: false };
});

describe("reading", () => {
  it("loads a workspace's identities, table and switches", async () => {
    const store = make();
    await store.load("web");
    expect(store.status).toBe("ready");
    expect(store.git?.identities.map((i) => i.label)).toEqual(["Work"]);
    expect(store.git?.repos.map((r) => r.id)).toEqual([7]);
    expect(store.git?.only_push_listed).toBe(true);
  });

  it("fails the first read and keeps the page on a quiet one", async () => {
    const store = make();
    api.down = true;
    await store.load("web");
    expect(store.status).toBe("failed");
    api.down = false;
    await store.load("web");
    api.down = true;
    await store.load("web", true);
    expect(store.status).toBe("ready");
    const refused = make();
    const real = api.GET;
    api.GET = (async () => ({
      response: { status: 500 } as Response,
    })) as never;
    await refused.load("web");
    expect(refused.status).toBe("failed");
    await refused.load("web", true);
    expect(refused.status).toBe("failed");
    api.GET = real;
  });

  it("never lets a slow answer overwrite a newer one", async () => {
    const store = make();
    const real = api.GET;
    let release: (() => void) | undefined;
    api.GET = (async (path: string, init: never) => {
      const first = release === undefined;
      if (first) await new Promise<void>((resolve) => (release = resolve));
      return real(path, init);
    }) as never;
    const slow = store.load("web");
    api.git["web"]!.push = false;
    await store.load("web", true);
    release?.();
    await slow;
    expect(store.git?.only_push_listed).toBe(false);
  });

  it("follows the workspace's own changes and any identity change, and stops", async () => {
    const store = make();
    const stop = store.start("web");
    await vi.waitFor(() => expect(store.status).toBe("ready"));
    api.git["web"]!.push = false;
    source.emit({ type: "workspace_git_changed", workspace: "other" });
    await Promise.resolve();
    expect(store.git?.only_push_listed).toBe(true);
    source.emit({ type: "workspace_git_changed", workspace: "web" });
    await vi.waitFor(() => expect(store.git?.only_push_listed).toBe(false));
    api.git["web"]!.push = true;
    source.emit({ type: "identities_changed" });
    await vi.waitFor(() => expect(store.git?.only_push_listed).toBe(true));
    api.git["web"]!.push = false;
    source.resync();
    await vi.waitFor(() => expect(store.git?.only_push_listed).toBe(false));
    stop();
    api.git["web"]!.push = true;
    source.emit({ type: "identities_changed" });
    await Promise.resolve();
    expect(store.git?.only_push_listed).toBe(false);
  });

  it("starts without a live source", async () => {
    const store = new WorkspaceGitStore(api as never, undefined);
    store.start("web")();
    await vi.waitFor(() => expect(store.status).toBe("ready"));
  });
});

describe("identities of a workspace", () => {
  it("adds one, last, and refuses a collision with the host's words", async () => {
    const store = make();
    await store.load("web");
    expect((await store.attach(2)).ok).toBe(true);
    expect(store.git?.identities.map((i) => i.label)).toEqual([
      "Work",
      "Personal",
    ]);
    expect(await store.attach(3)).toEqual({
      ok: false,
      message: "Work and Other both cover github.com/acme; narrow one.",
    });
    expect(store.git?.identities).toHaveLength(2);
  });

  it("puts them in a new order and takes one off", async () => {
    const store = make();
    await store.load("web");
    await store.attach(2);
    expect((await store.setIdentities([2, 1])).ok).toBe(true);
    expect(store.git?.identities.map((i) => i.id)).toEqual([2, 1]);
    expect((await store.detach(2)).ok).toBe(true);
    expect(store.git?.identities.map((i) => i.id)).toEqual([1]);
    expect(await store.detach(2)).toEqual({
      ok: false,
      message: "Refused.",
    });
    expect((await store.setIdentities([1, 3])).ok).toBe(false);
  });

  it("says when the service is down", async () => {
    const store = make();
    await store.load("web");
    api.down = true;
    const down = { ok: false, message: "puddle's service isn't answering." };
    expect(await store.attach(2)).toEqual(down);
    expect(await store.detach(1)).toEqual(down);
    expect(await store.setIdentities([1])).toEqual(down);
    expect(await store.setSwitches({ only_push_listed: false })).toEqual(down);
    expect(await store.setToggles(repoRow(7), true, true)).toEqual(down);
    expect(await store.removeRepo(repoRow(7))).toEqual(down);
    expect(
      await store.addRepo({
        host: "github.com",
        owner: "a",
        repo: "b",
        pull: true,
        push: true,
      }),
    ).toEqual(down);
  });
});

describe("switches and the table", () => {
  it("sets either switch", async () => {
    const store = make();
    await store.load("web");
    await store.setSwitches({ only_pull_listed: true });
    expect(store.git).toMatchObject({
      only_pull_listed: true,
      only_push_listed: true,
    });
    await store.setSwitches({ only_push_listed: false });
    expect(store.git).toMatchObject({
      only_pull_listed: true,
      only_push_listed: false,
    });
  });

  it("lists a repository, and refuses one that is already there", async () => {
    const store = make();
    await store.load("web");
    const row = {
      host: "github.com",
      owner: "acme",
      repo: "billing",
      pull: true,
      push: false,
    };
    expect((await store.addRepo(row)).ok).toBe(true);
    expect(store.git?.repos.map((r) => r.repo)).toEqual(["repo-7", "billing"]);
    expect(await store.addRepo(row)).toEqual({
      ok: false,
      message: "That repository is already listed.",
    });
  });

  it("changes a row's toggles and removes a row; a row already gone counts as removed", async () => {
    const store = make();
    await store.load("web");
    const row = store.git!.repos[0]!;
    expect((await store.setToggles(row, false, true)).ok).toBe(true);
    expect(store.git?.repos[0]).toMatchObject({ pull: false, push: true });
    expect(await store.setToggles(repoRow(404), true, true)).toEqual({
      ok: false,
      message: "Refused.",
    });
    expect((await store.removeRepo(row)).ok).toBe(true);
    expect(store.git?.repos).toEqual([]);
    expect((await store.removeRepo(row)).ok).toBe(true);
    api.refuse = { status: 500, message: "x" };
    expect(await store.removeRepo(repoRow(1))).toEqual({
      ok: false,
      message: "puddle couldn't remove the repository.",
    });
  });
});
