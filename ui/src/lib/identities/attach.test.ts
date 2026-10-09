// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { WorkspaceGitStore } from "#lib/stores/workspace-git.svelte.ts";
import {
  credential,
  FakeIdentities,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { useIdentities } from "./attach.ts";

let api: FakeIdentities;
const label = (id: number) => `L${id}`;
const store = () => new WorkspaceGitStore(api as never);

beforeEach(() => {
  api = new FakeIdentities();
  api.identities = [
    identity(1, {
      credentials: [
        credential({ source: ghSource("a"), owners: ["acme"], rest: false }),
      ],
    }),
    identity(2, {
      credentials: [credential({ source: ghSource("b"), rest: true })],
    }),
    identity(3, {
      credentials: [
        credential({ source: ghSource("c"), owners: ["acme"], rest: false }),
      ],
    }),
  ];
  api.git["w"] = { ids: [1], repos: [], push: true, pull: false };
});

describe("useIdentities", () => {
  it("does nothing when the workspace already has them in order", async () => {
    const result = await useIdentities("w", [1], label, store());
    expect(result).toEqual({ ok: true });
    expect(api.calls.filter((c) => !c.startsWith("GET"))).toEqual([]);
  });

  it("adds the chosen ones and puts them in the form's order", async () => {
    const result = await useIdentities("w", [2, 1], label, store());
    expect(result).toEqual({ ok: true });
    expect(api.git["w"]?.ids).toEqual([2, 1]);
    expect(api.calls).toContain("POST /api/workspaces/{id}/identities");
    expect(api.calls).toContain("PUT /api/workspaces/{id}/identities");
  });

  it("takes off the one the host chose when it was unticked", async () => {
    const result = await useIdentities("w", [2], label, store());
    expect(result).toEqual({ ok: true });
    expect(api.git["w"]?.ids).toEqual([2]);
    expect(api.calls.some((c) => c.startsWith("DELETE"))).toBe(true);
  });

  it("puts no identity on a workspace when none is chosen", async () => {
    const result = await useIdentities("w", [], label, store());
    expect(result).toEqual({ ok: true });
    expect(api.git["w"]?.ids).toEqual([]);
  });

  it("names the identity the host refused", async () => {
    const result = await useIdentities("w", [1, 3], label, store());
    expect(result).toEqual({
      ok: false,
      message: expect.stringContaining("L3: "),
    });
    expect(result.ok ? "" : result.message).toContain("both cover");
  });

  it("names the identity that could not be taken off", async () => {
    api.refuse = null;
    const git = store();
    await git.load("w");
    api.down = false;
    const failing = {
      load: git.load.bind(git),
      get git() {
        return git.git;
      },
      get status() {
        return git.status;
      },
      attach: git.attach.bind(git),
      setIdentities: git.setIdentities.bind(git),
      detach: async () => ({ ok: false as const, message: "no." }),
    };
    expect(await useIdentities("w", [2], label, failing)).toEqual({
      ok: false,
      message: "L1: no.",
    });
  });

  it("says when the order cannot be set", async () => {
    const git = store();
    const failing = {
      load: git.load.bind(git),
      get git() {
        return git.git;
      },
      get status() {
        return git.status;
      },
      attach: git.attach.bind(git),
      detach: git.detach.bind(git),
      setIdentities: async () => ({ ok: false as const, message: "later." }),
    };
    expect(await useIdentities("w", [2, 1], label, failing)).toEqual({
      ok: false,
      message: "later.",
    });
  });

  it("says when the workspace's identities cannot be read", async () => {
    api.down = true;
    const result = await useIdentities("w", [1], label, store());
    expect(result).toEqual({
      ok: false,
      message: "puddle couldn't read which identities the workspace has.",
    });
  });
});
