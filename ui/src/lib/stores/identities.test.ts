// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  credential,
  FakeIdentities,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import { describeSource } from "#lib/identities/model.ts";
import { IdentitiesStore } from "./identities.svelte.ts";

let api: FakeIdentities;
let source: FakeSource;

function make(pollMs = 60_000) {
  return new IdentitiesStore({ api: api as never, source, pollMs });
}

const request = (label: string) => ({
  label,
  author: { name: label, email: `${label.toLowerCase()}@example.com` },
  credentials: [credential()],
});

beforeEach(() => {
  api = new FakeIdentities();
  source = new FakeSource();
});
afterEach(() => vi.useRealTimers());

describe("reading", () => {
  it("loads the identities in order", async () => {
    api.identities = [identity(1), identity(2)];
    const store = make();
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.identities.map((i) => i.id)).toEqual([1, 2]);
    expect(store.byId(2)?.id).toBe(2);
    expect(store.byId(9)).toBeUndefined();
  });

  it("fails the first read quietly and keeps what it has later", async () => {
    api.down = true;
    const store = make();
    await store.refresh();
    expect(store.status).toBe("failed");
    api.down = false;
    api.identities = [identity(1)];
    await store.refresh();
    expect(store.status).toBe("ready");
    api.down = true;
    await store.refresh();
    expect(store.status).toBe("ready");
    expect(store.identities).toHaveLength(1);
  });

  it("keeps the list when a later read is refused", async () => {
    api.identities = [identity(1)];
    const store = make();
    await store.refresh();
    const real = api.GET;
    api.GET = (async () => ({
      response: { status: 500 } as Response,
    })) as never;
    await store.refresh();
    expect(store.identities).toHaveLength(1);
    const fresh = make();
    await fresh.refresh();
    expect(fresh.status).toBe("failed");
    api.GET = real;
  });

  it("finds an identity by the line that names one of its sources", async () => {
    api.identities = [
      identity(1, { credentials: [credential({ source: ghSource("tijs") })] }),
    ];
    const store = make();
    await store.refresh();
    expect(store.bySource("gh account tijs on github.com")?.id).toBe(1);
    expect(store.bySource("gh account other on github.com")).toBeUndefined();
  });
});

describe("changing identities", () => {
  it("makes one, last in the order, and keeps the answer's shape", async () => {
    const store = make();
    const made = await store.create(request("Work"));
    expect(made.ok && made.value.label).toBe("Work");
    expect(store.identities.map((i) => i.label)).toEqual(["Work"]);
  });

  it("shows the host's refusal as a sentence", async () => {
    const store = make();
    await store.create(request("Work"));
    api.refuse = { status: 409, message: "the label is taken" };
    const again = await store.create(request("work"));
    expect(again).toEqual({ ok: false, message: "The label is taken." });
    expect(store.identities).toHaveLength(1);
  });

  it("says the service is down when it is", async () => {
    const store = make();
    api.down = true;
    const down = "puddle's service isn't answering.";
    expect(await store.create(request("A"))).toEqual({
      ok: false,
      message: down,
    });
    expect(await store.update(1, request("A"))).toEqual({
      ok: false,
      message: down,
    });
    expect(await store.remove(1)).toEqual({ ok: false, message: down });
    expect(await store.makeDefault(1)).toEqual({ ok: false, message: down });
    expect(await store.reorder([1])).toEqual({ ok: false, message: down });
    expect(await store.storeToken("github.com", null, "t")).toEqual({
      ok: false,
      message: down,
    });
    expect(await store.signIn(ghSource())).toEqual({
      ok: false,
      message: down,
    });
    expect((await store.checkSource(ghSource())).state).toBe("problem");
    await store.loadFound();
    expect(store.foundStatus).toBe("failed");
    await expect(
      store.forgetToken({ kind: "stored", id: "x", host: "h", org: null }),
    ).resolves.toBeUndefined();
  });

  it("replaces an identity", async () => {
    api.identities = [identity(1), identity(2)];
    const store = make();
    await store.refresh();
    const result = await store.update(2, request("Renamed"));
    expect(result.ok).toBe(true);
    expect(store.identities.map((i) => i.label)).toEqual([
      "Identity 1",
      "Renamed",
    ]);
    api.refuse = { status: 422, message: "bad author" };
    expect(await store.update(2, request("X"))).toEqual({
      ok: false,
      message: "Bad author.",
    });
  });

  it("deletes an identity and says which workspaces lost it; a missing one counts as deleted", async () => {
    api.identities = [identity(1), identity(2)];
    api.git["web"] = { ids: [2], repos: [], push: true, pull: false };
    const store = make();
    await store.refresh();
    expect(await store.remove(2)).toEqual({ ok: true, value: ["web"] });
    expect(store.identities.map((i) => i.id)).toEqual([1]);
    expect(await store.remove(2)).toEqual({ ok: true, value: [] });
    api.refuse = { status: 500, message: "x" };
    expect(await store.remove(1)).toEqual({
      ok: false,
      message: "puddle couldn't delete that identity.",
    });
    expect(store.identities).toHaveLength(1);
  });

  it("sets the default and the order", async () => {
    api.identities = [identity(1), identity(2), identity(3)];
    const store = make();
    await store.refresh();
    expect((await store.makeDefault(3)).ok).toBe(true);
    expect(store.identities.find((i) => i.is_default)?.id).toBe(3);
    expect((await store.reorder([3, 1, 2])).ok).toBe(true);
    expect(store.identities.map((i) => i.id)).toEqual([3, 1, 2]);
    api.refuse = { status: 422, message: "not every identity exactly once" };
    expect(await store.reorder([1])).toEqual({
      ok: false,
      message: "Not every identity exactly once.",
    });
    api.refuse = { status: 404, message: "no such identity" };
    expect(await store.makeDefault(99)).toEqual({
      ok: false,
      message: "No such identity.",
    });
  });
});

describe("credentials", () => {
  it("looks for accounts already signed in", async () => {
    api.found = {
      accounts: [
        {
          via: "gh",
          host: "github.com",
          account: "me",
          org: null,
          signed_in: true,
        },
      ],
      problems: [],
    };
    const store = make();
    expect(store.found).toBeNull();
    await store.loadFound();
    expect(store.foundStatus).toBe("ready");
    expect(store.found?.accounts).toHaveLength(1);
  });

  it("tests a credential and remembers the answer by credential", async () => {
    const cred = credential();
    api.identities = [identity(1, { credentials: [cred] })];
    const store = make();
    await store.refresh();
    expect(store.checkOf(cred).state).toBe("untested");
    const pending = store.check(cred);
    expect(store.checkOf(cred).state).toBe("checking");
    expect((await pending).state).toBe("ok");
    expect(store.checkOf(cred).state).toBe("ok");
    api.unreadable.add(describeSource(cred.source));
    expect(await store.check(cred)).toMatchObject({
      state: "problem",
      needsSignIn: true,
    });
    api.refuse = { status: 500, message: "boom" };
    expect(await store.checkSource(cred.source)).toMatchObject({
      state: "problem",
      message: "Boom.",
      needsSignIn: false,
    });
  });

  it("tests every credential of every identity, one after another", async () => {
    api.identities = [
      identity(1, {
        credentials: [credential(), credential({ source: ghSource("two") })],
      }),
      identity(2),
    ];
    const store = make();
    await store.refresh();
    await store.checkAll();
    expect(
      api.calls.filter((c) => c === "POST /api/credentials/check"),
    ).toHaveLength(3);
    await store.checkAll([]);
    expect(
      api.calls.filter((c) => c === "POST /api/credentials/check"),
    ).toHaveLength(3);
  });

  it("learns from a workspace that a credential needs a sign-in, until it reads", async () => {
    const cred = credential({ source: ghSource("tijs") });
    api.identities = [identity(1, { credentials: [cred] })];
    api.unreadable.add(describeSource(cred.source));
    const store = make();
    await store.refresh();
    const readable: string[] = [];
    const stop = store.onReadable((line) => readable.push(line));
    await store.check(cred);
    store.markSignedOut(describeSource(cred.source));
    expect(store.checkOf(cred)).toMatchObject({
      state: "problem",
      needsSignIn: true,
    });
    // A sign-in, then a check that reads, ends it and tells the listeners.
    await store.signIn(cred.source);
    await store.check(cred);
    expect(store.checkOf(cred).state).toBe("ok");
    expect(store.signedOutLines.size).toBe(0);
    expect(readable).toEqual(["gh account tijs on github.com"]);
    stop();
    await store.check(cred);
    expect(readable).toHaveLength(1);
  });

  it("knows a sign-in is needed even before the identities are read", async () => {
    const cred = credential({ source: ghSource("tijs") });
    const store = make();
    store.markSignedOut(describeSource(cred.source));
    expect(store.checkOf(cred)).toMatchObject({ needsSignIn: true });
    store.markSignedOut(describeSource(cred.source));
    expect(store.signedOutLines.size).toBe(1);
  });

  it("keeps a pasted token and removes it again", async () => {
    const store = make();
    const kept = await store.storeToken(
      "dev.azure.com",
      "contoso",
      "secret-value",
    );
    expect(kept.ok && kept.value).toMatchObject({
      kind: "stored",
      host: "dev.azure.com",
      org: "contoso",
    });
    expect(api.tokens).toHaveLength(1);
    if (kept.ok) await store.forgetToken(kept.value);
    expect(api.tokens).toHaveLength(0);
    // Only a stored source has a token to remove.
    await store.forgetToken(ghSource());
    expect(
      api.calls.filter((c) => c.startsWith("DELETE /api/credentials/stored")),
    ).toHaveLength(1);
    api.refuse = { status: 422, message: "that is not a usable token" };
    expect(await store.storeToken("github.com", null, "a b")).toEqual({
      ok: false,
      message: "That is not a usable token.",
    });
  });

  it("starts a sign-in and passes on what it shows", async () => {
    const store = make();
    expect(await store.signIn(ghSource())).toEqual({
      ok: true,
      value: { code: "ABCD-1234", url: "https://github.com/login/device" },
    });
    api.refuse = {
      status: 422,
      message: "a pasted token has nothing to sign in to",
    };
    expect(
      await store.signIn({ kind: "stored", id: "t", host: "h", org: null }),
    ).toEqual({
      ok: false,
      message: "A pasted token has nothing to sign in to.",
    });
  });
});

describe("staying current", () => {
  it("refetches on identities_changed and on a resync, and stops when asked", async () => {
    api.identities = [identity(1)];
    const store = make();
    const stop = store.start();
    await vi.waitFor(() => expect(store.status).toBe("ready"));
    api.identities = [identity(1), identity(2)];
    source.emit({ type: "identities_changed" });
    await vi.waitFor(() => expect(store.identities).toHaveLength(2));
    api.identities = [identity(3)];
    source.resync();
    await vi.waitFor(() =>
      expect(store.identities.map((i) => i.id)).toEqual([3]),
    );
    source.emit({ type: "rules_changed" });
    stop();
    api.identities = [];
    source.emit({ type: "identities_changed" });
    await Promise.resolve();
    expect(store.identities).toHaveLength(1);
  });

  it("polls slowly as a safety net", async () => {
    vi.useFakeTimers();
    api.identities = [identity(1)];
    const store = make(1000);
    const stop = store.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(store.identities).toHaveLength(1);
    api.identities = [identity(1), identity(2)];
    await vi.advanceTimersByTimeAsync(1100);
    expect(store.identities).toHaveLength(2);
    stop();
    api.identities = [];
    await vi.advanceTimersByTimeAsync(5000);
    expect(store.identities).toHaveLength(2);
  });

  it("works without a live source", async () => {
    const store = new IdentitiesStore({ api: api as never });
    const stop = store.start();
    await vi.waitFor(() => expect(store.status).toBe("ready"));
    stop();
  });
});
