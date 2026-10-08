// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FakeSource } from "#lib/testing/fake-inbox.ts";
import {
  FakeIdentities,
  identity,
  repoRow,
} from "#lib/testing/fake-identities.ts";
import { IdentitiesStore } from "#lib/stores/identities.svelte.ts";
import { CredentialNotices } from "./credentials.ts";
import { InAppNotifier } from "./notifier.ts";
import { NoticeCenter } from "./notices.svelte.ts";
import { NoticeWatcher } from "./watcher.ts";

let api: FakeIdentities;
let center: NoticeCenter;
let store: IdentitiesStore;
let notices: CredentialNotices;

const signIn = {
  type: "credential_sign_in_needed",
  host: "github.com",
  source: "gh account me on github.com",
} as const;
const denied = (access: "push" | "pull") =>
  ({
    type: "git_access_denied",
    workspace: "web",
    host: "github.com",
    owner: "acme",
    repo: "billing",
    access,
  }) as const;
const only = () => {
  expect(center.items).toHaveLength(1);
  return center.items[0]!;
};

beforeEach(() => {
  api = new FakeIdentities();
  center = new NoticeCenter();
  store = new IdentitiesStore({ api: api as never });
  notices = new CredentialNotices({
    notifier: new InAppNotifier(center),
    identities: store,
    api: api as never,
  });
  api.git["web"] = { ids: [], repos: [], push: true, pull: false };
});

describe("a credential that cannot be read", () => {
  it("raises a notice that links to the identity with the sign-in button, never a window", async () => {
    api.identities = [identity(4)];
    await store.refresh();
    expect(notices.handle(signIn)).toBe(true);
    await vi.waitFor(() => expect(center.items).toHaveLength(1));
    const notice = only();
    expect(notice).toMatchObject({
      key: "sign-in:gh account me on github.com",
      tone: "warning",
      link: { href: "/identities/4", label: "Sign in" },
    });
    expect(notice.title).toContain("gh account me on github.com");
    expect(notice.action).toBeUndefined();
    expect(store.signedOutLines.has(signIn.source)).toBe(true);
  });

  it("reads the identities itself when no screen has, so the link is right on any page", async () => {
    api.identities = [identity(4)];
    notices.handle(signIn);
    await vi.waitFor(() => expect(center.items).toHaveLength(1));
    expect(only().link?.href).toBe("/identities/4");
    expect(api.calls.filter((c) => c === "GET /api/identities")).toHaveLength(
      1,
    );
    notices.handle(signIn);
    await vi.waitFor(() => expect(api.calls.length).toBeGreaterThan(0));
    expect(api.calls.filter((c) => c === "GET /api/identities")).toHaveLength(
      1,
    );
  });

  it("links to the list when no identity has that source, and replaces a repeat", async () => {
    notices.handle(signIn);
    notices.handle(signIn);
    await vi.waitFor(() => expect(center.items).toHaveLength(1));
    expect(only().link?.href).toBe("/identities");
  });

  it("goes away when the credential reads again", async () => {
    const stop = notices.start();
    notices.handle(signIn);
    await vi.waitFor(() => expect(center.items).toHaveLength(1));
    const cred = identity(4).credentials[0]!;
    api.identities = [identity(4)];
    await store.refresh();
    await store.check(cred);
    expect(center.items).toHaveLength(0);
    stop();
  });

  it("ignores events that are not its own", () => {
    expect(notices.handle({ type: "oom_kill" })).toBe(false);
    expect(
      notices.handle({ type: "git_access_denied", workspace: "web" }),
    ).toBe(false);
    expect(center.items).toHaveLength(0);
  });
});

describe("a push or fetch the table refused", () => {
  it("raises a notice naming the repository, with one button for the access refused", () => {
    notices.handle(denied("push"));
    const notice = only();
    expect(notice.title).toBe(
      "web: a push to github.com/acme/billing was refused.",
    );
    expect(notice.action?.label).toBe("Allow push for billing");
    expect(notice.link).toEqual({
      href: "/workspaces/web/git",
      label: "Git tab",
    });
    center.clear();
    notices.handle(denied("pull"));
    expect(only().title).toBe(
      "web: a fetch from github.com/acme/billing was refused.",
    );
  });

  it("lists the repository with just the access asked for", async () => {
    notices.handle(denied("pull"));
    await only().action!.run();
    expect(api.git["web"]!.repos[0]).toMatchObject({
      repo: "billing",
      pull: true,
      push: false,
    });
    expect(only()).toMatchObject({
      tone: "info",
      title: "web may now pull github.com/acme/billing.",
    });
    expect(only().action).toBeUndefined();
  });

  it("turns the access on for a row that is listed without losing the other one", async () => {
    api.git["web"]!.repos = [
      repoRow(9, { owner: "acme", repo: "billing", pull: true, push: false }),
    ];
    notices.handle(denied("push"));
    await only().action!.run();
    expect(api.git["web"]!.repos[0]).toMatchObject({ pull: true, push: true });
    center.clear();
    api.git["web"]!.repos = [
      repoRow(9, { owner: "acme", repo: "billing", pull: false, push: true }),
    ];
    notices.handle(denied("pull"));
    await only().action!.run();
    expect(api.git["web"]!.repos[0]).toMatchObject({ pull: true, push: true });
  });

  it("keeps the notice and says why when it could not list it", async () => {
    notices.handle(denied("push"));
    api.refuse = { status: 409, message: "that repository is already listed" };
    const real = api.GET;
    await only().action!.run();
    // The GET went through; the POST was refused.
    expect(only().tone).toBe("warning");
    expect(only().detail).toContain("That repository is already listed.");
    expect(only().action).toBeDefined();
    api.GET = real;
  });

  it("keeps the notice and says so when the service does not answer", async () => {
    notices.handle(denied("push"));
    api.down = true;
    await only().action!.run();
    expect(only().tone).toBe("warning");
    expect(only().detail).toContain("its service isn't answering");
  });

  it("keeps the notice when the table cannot be read", async () => {
    notices.handle(denied("push"));
    api.GET = (async () => ({
      response: { status: 500 } as Response,
    })) as never;
    await only().action!.run();
    expect(only().tone).toBe("warning");
  });
});

describe("the watcher hands these events over", () => {
  it("raises them from the stream and withdraws a sign-in notice when it reads", async () => {
    const source = new FakeSource();
    api.identities = [identity(4)];
    await store.refresh();
    const watcher = new NoticeWatcher({
      source,
      notifier: new InAppNotifier(center),
      api: {
        GET: async () => ({ data: { workspaces: [] } }),
        POST: vi.fn(),
        PUT: vi.fn(),
      } as never,
      identities: store,
    });
    const stop = watcher.start();
    source.emit(signIn);
    source.emit(denied("push"));
    await vi.waitFor(() => expect(center.items).toHaveLength(2));
    expect(center.items.map((n) => n.key).sort()).toEqual([
      "git-denied:web:push:github.com/acme/billing",
      "sign-in:gh account me on github.com",
    ]);
    await store.check(identity(4).credentials[0]!);
    expect(center.items.map((n) => n.key)).toEqual([
      "git-denied:web:push:github.com/acme/billing",
    ]);
    stop();
  });
});
