// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { asLoginProblem, LoginNotices } from "./logins.ts";
import { InAppNotifier } from "./notifier.ts";
import { NoticeCenter } from "./notices.svelte.ts";
import { NoticeWatcher } from "./watcher.ts";

let center: NoticeCenter;
let notices: LoginNotices;

const problem = (kind: string, service = "Claude Code") => ({
  type: "login_problem",
  workspace: "web",
  service,
  kind,
});

beforeEach(() => {
  center = new NoticeCenter();
  notices = new LoginNotices(new InAppNotifier(center));
});

describe("a login puddle could not capture", () => {
  it.each([
    "store_unavailable",
    "unexpected_answer",
    "unusable_token",
    "bound_token",
  ])("says the login works but is not protected (%s)", (kind) => {
    expect(notices.handle(problem(kind))).toBe(true);
    expect(center.items).toHaveLength(1);
    const notice = center.items[0]!;
    expect(notice).toMatchObject({
      key: `login:web:Claude Code:${kind}`,
      tone: "warning",
      title: "Claude Code login in web is not protected.",
      link: { href: "/workspaces/web/settings", label: "Workspace settings" },
    });
    expect(notice.detail).toContain("real token");
    expect(notice.detail).toMatch(/^[A-Z]/);
  });

  it("names the store as the way out when the store is the problem", () => {
    notices.handle(problem("store_unavailable"));
    expect(center.items[0]!.detail).toContain("credential store");
    expect(center.items[0]!.detail).toContain("sign in again");
  });
});

describe("a login puddle kept and cannot use", () => {
  it("says the tool will ask for a new sign-in when a kept login cannot be read", () => {
    notices.handle(problem("unreadable", "GitHub"));
    const notice = center.items[0]!;
    expect(notice.title).toBe("GitHub login in web can't be used.");
    expect(notice.detail).toContain("ask you to sign in again");
  });

  it("raises one notice for the same problem, not a pile", () => {
    notices.handle(problem("unreadable"));
    notices.handle(problem("unreadable"));
    expect(center.items).toHaveLength(1);
  });
});

describe("events that are not login problems", () => {
  it.each([
    null,
    "text",
    { type: "oom_kill" },
    { type: "login_problem", workspace: "web", service: "GitHub" },
    {
      type: "login_problem",
      workspace: 1,
      service: "GitHub",
      kind: "unreadable",
    },
    { type: "login_problem", workspace: "web", service: "GitHub", kind: "new" },
  ])("are ignored (%j)", (raw) => {
    expect(asLoginProblem(raw)).toBeNull();
    expect(notices.handle(raw)).toBe(false);
    expect(center.items).toHaveLength(0);
  });
});

describe("the notice watcher", () => {
  it("turns the stream's event into the notice", () => {
    const watcher = new NoticeWatcher({ notifier: new InAppNotifier(center) });
    watcher.handle(problem("bound_token", "GitHub"));
    expect(center.items).toHaveLength(1);
    expect(center.items[0]!.title).toBe(
      "GitHub login in web is not protected.",
    );
  });
});
