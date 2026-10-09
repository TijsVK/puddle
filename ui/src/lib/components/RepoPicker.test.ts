// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { identity } from "#lib/testing/fake-identities.ts";
import { FakeRepos, repoSource, repoView } from "#lib/testing/fake-repos.ts";
import { RepoLists } from "#lib/stores/repos.svelte.ts";
import RepoPicker from "./RepoPicker.svelte";

const work = identity(1, { label: "Work" });
const personal = identity(2, { label: "Personal" });
let api: FakeRepos;

beforeEach(() => {
  api = new FakeRepos();
  api.repos = [
    repoView("acme", "web", { identities: [1, 2], role: "admin" }),
    repoView("tijs", "dotfiles", { identities: [2], visibility: "public" }),
  ];
  api.sources = [repoSource({ repo_count: 2 })];
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function show() {
  const store = new RepoLists({ api: api as never, now: () => 5_000_000 });
  const onPick = vi.fn();
  render(RepoPicker, {
    props: { identities: [work, personal], onPick, store },
  } as never);
  return { store, onPick };
}

async function open() {
  await fireEvent.click(screen.getByText("Choose from your repositories"));
  return screen.findByLabelText("Search your repositories");
}

/** Opens it while timers are faked (the testing library's own waits would never end). */
async function openFaked() {
  await fireEvent.click(screen.getByText("Choose from your repositories"));
  await vi.advanceTimersByTimeAsync(10);
  return screen.getByLabelText("Search your repositories");
}

describe("RepoPicker", () => {
  it("reads nothing until it is opened", () => {
    show();
    expect(api.calls).toHaveLength(0);
    expect(screen.queryByLabelText("Search your repositories")).toBeNull();
  });

  it("lists the repositories of every identity once opened, with who listed them", async () => {
    show();
    await open();
    const web = await screen.findByRole("button", { name: /acme\/web/ });
    expect(web).toHaveTextContent("private · admin · listed by Work, Personal");
    expect(
      screen.getByRole("button", { name: /tijs\/dotfiles/ }),
    ).toHaveTextContent("public · write · listed by Personal");
    expect(screen.getByRole("status")).toHaveTextContent("2 repositories.");
    expect(api.queries[0]).toEqual({ limit: 20 });
  });

  it("hands the pick to the form with the identity that listed it first", async () => {
    const { onPick } = show();
    await open();
    await fireEvent.click(
      await screen.findByRole("button", { name: /acme\/web/ }),
    );
    expect(onPick).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://github.com/acme/web" }),
      1,
    );
  });

  it("hands over no identity when the list names none", async () => {
    api.repos = [repoView("acme", "web", { identities: [] })];
    const { onPick } = show();
    await open();
    await fireEvent.click(
      await screen.findByRole("button", { name: /acme\/web/ }),
    );
    expect(onPick.mock.calls[0]?.[1]).toBeNull();
  });

  it("narrows by words after a pause and says when nothing matches", async () => {
    vi.useFakeTimers();
    show();
    const search = await openFaked();
    await fireEvent.input(search, { target: { value: "zzz" } });
    await vi.advanceTimersByTimeAsync(300);
    expect(api.queries.at(-1)).toEqual({ query: "zzz", limit: 20 });
    expect(screen.getByRole("status")).toHaveTextContent(
      "No repository matches “zzz”.",
    );
  });

  it("says when no identity reaches a repository yet", async () => {
    api.repos = [];
    api.sources = [repoSource()];
    show();
    await open();
    expect(
      await screen.findByText(/None of your identities reaches/),
    ).toBeVisible();
  });

  it("says when the list was cut and asks for more of the name", async () => {
    api.repos = Array.from({ length: 25 }, (_, i) => repoView("acme", `r${i}`));
    show();
    await open();
    expect(
      await screen.findByText(/Showing 20 of 25\. Type more of the name/),
    ).toBeVisible();
  });

  it("shows progress while a list is slow", async () => {
    vi.useFakeTimers();
    api.hold();
    show();
    await openFaked();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Reading the lists from your Git hosts",
    );
    await vi.advanceTimersByTimeAsync(1600);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Still asking your Git hosts",
    );
    api.release();
  });

  it("shows a list that failed or left something out, and a refusal outright", async () => {
    api.sources = [
      repoSource({ notes: [{ code: "truncated", message: "More exist." }] }),
      repoSource({
        credential: 1,
        identity_id: 2,
        state: "failed",
        problem: {
          code: "token_rejected",
          message: "The token was rejected.",
          needs_sign_in: false,
        },
      }),
    ];
    const { store } = show();
    await open();
    expect(await screen.findByText("More exist.")).toBeVisible();
    expect(screen.getByText("The token was rejected.")).toBeVisible();
    api.refuse = { status: 503, message: "repository lists are not available" };
    await store.load({ limit: 20 });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Repository lists are not available.",
    );
  });

  it("warns about a project with a space but still lists it", async () => {
    api.repos = [
      repoView("contoso", "scanner", {
        host: "dev.azure.com",
        full_name: "contoso/Shop Floor/scanner",
        url: "https://dev.azure.com/contoso/Shop%20Floor/_git/scanner",
      }),
    ];
    show();
    await open();
    expect(await screen.findByText(/project name has a space/)).toBeVisible();
  });

  it("stops asking when closed again", async () => {
    const { store } = show();
    await open();
    await screen.findByRole("button", { name: /acme\/web/ });
    const spy = vi.spyOn(store, "stop");
    await fireEvent.click(screen.getByText("Choose from your repositories"));
    await vi.waitFor(() => expect(spy).toHaveBeenCalled());
    expect(screen.queryByLabelText("Search your repositories")).toBeNull();
  });

  it("names an identity it does not know", async () => {
    api.repos = [repoView("acme", "web", { identities: [9] })];
    show();
    await open();
    expect(
      await screen.findByRole("button", { name: /listed by Identity 9/ }),
    ).toBeVisible();
  });
});
