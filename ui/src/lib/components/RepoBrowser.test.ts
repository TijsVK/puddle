// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  credential,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { FakeRepos, repoSource, repoView } from "#lib/testing/fake-repos.ts";
import { RepoLists } from "#lib/stores/repos.svelte.ts";
import RepoBrowser from "./RepoBrowser.svelte";

const NOW = 5_000_000;
const work = identity(1, {
  label: "Work",
  credentials: [credential({ source: ghSource("tijs-work") })],
});
let api: FakeRepos;

beforeEach(() => {
  api = new FakeRepos();
  api.repos = [
    repoView("acme", "web", { identities: [1, 2], role: "admin" }),
    repoView("acme", "old", { archived: true, fork: true, role: "unknown" }),
  ];
  api.sources = [repoSource({ repo_count: 2, refreshed_at: NOW - 60_000 })];
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function show(over: Record<string, unknown> = {}) {
  const store = new RepoLists({ api: api as never, now: () => NOW });
  const onCreate = vi.fn();
  const onSignIn = vi.fn();
  render(RepoBrowser, {
    props: {
      identity: work,
      store,
      onCreate,
      onSignIn,
      ...over,
    },
  } as never);
  return { store, onCreate, onSignIn };
}

describe("RepoBrowser", () => {
  it("lists what the identity reaches, with traits, role and who else reaches it", async () => {
    await show();
    const web = await screen.findByRole("row", { name: /acme\/web/ });
    expect(within(web).getByText("admin")).toBeVisible();
    const old = screen.getByRole("row", { name: /acme\/old/ });
    expect(within(old).getByText("archived")).toBeVisible();
    expect(within(old).getByText("fork")).toBeVisible();
    expect(screen.getByTestId("repo-summary")).toHaveTextContent(
      "2 repositories.",
    );
    expect(api.queries[0]).toMatchObject({ identity: 1 });
  });

  it("opens the create form for the row's repository", async () => {
    const { onCreate } = await show();
    await fireEvent.click(
      await screen.findByRole("button", {
        name: "Create a workspace for acme/web",
      }),
    );
    expect(onCreate).toHaveBeenCalledWith(
      expect.objectContaining({ full_name: "acme/web" }),
    );
  });

  it("shows progress while the first read is slow", async () => {
    vi.useFakeTimers();
    api.hold();
    await show();
    expect(screen.getByTestId("repo-summary")).toHaveTextContent(
      "Reading the lists from your Git hosts",
    );
    await vi.advanceTimersByTimeAsync(1600);
    expect(screen.getByTestId("repo-summary")).toHaveTextContent(
      "Still asking your Git hosts",
    );
    expect(screen.getByRole("button", { name: /Refresh/ })).toBeDisabled();
    api.release();
    await vi.advanceTimersByTimeAsync(0);
    expect(await screen.findByText("acme/web")).toBeVisible();
  });

  it("says an empty list is empty, not that nothing happened", async () => {
    api.repos = [];
    api.sources = [repoSource()];
    await show();
    expect(await screen.findByTestId("repo-empty")).toHaveTextContent(
      "reaches no repository",
    );
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says an identity without a credential has nothing to list", async () => {
    api.repos = [];
    api.sources = [];
    await show();
    expect(await screen.findByTestId("repo-no-credentials")).toBeVisible();
  });

  it("shows a list's problem and notes beside it and keeps the others usable", async () => {
    api.sources = [
      repoSource({
        credential: 0,
        notes: [{ code: "fine_grained_token", message: "Only granted repos." }],
      }),
      repoSource({
        credential: 1,
        state: "failed",
        problem: {
          code: "not_signed_in",
          message: "Sign in again.",
          needs_sign_in: true,
        },
      }),
    ];
    const { onSignIn } = await show({
      identity: identity(1, {
        credentials: [
          credential({ source: ghSource("tijs-work") }),
          credential({ source: ghSource("tijs-old") }),
        ],
      }),
    });
    expect(await screen.findByText("Only granted repos.")).toBeVisible();
    expect(screen.getByText(/Sign in again\./)).toBeVisible();
    expect(screen.getByRole("table")).toBeVisible();
    await fireEvent.click(
      screen.getByRole("button", { name: /Sign in to gh · tijs-old/ }),
    );
    expect(onSignIn).toHaveBeenCalledWith(1);
  });

  it("warns on an Azure DevOps project with a space and still offers the button", async () => {
    api.repos = [
      repoView("contoso", "scanner", {
        host: "dev.azure.com",
        project: "Shop Floor",
        full_name: "contoso/Shop Floor/scanner",
        url: "https://dev.azure.com/contoso/Shop%20Floor/_git/scanner",
      }),
    ];
    await show();
    expect(await screen.findByTestId("repo-table-warning")).toHaveTextContent(
      "can't hold",
    );
    expect(
      screen.getByRole("button", {
        name: "Create a workspace for contoso/Shop Floor/scanner",
      }),
    ).toBeEnabled();
  });

  it("searches after a pause and says when nothing matches", async () => {
    vi.useFakeTimers();
    await show();
    await vi.advanceTimersByTimeAsync(0);
    const search = screen.getByLabelText("Search these repositories");
    await fireEvent.input(search, { target: { value: "zzz" } });
    await vi.advanceTimersByTimeAsync(300);
    expect(api.queries.at(-1)).toMatchObject({ identity: 1, query: "zzz" });
    expect(screen.getByTestId("repo-summary")).toHaveTextContent(
      "No repository matches “zzz”.",
    );
    expect(screen.queryByRole("table")).toBeNull();
    await fireEvent.input(search, { target: { value: "acme" } });
    await vi.advanceTimersByTimeAsync(300);
    expect(screen.getByTestId("repo-summary")).toHaveTextContent(
      "2 repositories match “acme”.",
    );
  });

  it("refreshes the lists of this identity on a click", async () => {
    await show();
    await fireEvent.click(
      await screen.findByRole("button", { name: /Refresh/ }),
    );
    await vi.waitFor(() =>
      expect(api.refreshBodies).toEqual([{ identity_id: 1 }]),
    );
  });

  it("shows more when the page was cut", async () => {
    api.repos = Array.from({ length: 3 }, (_, i) => repoView("acme", `r${i}`));
    const { store } = await show();
    await screen.findByRole("table");
    store.listing = { ...store.listing!, total: 5 };
    const more = await screen.findByRole("button", {
      name: /Show more \(2 left\)/,
    });
    await fireEvent.click(more);
    await vi.waitFor(() =>
      expect(api.queries.at(-1)).toMatchObject({ offset: 3 }),
    );
  });

  it("says a read that failed outright, and that the old list is the last read", async () => {
    const { store } = await show();
    await screen.findByRole("table");
    api.refuse = { status: 503, message: "repository lists are not available" };
    await store.load({ identity: 1 });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Repository lists are not available. The list below is from the last read.",
    );
  });

  it("says a read that failed with nothing to show", async () => {
    api.refuse = { status: 503, message: "repository lists are not available" };
    await show();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Repository lists are not available.",
    );
    expect(screen.queryByText(/last read/)).toBeNull();
  });
});
