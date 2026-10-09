// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const url = vi.hoisted(() => ({ id: "1" }));
vi.mock("$app/state", () => ({
  page: {
    get params() {
      return { id: url.id };
    },
  },
}));
const goto = vi.hoisted(() => vi.fn());
vi.mock("$app/navigation", () => ({ goto }));

const h = await vi.hoisted(async () => {
  const fake = await import("#lib/testing/fake-identities.ts");
  const repos = await import("#lib/testing/fake-repos.ts");
  return { api: new fake.FakeIdentities(), repos: new repos.FakeRepos() };
});

// The page makes its own lists; they read from the stand-in.
vi.mock("#lib/stores/repos.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/repos.svelte.ts")>();
  return {
    ...mod,
    RepoLists: class extends mod.RepoLists {
      constructor() {
        super({ api: h.repos as never });
      }
    },
  };
});

vi.mock("#lib/stores/identities.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/identities.svelte.ts")>();
  return {
    ...mod,
    identities: new mod.IdentitiesStore({
      api: h.api as never,
      pollMs: 60_000,
    }),
  };
});

import { identities as store } from "#lib/stores/identities.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import {
  credential,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { repoSource, repoView } from "#lib/testing/fake-repos.ts";
import { workspaces } from "#lib/stores/workspaces.svelte.ts";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import Page from "./+page.svelte";

const { api } = h;
const WORK = "gh account tijs-work on github.com";

beforeEach(() => {
  url.id = "1";
  goto.mockReset();
  api.identities = [
    identity(1, {
      label: "Work",
      credentials: [
        credential({
          source: ghSource("tijs-work"),
          owners: ["acme"],
          rest: false,
        }),
        credential({
          host: "dev.azure.com",
          source: {
            kind: "stored",
            id: "tok-1",
            host: "dev.azure.com",
            org: "contoso",
          },
          owners: ["contoso"],
          rest: false,
        }),
      ],
    }),
    identity(2, { label: "Personal", is_default: false, credentials: [] }),
  ];
  h.repos.repos = [repoView("acme", "web", { identities: [1, 2] })];
  h.repos.sources = [repoSource({ repo_count: 1 })];
  h.repos.down = false;
  h.repos.refuse = null;
  h.repos.calls = [];
  api.git = { "web-shop": { ids: [1], repos: [], push: true, pull: false } };
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.refuse = null;
  api.tokens = ["tok-1"];
  api.unreadable.clear();
  store.identities = [];
  store.status = "loading";
  store.checks = {};
  store.signedOutLines = new Set();
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

const cred = (line: string) =>
  document.querySelector<HTMLElement>(`[data-credential="${line}"]`)!;
const lastToast = () => toasts.items.at(-1)?.message;

describe("one identity", () => {
  it("shows the author, each credential with what it covers, the repos place and the workspaces", async () => {
    render(Page);
    expect(
      await screen.findByRole("heading", { level: 1, name: "Work" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Name 1 <id1@example.com>")).toBeInTheDocument();
    const gh = within(cred(WORK));
    expect(gh.getByText("gh · tijs-work")).toBeInTheDocument();
    expect(gh.getByText("Covers acme")).toBeInTheDocument();
    expect(gh.getByText("Not tested")).toBeInTheDocument();
    expect(screen.getByTestId("identity-repos")).toHaveTextContent(
      "Repos it can reach",
    );
    expect(
      await screen.findByRole("row", { name: /acme\/web/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-shop" })).toHaveAttribute(
      "href",
      "/workspaces/web-shop/git",
    );
    expect(screen.getByRole("link", { name: "Identities" })).toHaveAttribute(
      "href",
      "/identities",
    );
    expect(screen.getByText(/Default/)).toBeInTheDocument();
  });

  it("tests a credential and says what came of it without showing a value", async () => {
    api.unreadable.add(WORK);
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    await fireEvent.click(
      screen.getByRole("button", { name: "Test gh · tijs-work on github.com" }),
    );
    await waitFor(() =>
      expect(
        within(cred(WORK)).getByText("Sign in needed"),
      ).toBeInTheDocument(),
    );
    expect(within(cred(WORK)).getByRole("status")).toHaveTextContent(
      "not signed in",
    );
    const stored = within(cred("stored token tok-1 for dev.azure.com"));
    await fireEvent.click(
      stored.getByRole("button", { name: /^Test Pasted token/ }),
    );
    await waitFor(() => expect(stored.getByText("OK")).toBeInTheDocument());
    expect(stored.getByRole("status")).toHaveTextContent("never shows it");
    // A pasted token has nothing to sign in to.
    expect(stored.queryByRole("button", { name: /Sign in/ })).toBeNull();
  });

  it("signs in on a click: shows the code, then closes when the credential reads", async () => {
    api.unreadable.add(WORK);
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    expect(api.calls).not.toContain("POST /api/credentials/sign-in");
    await fireEvent.click(
      screen.getByRole("button", { name: "Test gh · tijs-work on github.com" }),
    );
    const signIn = await screen.findByRole("button", {
      name: "Sign in to gh · tijs-work on github.com",
    });
    expect(api.calls).not.toContain("POST /api/credentials/sign-in");
    await fireEvent.click(signIn);
    expect(await screen.findByTestId("sign-in-code")).toHaveTextContent(
      "ABCD-1234",
    );
    expect(api.calls).toContain("POST /api/credentials/sign-in");
  });

  it("checks the credential while the sign-in is open, says when it reads, and closes", async () => {
    api.unreadable.add(WORK);
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    store.markSignedOut(WORK);
    const signIn = await screen.findByRole("button", {
      name: /^Sign in to gh/,
    });
    // Only the dialog's own wait is faked, so the screen's polling can be moved on.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      await fireEvent.click(signIn);
      expect(await screen.findByTestId("sign-in-code")).toHaveTextContent(
        "ABCD-1234",
      );
      await vi.advanceTimersByTimeAsync(3100);
    } finally {
      vi.useRealTimers();
    }
    expect(await screen.findByText("Signed in.")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("says why a sign-in could not start", async () => {
    api.unreadable.add(WORK);
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    store.markSignedOut(WORK);
    api.refuse = { status: 503, message: "gh is not installed or not on PATH" };
    await fireEvent.click(
      await screen.findByRole("button", { name: /^Sign in to gh/ }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Gh is not installed or not on PATH.",
    );
  });

  it("offers Sign in at once for a credential a workspace could not read", async () => {
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    expect(screen.queryByRole("button", { name: /^Sign in to/ })).toBeNull();
    store.markSignedOut(WORK);
    expect(
      await screen.findByRole("button", { name: /^Sign in to gh/ }),
    ).toBeInTheDocument();
  });

  it("edits the identity and gives focus back to the heading", async () => {
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    await fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const dialog = await screen.findByRole("dialog");
    await fireEvent.input(within(dialog).getByLabelText("Author name"), {
      target: { value: "Tijs W." },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(lastToast()).toBe("Saved Work."));
    expect(await screen.findByText(/Tijs W\./)).toBeInTheDocument();
  });

  it("makes it the default", async () => {
    url.id = "2";
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Personal" });
    expect(screen.getByText(/^None\./)).toBeInTheDocument();
    expect(screen.getByText("None yet.")).toBeInTheDocument();
    await fireEvent.click(
      screen.getByRole("button", { name: "Set as default" }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("Personal is now the default."),
    );
    api.refuse = { status: 404, message: "no such identity" };
    await fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    await fireEvent.click(
      await screen.findByRole("button", { name: "Cancel" }),
    );
  });

  it("reports a refused default", async () => {
    url.id = "2";
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Personal" });
    api.refuse = { status: 404, message: "no such identity" };
    await fireEvent.click(
      screen.getByRole("button", { name: "Set as default" }),
    );
    await waitFor(() => expect(lastToast()).toBe("No such identity."));
    expect(toasts.items.at(-1)?.tone).toBe("error");
  });

  it("deletes it after asking, removes its tokens and goes back to the list", async () => {
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent("web-shop will lose it");
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Delete Work" }),
    );
    await waitFor(() => expect(lastToast()).toBe("Deleted Work."));
    expect(goto).toHaveBeenCalledWith("/identities");
    expect(api.tokens).toEqual([]);
  });

  it("keeps the identity when the delete is refused", async () => {
    url.id = "2";
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Personal" });
    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent("No workspace uses it");
    api.refuse = { status: 500, message: "x" };
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Delete Personal" }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("puddle couldn't delete that identity."),
    );
    expect(goto).not.toHaveBeenCalled();
  });

  it("goes back to the list when the identity is deleted elsewhere", async () => {
    render(Page);
    await screen.findByRole("heading", { level: 1, name: "Work" });
    api.identities = api.identities.filter((i) => i.id !== 1);
    await store.refresh();
    await waitFor(() => expect(goto).toHaveBeenCalledWith("/identities"));
    expect(
      screen.getByRole("heading", { name: "No such identity" }),
    ).toBeInTheDocument();
  });

  it("says when there is no such identity, and while it loads or fails", async () => {
    url.id = "99";
    render(Page);
    expect(screen.getByText(/Loading identity/)).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "No such identity" }),
    ).toBeInTheDocument();
    expect(goto).not.toHaveBeenCalled();
    cleanup();
    store.status = "loading";
    api.down = true;
    render(Page);
    expect(
      await screen.findByText(/Couldn't read the identity yet/),
    ).toBeInTheDocument();
  });

  it("opens the create form on this page with the repository and the identity that listed it", async () => {
    render(Page);
    await fireEvent.click(
      await screen.findByRole("button", {
        name: "Create a workspace for acme/web",
      }),
    );
    const dialog = await screen.findByRole("dialog", { name: "New workspace" });
    expect(within(dialog).getByLabelText("Git repository (HTTPS)")).toHaveValue(
      "https://github.com/acme/web",
    );
    expect(within(dialog).getByLabelText("Name")).toHaveValue("web");
    await waitFor(() =>
      expect(
        within(dialog).getByRole("checkbox", { name: /Work/ }),
      ).toBeChecked(),
    );
  });

  it("signs in from a list that says it is signed out", async () => {
    h.repos.sources = [
      repoSource({
        state: "failed",
        problem: {
          code: "not_signed_in",
          message: "Not signed in.",
          needs_sign_in: true,
        },
      }),
    ];
    render(Page);
    await fireEvent.click(
      await screen.findByRole("button", {
        name: "Sign in to gh · tijs-work on github.com",
      }),
    );
    await waitFor(() =>
      expect(api.calls).toContain("POST /api/credentials/sign-in"),
    );
  });

  it("ignores a sign-in for a credential the identity no longer has", async () => {
    h.repos.sources = [
      repoSource({
        credential: 7,
        state: "failed",
        problem: {
          code: "not_signed_in",
          message: "Not signed in.",
          needs_sign_in: true,
        },
      }),
    ];
    render(Page);
    await fireEvent.click(
      await screen.findByRole("button", { name: /Sign in to/ }),
    );
    expect(api.calls).not.toContain("POST /api/credentials/sign-in");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("goes to the new workspace after the form made it, and closes on cancel", async () => {
    const create = vi
      .spyOn(workspaces, "create")
      .mockResolvedValue({ ok: true, value: workspace("web") });
    render(Page);
    await fireEvent.click(
      await screen.findByRole("button", {
        name: "Create a workspace for acme/web",
      }),
    );
    await fireEvent.click(
      await screen.findByRole("button", { name: "Create workspace" }),
    );
    await waitFor(() => expect(goto).toHaveBeenCalledWith("/workspaces/web"));
    expect(create).toHaveBeenCalledWith({
      name: "web",
      repo_url: "https://github.com/acme/web",
    });
    await fireEvent.click(
      await screen.findByRole("button", {
        name: "Create a workspace for acme/web",
      }),
    );
    await fireEvent.click(
      await screen.findByRole("button", { name: "Cancel" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    create.mockRestore();
  });
});
