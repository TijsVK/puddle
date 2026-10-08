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

const h = await vi.hoisted(async () => {
  const fake = await import("#lib/testing/fake-identities.ts");
  return { api: new fake.FakeIdentities(), fake };
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
import Page from "./+page.svelte";

const { api } = h;

beforeEach(() => {
  api.identities = [
    identity(1, {
      label: "Work",
      credentials: [
        credential({
          source: ghSource("tijs-work"),
          owners: ["acme"],
          rest: false,
        }),
      ],
    }),
    identity(2, {
      label: "Personal",
      is_default: false,
      credentials: [credential({ source: ghSource("tijs") })],
    }),
    identity(3, { label: "Commits only", is_default: false, credentials: [] }),
  ];
  api.git = {
    "web-shop": { ids: [1], repos: [], push: true, pull: false },
    docs: { ids: [1], repos: [], push: true, pull: false },
  };
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.refuse = null;
  api.tokens = [];
  api.unreadable.clear();
  store.identities = [];
  store.status = "loading";
  store.checks = {};
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

const rows = () =>
  screen
    .getAllByRole("listitem")
    .filter((li) => li.hasAttribute("data-identity-id"));
const row = (label: string) =>
  rows().find((r) => within(r).queryByRole("heading", { name: label }))!;
const lastToast = () => toasts.items.at(-1)?.message;

describe("the identities list", () => {
  it("shows each identity with its author, credentials, default badge and use", async () => {
    render(Page);
    expect(
      await screen.findByRole("heading", { level: 1, name: "Identities" }),
    ).toBeInTheDocument();
    await screen.findByText("Commits only");
    expect(
      rows().map((r) => within(r).getByRole("heading").textContent),
    ).toEqual(["Work", "Personal", "Commits only"]);
    const work = within(row("Work"));
    expect(work.getByText("Default")).toBeInTheDocument();
    expect(work.getByText("Name 1 <id1@example.com>")).toBeInTheDocument();
    expect(
      work.getByText("gh · tijs-work · github.com: acme"),
    ).toBeInTheDocument();
    expect(work.getByText("Used by 2 workspaces")).toBeInTheDocument();
    expect(work.getByText("Not tested")).toBeInTheDocument();
    expect(within(row("Personal")).queryByText("Default")).toBeNull();
    expect(
      within(row("Commits only")).getByText("No credentials: commits only."),
    ).toBeInTheDocument();
    expect(work.getByRole("link", { name: "Work" })).toHaveAttribute(
      "href",
      "/identities/1",
    );
  });

  it("says what an empty list means, and when it cannot be read", async () => {
    api.identities = [];
    render(Page);
    expect(await screen.findByText("No identities yet")).toBeInTheDocument();
    cleanup();
    store.status = "loading";
    api.down = true;
    render(Page);
    expect(
      await screen.findByText(/Couldn't read the identities yet/),
    ).toBeInTheDocument();
  });

  it("shows loading before the first answer", () => {
    render(Page);
    expect(screen.getByText(/Loading identities/)).toBeInTheDocument();
  });

  it("tests every credential and shows each status", async () => {
    api.unreadable.add("gh account tijs on github.com");
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(screen.getByRole("button", { name: "Test all" }));
    await waitFor(() =>
      expect(within(row("Work")).getByText("OK")).toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(
        within(row("Personal")).getByText("Sign in needed"),
      ).toBeInTheDocument(),
    );
    expect(
      await screen.findByRole("button", { name: "Test all" }),
    ).toBeEnabled();
  });

  it("sets another identity as the default and says so", async () => {
    render(Page);
    await screen.findByText("Work");
    expect(
      within(row("Work")).queryByRole("button", { name: /as default/ }),
    ).toBeNull();
    await fireEvent.click(
      within(row("Personal")).getByRole("button", {
        name: "Set Personal as default",
      }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("Personal is now the default."),
    );
    await waitFor(() =>
      expect(within(row("Personal")).getByText("Default")).toBeInTheDocument(),
    );
    api.refuse = { status: 404, message: "no such identity" };
    await fireEvent.click(
      within(row("Work")).getByRole("button", { name: "Set Work as default" }),
    );
    await waitFor(() => expect(lastToast()).toBe("No such identity."));
  });

  it("moves an identity up or down and keeps focus on a button that still works", async () => {
    render(Page);
    await screen.findByText("Work");
    expect(
      within(row("Work")).getByRole("button", { name: "Move Work up" }),
    ).toBeDisabled();
    expect(
      within(row("Commits only")).getByRole("button", {
        name: "Move Commits only down",
      }),
    ).toBeDisabled();
    const down = within(row("Work")).getByRole("button", {
      name: "Move Work down",
    });
    down.focus();
    await fireEvent.click(down);
    await waitFor(() =>
      expect(
        rows().map((r) => within(r).getByRole("heading").textContent),
      ).toEqual(["Personal", "Work", "Commits only"]),
    );
    const last = within(row("Work")).getByRole("button", {
      name: "Move Work down",
    });
    last.focus();
    await fireEvent.click(last);
    await waitFor(() =>
      expect(
        within(row("Work")).getByRole("button", { name: "Move Work down" }),
      ).toBeDisabled(),
    );
    await waitFor(() =>
      expect(
        within(row("Work")).getByRole("button", { name: "Move Work up" }),
      ).toHaveFocus(),
    );
    api.refuse = { status: 422, message: "not every identity exactly once" };
    await fireEvent.click(
      within(row("Work")).getByRole("button", { name: "Move Work up" }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("Not every identity exactly once."),
    );
  });

  it("asks before deleting, names the workspaces that lose it, and removes its tokens", async () => {
    api.tokens = ["tok-1"];
    api.identities[0] = {
      ...api.identities[0]!,
      credentials: [
        credential({
          source: {
            kind: "stored",
            id: "tok-1",
            host: "github.com",
            org: null,
          },
        }),
      ],
    };
    api.git = { "web-shop": { ids: [1], repos: [], push: true, pull: false } };
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(
      within(row("Work")).getByRole("button", { name: "Delete Work" }),
    );
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent("Delete Work?");
    expect(confirm).toHaveTextContent("web-shop will lose it");
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Cancel" }),
    );
    expect(api.identities).toHaveLength(3);
    await fireEvent.click(
      within(row("Work")).getByRole("button", { name: "Delete Work" }),
    );
    await fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Delete Work",
      }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("Deleted Work; it was taken off web-shop."),
    );
    expect(api.identities.map((i) => i.label)).toEqual([
      "Personal",
      "Commits only",
    ]);
    expect(api.tokens).toEqual([]);
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveFocus(),
    );
  });

  it("waits for the confirm dialog to finish closing before it moves focus", async () => {
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(
      within(row("Commits only")).getByRole("button", {
        name: "Delete Commits only",
      }),
    );
    const confirm = await screen.findByRole("alertdialog");
    // A dialog that is slow to leave the page, as the real one is while it fades.
    const lingering = document.createElement("div");
    lingering.setAttribute("role", "dialog");
    document.body.append(lingering);
    setTimeout(() => lingering.remove(), 60);
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Delete Commits only" }),
    );
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveFocus(),
    );
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("deletes an identity nobody uses without naming workspaces", async () => {
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(
      within(row("Commits only")).getByRole("button", {
        name: "Delete Commits only",
      }),
    );
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent("No workspace uses it");
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Delete Commits only" }),
    );
    await waitFor(() => expect(lastToast()).toBe("Deleted Commits only."));
  });

  it("keeps the identity when the delete is refused", async () => {
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(
      within(row("Personal")).getByRole("button", { name: "Delete Personal" }),
    );
    api.refuse = { status: 500, message: "x" };
    await fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Delete Personal",
      }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe("puddle couldn't delete that identity."),
    );
    expect(api.identities).toHaveLength(3);
  });

  it("adds an identity from the dialog", async () => {
    render(Page);
    await screen.findByText("Work");
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    const dialog = await screen.findByRole("dialog");
    await fireEvent.input(within(dialog).getByLabelText("Identity name"), {
      target: { value: "Fresh" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Author name"), {
      target: { value: "F" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Author email"), {
      target: { value: "f@b.example" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add identity" }),
    );
    await waitFor(() => expect(lastToast()).toBe("Added Fresh."));
    expect(
      within(row("Fresh")).getByText("No credentials: commits only."),
    ).toBeInTheDocument();
  });

  it("disables Test all with nothing to test", async () => {
    api.identities = [];
    render(Page);
    await screen.findByText("No identities yet");
    expect(screen.getByRole("button", { name: "Test all" })).toBeDisabled();
  });
});
