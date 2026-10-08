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
import { FakeRuleSets, builtIn, mine } from "#lib/testing/fake-rule-sets.ts";
import { RuleSetsStore } from "#lib/stores/rule-sets.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import RuleSetsSection from "./RuleSetsSection.svelte";

let api: FakeRuleSets;
let store: RuleSetsStore;

beforeEach(async () => {
  api = new FakeRuleSets();
  api.sets = [builtIn("github", { name: "GitHub" }), mine(4, { name: "Work" })];
  store = new RuleSetsStore({ api: api as never });
  await store.refresh();
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

function mount() {
  render(RuleSetsSection, {
    props: {
      store,
      workspaces: [],
      onAddEntry: vi.fn(),
      onDeleteEntry: vi.fn(),
    },
  } as never);
}

const card = (name: string) => screen.getByRole("article", { name });
const lastToast = () => toasts.items.at(-1)?.message;

describe("switching", () => {
  it("turns a set off at once and says how many requests it decided", async () => {
    mount();
    api.closes = [7];
    await fireEvent.click(
      within(card("Work")).getByRole("switch", {
        name: "On for every workspace",
      }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe(
        "Work is off for every workspace; it decided 1 waiting request.",
      ),
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("asks before turning one on everywhere, and does nothing on cancel", async () => {
    mount();
    await fireEvent.click(
      within(card("GitHub")).getByRole("switch", {
        name: "On for every workspace",
      }),
    );
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent(
      "GitHub: allow its 1 entry in every workspace",
    );
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Cancel" }),
    );
    expect(api.calls).not.toContain("PUT /api/rule-sets/{id}/switch");
  });

  it("asks too when a set goes back to a default that is on", async () => {
    store.sets = [mine(4, { name: "Work", global: false })];
    mount();
    await fireEvent.click(
      within(card("Work")).getByRole("button", {
        name: "Back to the default (on)",
      }),
    );
    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  });

  it("shows a refused switch as an error", async () => {
    mount();
    api.refuse = { status: 422, message: "nope" };
    await fireEvent.click(
      within(card("Work")).getByRole("switch", {
        name: "On for every workspace",
      }),
    );
    await waitFor(() => expect(lastToast()).toBe("Nope."));
  });
});

describe("making, renaming and deleting", () => {
  it("makes a set from the dialog, and keeps the dialog open on a refusal", async () => {
    mount();
    await fireEvent.click(screen.getByRole("button", { name: "New rule set" }));
    let dialog = await screen.findByRole("dialog", { name: "New rule set" });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Make rule set" }),
    );
    expect(within(dialog).getByRole("alert")).toHaveTextContent(
      "Give the rule set a name.",
    );
    api.refuse = { status: 422, message: "another rule set has this name" };
    await fireEvent.input(within(dialog).getByLabelText("Name"), {
      target: { value: "Work" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Make rule set" }),
    );
    await waitFor(() =>
      expect(within(dialog).getByRole("alert")).toHaveTextContent(
        "Another rule set has this name.",
      ),
    );
    await fireEvent.input(within(dialog).getByLabelText("Name"), {
      target: { value: "Client X" },
    });
    await fireEvent.input(
      within(dialog).getByLabelText("Description (optional)"),
      { target: { value: "their tenant" } },
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Make rule set" }),
    );
    await waitFor(() => expect(lastToast()).toBe("Made rule set Client X."));
    expect(
      screen.getByRole("article", { name: "Client X" }),
    ).toBeInTheDocument();
    // Rename: the dialog starts from the current name.
    await fireEvent.click(
      within(card("Client X")).getByRole("button", { name: "Rename" }),
    );
    dialog = await screen.findByRole("dialog", { name: "Rename rule set" });
    expect(within(dialog).getByLabelText("Name")).toHaveValue("Client X");
    await fireEvent.input(within(dialog).getByLabelText("Name"), {
      target: { value: "Client Y" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(lastToast()).toBe("Renamed to Client Y."));
  });

  it("deletes a set after asking", async () => {
    mount();
    await fireEvent.click(
      within(card("Work")).getByRole("button", { name: "Delete set" }),
    );
    await fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Cancel",
      }),
    );
    expect(api.calls).not.toContain("DELETE /api/rule-sets/{id}");
    await fireEvent.click(
      within(card("Work")).getByRole("button", { name: "Delete set" }),
    );
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent("Work and its 0 entries");
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Delete rule set" }),
    );
    await waitFor(() => expect(lastToast()).toBe("Deleted rule set Work."));
    expect(screen.queryByRole("article", { name: "Work" })).toBeNull();
  });
});

describe("loading", () => {
  it("says when it is loading or can't read the sets", () => {
    const fresh = new RuleSetsStore({ api: api as never });
    render(RuleSetsSection, {
      props: {
        store: fresh,
        workspaces: [],
        onAddEntry: vi.fn(),
        onDeleteEntry: vi.fn(),
      },
    } as never);
    expect(screen.getByText(/Loading rule sets/)).toBeInTheDocument();
    fresh.status = "failed";
  });
});
