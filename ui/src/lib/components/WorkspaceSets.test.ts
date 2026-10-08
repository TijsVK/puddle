// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  FakeRuleSets,
  builtIn,
  mine,
  systemHost,
} from "#lib/testing/fake-rule-sets.ts";
import { RuleSetsStore } from "#lib/stores/rule-sets.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import WorkspaceSets from "./WorkspaceSets.svelte";

let api: FakeRuleSets;
let store: RuleSetsStore;

beforeEach(async () => {
  api = new FakeRuleSets();
  api.sets = [
    builtIn("github", { name: "GitHub" }),
    mine(4, {
      name: "Work",
      overrides: [{ workspace: "api" as never, enabled: false }],
    }),
  ];
  api.system = [
    systemHost("open-vsx.org"),
    systemHost("marketplace.visualstudio.com", {
      reason: "direct_ssh",
      reason_text: "Direct SSH is on for this workspace.",
      workspace: "other" as never,
    }),
  ];
  store = new RuleSetsStore({ api: api as never });
  await store.refresh();
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

describe("a workspace's rule sets", () => {
  it("shows each set's state there and only the System managed hosts that apply", () => {
    render(WorkspaceSets, { props: { store, workspace: "api" } } as never);
    expect(screen.getByText("Off, as for every workspace")).toBeInTheDocument();
    expect(
      screen.getByText("Off here", { selector: ".muted" }),
    ).toBeInTheDocument();
    const system = screen.getByRole("region", { name: "System managed" });
    expect(within(system).getByText("open-vsx.org")).toBeInTheDocument();
    expect(
      within(system).queryByText("marketplace.visualstudio.com"),
    ).toBeNull();
  });

  it("switches a set there, and back to following every workspace", async () => {
    render(WorkspaceSets, { props: { store, workspace: "api" } } as never);
    await fireEvent.click(
      screen.getByRole("button", { name: "Turn GitHub on in api" }),
    );
    await waitFor(() =>
      expect(toasts.items.at(-1)?.message).toBe("GitHub: on in api."),
    );
    api.closes = [1, 2];
    await fireEvent.click(
      screen.getByRole("button", {
        name: "Make Work in api follow every workspace",
      }),
    );
    await waitFor(() =>
      expect(toasts.items.at(-1)?.message).toBe(
        "Work: follows every workspace in api; it decided 2 waiting requests.",
      ),
    );
    api.refuse = { status: 500, message: "boom" };
    await fireEvent.click(
      screen.getByRole("button", { name: "Turn Work off in api" }),
    );
    await waitFor(() => expect(toasts.items.at(-1)?.message).toBe("Boom."));
  });

  it("says when nothing is allowed by puddle itself", () => {
    store.system = [];
    render(WorkspaceSets, { props: { store, workspace: "api" } } as never);
    expect(
      screen.getByText("Puddle allows nothing by itself right now."),
    ).toBeInTheDocument();
  });
});
