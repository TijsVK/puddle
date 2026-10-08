// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { builtIn, mine } from "#lib/testing/fake-rule-sets.ts";
import type { RuleSet } from "#lib/rules/sets.ts";
import RuleSetCard from "./RuleSetCard.svelte";

afterEach(cleanup);

function mount(set: RuleSet) {
  const props = {
    set,
    workspaces: ["api", "web"],
    onSwitch: vi.fn(),
    onAddEntry: vi.fn(),
    onRename: vi.fn(),
    onDelete: vi.fn(),
    onDeleteEntry: vi.fn(),
  };
  render(RuleSetCard, { props } as never);
  return props;
}

describe("a built-in set", () => {
  it("says what it is, that it ships off, and has no actions of yours", () => {
    mount(builtIn("github", { name: "GitHub", changed_at: 0 }));
    expect(screen.getByRole("article", { name: "GitHub" })).toBeInTheDocument();
    expect(screen.getByText("Built in")).toBeInTheDocument();
    expect(screen.getByText("builtin:github")).toBeInTheDocument();
    expect(screen.getByText(/Updated by puddle/)).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: "On for every workspace" }),
    ).not.toBeChecked();
    expect(
      screen.getByText("Off (built-in sets ship off)"),
    ).toBeInTheDocument();
    expect(screen.getByText("1 entry")).toBeInTheDocument();
    expect(screen.getByText("main host")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rename" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Delete/ })).toBeNull();
  });

  it("asks the page to switch it, and leaves the box as it was until the answer", async () => {
    const props = mount(builtIn("github"));
    const box = screen.getByRole("switch", { name: "On for every workspace" });
    await fireEvent.click(box);
    expect(props.onSwitch).toHaveBeenCalledWith(props.set, null, true);
    expect(box).not.toBeChecked();
  });

  it("switches for one workspace, checking the name first", async () => {
    const props = mount(builtIn("github"));
    await fireEvent.click(screen.getByRole("button", { name: "On there" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Name the workspace");
    expect(props.onSwitch).not.toHaveBeenCalled();
    await fireEvent.input(screen.getByLabelText("Workspace name"), {
      target: { value: "api" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Off there" }));
    expect(props.onSwitch).toHaveBeenCalledWith(props.set, "api", false);
    // Enter in the field submits nothing by itself: the buttons say on or off.
    await fireEvent.submit(
      screen.getByRole("form", { name: "Switch github for one workspace" }),
    );
    expect(props.onSwitch).toHaveBeenCalledTimes(1);
  });

  it("lists the workspaces that switch it, each with a way back", async () => {
    const props = mount(
      builtIn("github", {
        global: true,
        overrides: [{ sandbox: "api" as never, enabled: false }],
      }),
    );
    expect(
      screen.getByRole("list", { name: "Workspaces that switch github" }),
    ).toHaveTextContent("Off in api");
    await fireEvent.click(
      screen.getByRole("button", { name: "Follow every workspace" }),
    );
    expect(props.onSwitch).toHaveBeenCalledWith(props.set, "api", null);
    await fireEvent.click(
      screen.getByRole("button", { name: "Back to the default (off)" }),
    );
    expect(props.onSwitch).toHaveBeenCalledWith(props.set, null, null);
  });
});

describe("a set you made", () => {
  it("has its own actions and entries you can delete", async () => {
    const set = mine(4, {
      name: "Client X",
      description: "their tenant",
      entries: [
        {
          pattern: ".azure.com",
          pattern_kind: "suffix",
          effect: "allow",
          note: "",
          rule_id: 9,
          expires_at: null,
        },
      ],
    });
    const props = mount(set);
    expect(screen.getByText("Yours")).toBeInTheDocument();
    expect(screen.getByText("their tenant")).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: "On for every workspace" }),
    ).toBeChecked();
    await fireEvent.click(screen.getByRole("button", { name: "Add entry" }));
    await fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    await fireEvent.click(screen.getByRole("button", { name: "Delete set" }));
    await fireEvent.click(
      screen.getByRole("button", { name: "Delete *.azure.com from Client X" }),
    );
    expect(props.onAddEntry).toHaveBeenCalledWith(set);
    expect(props.onRename).toHaveBeenCalledWith(set);
    expect(props.onDelete).toHaveBeenCalledWith(set);
    expect(props.onDeleteEntry).toHaveBeenCalledWith(set, set.entries[0]);
  });

  it("says how to fill an empty set", () => {
    mount(mine(4));
    expect(screen.getByText("0 entries")).toBeInTheDocument();
    expect(
      screen.getByText(/approve a request into this set/),
    ).toBeInTheDocument();
  });
});
