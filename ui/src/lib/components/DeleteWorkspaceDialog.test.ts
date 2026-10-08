// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanCheck, dirtyCheck } from "#lib/testing/fake-workspaces.ts";
import DeleteWorkspaceDialog from "./DeleteWorkspaceDialog.svelte";

afterEach(cleanup);

function mount(over: Record<string, unknown> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(DeleteWorkspaceDialog, {
    props: {
      open: true,
      name: "demo",
      check: dirtyCheck("demo"),
      onConfirm,
      onCancel,
      ...over,
    },
  } as never);
  return { onConfirm, onCancel };
}

const remove = () =>
  screen.getByRole("button", { name: /^Delete workspace|Deleting/ });

describe("DeleteWorkspaceDialog", () => {
  it("is an alert dialog naming the workspace and listing what would be lost", async () => {
    mount();
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveAccessibleName("Delete demo?");
    expect(dialog).toHaveTextContent("Uncommitted changes");
    expect(dialog).toHaveTextContent("M a.md");
    expect(dialog).toHaveTextContent("and 3 more");
    expect(dialog).toHaveTextContent("abc123 Fix it");
    expect(dialog).toHaveTextContent("Files outside any repository");
    expect(dialog).toHaveTextContent("scratch");
  });

  it("shows guest text as text, never as markup", async () => {
    mount({
      check: {
        ...dirtyCheck("demo"),
        other: { items: ["<img src=x onerror=alert(1)>"], more: 0 },
      },
    });
    await screen.findByRole("alertdialog");
    expect(document.querySelector("img")).toBeNull();
    expect(
      screen.getByText("<img src=x onerror=alert(1)>"),
    ).toBeInTheDocument();
  });

  it("puts focus on Cancel and needs the box ticked before it deletes", async () => {
    const { onConfirm } = mount();
    const cancel = await screen.findByRole("button", { name: "Cancel" });
    await vi.waitFor(() => expect(cancel).toHaveFocus());
    expect(remove()).toBeDisabled();
    await fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I understand this work will be lost/,
      }),
    );
    expect(remove()).toBeEnabled();
    await fireEvent.click(remove());
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("says nothing was found for a clean check, and still asks", async () => {
    mount({ check: cleanCheck("demo") });
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("found nothing unsaved");
    expect(dialog).not.toHaveTextContent("You would lose");
    expect(remove()).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "Delete demo and its disk" }),
    ).not.toBeChecked();
  });

  it("says a missing volume loses nothing, and still asks", async () => {
    mount({ check: cleanCheck("demo", { volume_missing: true }) });
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("volume is already gone");
    expect(dialog).not.toHaveTextContent("everything on its disk");
    expect(remove()).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "Delete demo" }),
    ).not.toBeChecked();
  });

  it("says what could not be checked, and counts that as a risk", async () => {
    mount({
      check: cleanCheck("demo", {
        clean: false,
        errors: ["git failed in demo"],
      }),
    });
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("puddle couldn't check everything");
    expect(dialog).toHaveTextContent("git failed in demo");
    expect(dialog).toHaveTextContent("not everything could be checked");
    expect(
      screen.getByRole("checkbox", {
        name: /I understand this work will be lost/,
      }),
    ).toBeInTheDocument();
  });

  it("shows why the last attempt failed", async () => {
    mount({ error: "the workspace changed" });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "the workspace changed",
    );
  });

  it("disables the button and says so while deleting", async () => {
    mount({ working: true });
    await screen.findByRole("alertdialog");
    expect(screen.getByRole("button", { name: "Deleting…" })).toBeDisabled();
  });

  it("cancels with the Cancel button", async () => {
    const { onCancel } = mount();
    await fireEvent.click(
      await screen.findByRole("button", { name: "Cancel" }),
    );
    expect(onCancel).toHaveBeenCalled();
  });

  it("asks again after a new check: the box is unticked", async () => {
    const { rerender } = render(DeleteWorkspaceDialog, {
      props: {
        open: true,
        name: "demo",
        check: dirtyCheck("demo"),
        onConfirm: vi.fn(),
        onCancel: vi.fn(),
      },
    } as never);
    const box = await screen.findByRole("checkbox");
    await fireEvent.click(box);
    expect(box).toBeChecked();
    await rerender({
      check: { ...dirtyCheck("demo"), fingerprint: "fp-new" },
    } as never);
    await vi.waitFor(() =>
      expect(screen.getByRole("checkbox")).not.toBeChecked(),
    );
  });
});
