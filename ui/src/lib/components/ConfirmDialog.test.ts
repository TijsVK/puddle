// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import ConfirmDialog from "./ConfirmDialog.svelte";

afterEach(cleanup);

function mount(over: Record<string, unknown> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(ConfirmDialog, {
    props: {
      open: true,
      title: "Allow for every workspace?",
      summary: "Allow example.com for every workspace, permanently",
      detail: "This covers workspaces you create later.",
      confirmLabel: "Allow in every workspace",
      onConfirm,
      onCancel,
      ...over,
    },
  } as never);
  return { onConfirm, onCancel };
}

describe("ConfirmDialog", () => {
  it("is an alert dialog that names what will happen", async () => {
    mount();
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveAccessibleName("Allow for every workspace?");
    expect(dialog).toHaveTextContent(
      "Allow example.com for every workspace, permanently",
    );
    expect(dialog).toHaveTextContent(
      "This covers workspaces you create later.",
    );
  });

  it("confirms with the action button", async () => {
    const { onConfirm, onCancel } = mount();
    await fireEvent.click(
      await screen.findByRole("button", { name: "Allow in every workspace" }),
    );
    expect(onConfirm).toHaveBeenCalledOnce();
    expect(onCancel).not.toHaveBeenCalled();
    // The action button does not close a bits-ui alert dialog by itself; this one does.
    await vi.waitFor(() =>
      expect(screen.queryByRole("alertdialog")).toBeNull(),
    );
  });

  it("cancels with Cancel and with Escape, and focuses Cancel first", async () => {
    const { onConfirm, onCancel } = mount();
    const cancel = await screen.findByRole("button", { name: "Cancel" });
    await vi.waitFor(() => expect(cancel).toHaveFocus());
    await fireEvent.keyDown(cancel, { key: "Escape" });
    await vi.waitFor(() => expect(onCancel).toHaveBeenCalled());
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("works without a cancel callback and without detail", async () => {
    render(ConfirmDialog, {
      props: {
        open: true,
        title: "T",
        summary: "S",
        confirmLabel: "Go",
        tone: "deny",
        onConfirm: () => undefined,
      },
    } as never);
    await fireEvent.click(
      await screen.findByRole("button", { name: "Cancel" }),
    );
    await vi.waitFor(() =>
      expect(screen.queryByRole("alertdialog")).toBeNull(),
    );
  });
});
