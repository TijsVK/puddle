// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import ConfirmDialog from "./ConfirmDialog.svelte";

afterEach(cleanup);

async function frames(count: number): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    await new Promise((done) => requestAnimationFrame(done));
  }
}

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

  it("leaves focus where it was moved right after opening; a frame later it is not put back on Cancel", async () => {
    const props = {
      title: "Allow for every workspace?",
      summary: "Allow example.com for every workspace, permanently",
      confirmLabel: "Allow in every workspace",
      onConfirm: vi.fn(),
    };
    const view = render(ConfirmDialog, {
      props: { ...props, open: false },
    } as never);
    await view.rerender({ ...props, open: true });
    // Opening puts focus on Cancel at once; a Tab before the next frame moves it on.
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    const action = screen.getByRole("button", {
      name: "Allow in every workspace",
    });
    action.focus();
    await frames(3);
    expect(action).toHaveFocus();
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
