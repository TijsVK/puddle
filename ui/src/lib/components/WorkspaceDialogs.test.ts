// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = await vi.hoisted(async () => {
  const ws = await import("#lib/testing/fake-workspaces.ts");
  return {
    api: new ws.FakeWorkspaces(),
    workspace: ws.workspace,
    dirty: ws.dirtyCheck,
  };
});

vi.mock("#lib/stores/workspaces.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/workspaces.svelte.ts")>();
  return {
    ...mod,
    workspaces: new mod.WorkspaceStore({ api: h.api as never }),
  };
});

import { toasts } from "#lib/stores/toasts.svelte.ts";
import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
import { workspaces } from "#lib/stores/workspaces.svelte.ts";
import WorkspaceDialogs from "./WorkspaceDialogs.svelte";

const { api, workspace, dirty } = h;

beforeEach(async () => {
  api.list = [
    workspace("demo", { status: "running", first_connect_notice_due: true }),
  ];
  api.calls = [];
  api.check = null;
  await workspaces.refresh();
  actions.createOpen = false;
  actions.noticeOpen = false;
  actions.deleteOpen = false;
  actions.deleting = null;
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

describe("WorkspaceDialogs", () => {
  it("draws nothing until an action asks for a dialog", () => {
    render(WorkspaceDialogs);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("opens the create form from the action", async () => {
    render(WorkspaceDialogs);
    actions.openCreate();
    expect(
      await screen.findByRole("dialog", { name: "New workspace" }),
    ).toBeInTheDocument();
  });

  it("says what attaching trusts before the first desktop attach, and opens only after the yes", async () => {
    render(WorkspaceDialogs);
    actions.attach(workspaces.byName("demo")!);
    const dialog = await screen.findByRole("alertdialog", {
      name: "Open demo in VS Code?",
    });
    expect(dialog).toHaveTextContent("makes the workspace trusted");
    expect(dialog).toHaveTextContent("signed-in GitHub token");
    expect(dialog).toHaveTextContent(
      "The browser editor keeps the workspace isolated.",
    );
    expect(api.calls).not.toContain("POST /api/workspaces/{id}/attach");
    await fireEvent.click(
      screen.getByRole("button", { name: "Open in VS Code" }),
    );
    await vi.waitFor(() =>
      expect(api.calls).toContain("POST /api/workspaces/{id}/attach"),
    );
  });

  it("cancelling the notice opens nothing", async () => {
    render(WorkspaceDialogs);
    actions.attach(workspaces.byName("demo")!);
    await fireEvent.click(
      await screen.findByRole("button", { name: "Cancel" }),
    );
    await vi.waitFor(() => expect(actions.noticeFor).toBeNull());
    expect(api.calls).not.toContain("POST /api/workspaces/{id}/attach");
  });

  it("shows the delete check the action read, and deletes after the box is ticked", async () => {
    api.list = [workspace("demo", { status: "stopped" })];
    api.check = dirty("demo");
    await workspaces.refresh();
    render(WorkspaceDialogs);
    await actions.askDelete(workspaces.byName("demo")!);
    const dialog = await screen.findByRole("alertdialog", {
      name: "Delete demo?",
    });
    expect(dialog).toHaveTextContent("Uncommitted changes");
    await fireEvent.click(screen.getByRole("checkbox"));
    await fireEvent.click(
      screen.getByRole("button", { name: "Delete workspace" }),
    );
    await vi.waitFor(() =>
      expect(api.calls).toContain("DELETE /api/workspaces/{id}"),
    );
    expect(toasts.items.at(-1)?.message).toBe("Deleting demo.");
  });
});
