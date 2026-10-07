// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = await vi.hoisted(async () => {
  const inbox = await import("#lib/testing/fake-inbox.ts");
  const ws = await import("#lib/testing/fake-workspaces.ts");
  return {
    inbox: new inbox.FakeInbox(),
    source: new inbox.FakeSource(),
    request: inbox.request,
    api: new ws.FakeWorkspaces(),
    workspace: ws.workspace,
  };
});

vi.mock("#lib/stores/pending.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/pending.svelte.ts")>();
  return {
    ...mod,
    pending: new mod.PendingStore({
      api: h.inbox as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});
vi.mock("#lib/stores/workspaces.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/workspaces.svelte.ts")>();
  return {
    ...mod,
    workspaces: new mod.WorkspaceStore({
      api: h.api as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});

import { pending } from "#lib/stores/pending.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import { workspaceActions } from "#lib/stores/workspace-actions.svelte.ts";
import { workspaces } from "#lib/stores/workspaces.svelte.ts";
import Layout from "./+layout.svelte";
import ListPage from "./+page.svelte";

const { inbox, source, api, workspace, request } = h;

function reset() {
  inbox.open = [];
  inbox.calls = [];
  inbox.down = false;
  api.list = [];
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.refuse.clear();
  pending.rows = [];
  pending.status = "loading";
  workspaces.list = [];
  workspaces.status = "loading";
  workspaces.progress = {};
  workspaces.oom = {};
  workspaceActions.createOpen = false;
  workspaceActions.connectOpen = false;
  workspaceActions.trustOpen = false;
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
}

beforeEach(reset);
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function mount() {
  const view = render(ListPage);
  await workspaces.refresh();
  await pending.refresh();
  return view;
}

describe("the workspace list", () => {
  it("shows a loading line, then a card per workspace with a count", async () => {
    api.list = [
      workspace("web-shop", { status: "running" }),
      workspace("docs"),
    ];
    render(ListPage);
    expect(screen.getByText(/Loading workspaces/)).toBeInTheDocument();
    await workspaces.refresh();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Workspaces" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(screen.getByText("2 workspaces")).toBeInTheDocument();
    expect(
      screen.getByRole("list", { name: "Workspaces" }),
    ).toBeInTheDocument();
  });

  it("says one workspace in the singular", async () => {
    api.list = [workspace("only")];
    await mount();
    expect(await screen.findByText("1 workspace")).toBeInTheDocument();
  });

  it("says so when the service didn't answer", async () => {
    api.down = true;
    await mount();
    expect(
      await screen.findByText(/Couldn't read the workspaces/),
    ).toBeInTheDocument();
  });

  it("explains what a workspace is when there is none, and offers to make one", async () => {
    await mount();
    expect(
      await screen.findByRole("heading", { name: "No workspaces yet" }),
    ).toBeInTheDocument();
    await fireEvent.click(
      screen.getAllByRole("button", { name: "New workspace" }).at(-1)!,
    );
    expect(workspaceActions.createOpen).toBe(true);
  });

  it("opens the create dialog from the header button", async () => {
    api.list = [workspace("a")];
    await mount();
    await fireEvent.click(
      await screen.findByRole("button", { name: "New workspace" }),
    );
    expect(workspaceActions.createOpen).toBe(true);
  });

  it("starts a workspace from its card", async () => {
    api.list = [workspace("docs")];
    await mount();
    await fireEvent.click(
      await screen.findByRole("button", { name: "Start docs" }),
    );
    await vi.waitFor(() =>
      expect(workspaces.byName("docs")?.busy).toBe("starting"),
    );
    expect(screen.getByRole("article")).toHaveTextContent("Starting");
  });

  it("shows the strip when requests wait, with the newest one, and each card's own count", async () => {
    api.list = [workspace("a"), workspace("b")];
    inbox.add(
      request(1, {
        sandbox: "a" as never,
        host: "old.example.com",
        first_seen: 1,
      }),
      "example.com",
    );
    inbox.add(
      request(2, {
        sandbox: "b" as never,
        host: "new.example.com",
        first_seen: 9,
      }),
      "example.com",
    );
    inbox.add(
      request(3, {
        sandbox: "b" as never,
        host: "newer.example.org",
        first_seen: 5,
      }),
      "example.org",
    );
    await mount();
    const strip = await screen.findByText(/3 requests waiting/);
    expect(strip.closest("[role=status]")).toHaveTextContent(
      "Latest: b wants new.example.com:443",
    );
    expect(screen.getByRole("article", { name: "a" })).toHaveTextContent(
      "1 waiting",
    );
    expect(screen.getByRole("article", { name: "b" })).toHaveTextContent(
      "2 waiting",
    );
  });

  it("has no strip when nothing waits", async () => {
    api.list = [workspace("a")];
    await mount();
    await screen.findByRole("article");
    expect(screen.queryByText(/waiting\./)).toBeNull();
  });

  it("shows the out-of-memory flag and a failure with a Dismiss", async () => {
    api.list = [workspace("a", { status: "running" })];
    await mount();
    workspaces.handleEvent({
      type: "oom_kill",
      sandbox: "a",
      pid: 3,
      process: "node",
    });
    expect(await screen.findByText(/Out of memory/)).toBeInTheDocument();
    workspaces.handleEvent({
      type: "workspace_progress",
      sandbox: "a",
      step: "failed",
      detail: "boom",
    });
    await fireEvent.click(
      await screen.findByRole("button", { name: "Dismiss" }),
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("ticks the relative times every 30 seconds", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(10_000_000);
    api.list = [workspace("a", { created_at: 10_000_000 - 3_600_000 })];
    await mount();
    expect(await screen.findByText("1 hour ago")).toBeInTheDocument();
    vi.setSystemTime(10_000_000 + 2 * 3_600_000);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(screen.getByText("3 hours ago")).toBeInTheDocument();
  });
});

describe("the workspaces layout", () => {
  it("listens for the whole section, shows the dialogs and toasts, and stops on leaving", async () => {
    api.list = [workspace("a", { status: "running" })];
    const start = vi.spyOn(workspaces, "start");
    const startPending = vi.spyOn(pending, "start");
    const view = render(Layout, { children: (() => {}) as never });
    expect(start).toHaveBeenCalledOnce();
    expect(startPending).toHaveBeenCalledOnce();
    expect(workspaces.onSettled).toBe(workspaceActions.settled);
    expect(
      screen.getByRole("region", { name: "Notifications" }),
    ).toBeInTheDocument();
    // The end of an operation reaches the user as a toast.
    await workspaces.refresh();
    source.emit({
      type: "workspace_progress",
      sandbox: "a",
      step: "stopping",
      detail: null,
    });
    source.emit({
      type: "workspace_progress",
      sandbox: "a",
      step: "done",
      detail: null,
    });
    await vi.waitFor(() =>
      expect(toasts.items.at(-1)?.message).toBe("Stopped a."),
    );
    view.unmount();
    expect(workspaces.onSettled).toBeNull();
    start.mockRestore();
    startPending.mockRestore();
  });
});
