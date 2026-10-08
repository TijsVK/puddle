// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import WorkspaceCard from "./WorkspaceCard.svelte";

afterEach(cleanup);

const NOW = 10_000_000;

function mount(over: Record<string, unknown> = {}, w = workspace("demo")) {
  const calls = {
    start: vi.fn(),
    stop: vi.fn(),
    connect: vi.fn(),
    dismiss: vi.fn(),
  };
  render(WorkspaceCard, {
    props: {
      workspace: w,
      now: NOW,
      onStart: calls.start,
      onStop: calls.stop,
      onConnect: calls.connect,
      onDismiss: calls.dismiss,
      ...over,
    },
  });
  return calls;
}

describe("WorkspaceCard", () => {
  it("is an article named by the workspace, linking to its page", () => {
    mount({}, workspace("my-site", { id: "my site" }));
    expect(
      screen.getByRole("article", { name: "my-site" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "my-site" })).toHaveAttribute(
      "href",
      "/workspaces/my%20site",
    );
    expect(
      screen.getByRole("link", { name: "Details of my-site" }),
    ).toHaveAttribute("href", "/workspaces/my%20site");
  });

  it("shows the repository, state, memory, disk and age", () => {
    mount({}, workspace("demo", { created_at: NOW - 3_600_000 * 3 }));
    const card = screen.getByRole("article");
    expect(card).toHaveTextContent("https://github.com/acme/demo.git");
    expect(card).toHaveTextContent("Stopped");
    expect(card).toHaveTextContent("8 GiB memory");
    expect(card).toHaveTextContent("2 GiB of 32 GiB used");
    expect(card).toHaveTextContent("3 hours ago");
  });

  it("tells a workspace with no volume how to get out, and keeps Start", () => {
    const calls = mount({}, workspace("demo", { status: "volume_missing" }));
    const card = screen.getByRole("article");
    expect(card).toHaveTextContent("Volume missing");
    expect(card).toHaveTextContent("Restore the volume ws-demo");
    expect(card).toHaveTextContent("open Details to delete it");
    expect(screen.getByRole("button", { name: /Start/ })).toBeEnabled();
    expect(calls.start).not.toHaveBeenCalled();
  });

  it("marks a workspace with direct SSH on as trusted, and no other", () => {
    mount({}, workspace("demo", { direct_ssh: true }));
    expect(screen.getByText("Trusted")).toBeInTheDocument();
    cleanup();
    mount({}, workspace("demo"));
    expect(screen.queryByText("Trusted")).toBeNull();
  });

  it("links the waiting count to the network tab, only when something waits", () => {
    mount({ waiting: 2 });
    expect(screen.getByRole("link", { name: "2 waiting" })).toHaveAttribute(
      "href",
      "/workspaces/demo/network",
    );
    cleanup();
    mount({ waiting: 0 });
    expect(screen.queryByRole("link", { name: /waiting/ })).toBeNull();
  });

  it("flags a recent out-of-memory kill", () => {
    mount({ oom: { process: "node", pid: 7, at: NOW - 120_000 } });
    expect(screen.getByRole("article")).toHaveTextContent(
      "Out of memory 2 minutes ago",
    );
  });

  it("shows progress and a failure the user can dismiss", async () => {
    const calls = mount(
      {
        progress: {
          step: "failed",
          detail: "no boot",
          operation: "starting",
          failed: true,
        },
      },
      workspace("demo", { status: "crashed" }),
    );
    expect(screen.getByRole("alert")).toHaveTextContent("no boot");
    await fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(calls.dismiss).toHaveBeenCalledWith(
      expect.objectContaining({ name: "demo" }),
    );
  });

  it("starts, and says what it is doing while busy", async () => {
    const calls = mount();
    await fireEvent.click(screen.getByRole("button", { name: "Start demo" }));
    expect(calls.start).toHaveBeenCalledOnce();
    cleanup();
    mount({}, workspace("demo", { status: "starting", busy: "starting" }));
    expect(screen.getByRole("article")).toHaveTextContent("Starting");
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
});
