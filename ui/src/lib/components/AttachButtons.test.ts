// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import AttachButtons from "./AttachButtons.svelte";

afterEach(cleanup);

function mount(over: Parameters<typeof workspace>[1] = {}) {
  const calls = { start: vi.fn(), stop: vi.fn(), attach: vi.fn() };
  const w = workspace("demo", over);
  render(AttachButtons, {
    props: {
      workspace: w,
      onStart: calls.start,
      onStop: calls.stop,
      onAttach: calls.attach,
    },
  });
  return { calls, w };
}

describe("AttachButtons", () => {
  it("offers Start on a workspace that is down, and nothing to open", async () => {
    const { calls, w } = mount({ status: "stopped" });
    await fireEvent.click(screen.getByRole("button", { name: "Start demo" }));
    expect(calls.start).toHaveBeenCalledWith(w);
    expect(screen.queryByRole("button", { name: /VS Code/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Stop/ })).toBeNull();
  });

  it("opens VS Code in one click and stops, on a running workspace", async () => {
    const { calls, w } = mount({ status: "running" });
    await fireEvent.click(
      screen.getByRole("button", { name: "Open in VS Code (demo)" }),
    );
    expect(calls.attach).toHaveBeenCalledWith(w);
    await fireEvent.click(screen.getByRole("button", { name: "Stop demo" }));
    expect(calls.stop).toHaveBeenCalledWith(w);
  });

  it("shows the browser editor as unavailable, with the reason for readers", () => {
    mount({ status: "running" });
    const browser = screen.getByRole("button", { name: "Browser (demo)" });
    expect(browser).toBeDisabled();
    expect(browser).toHaveAccessibleDescription(
      "Browser VS Code is not available yet.",
    );
  });

  it("disables what can't be done while the workspace changes", () => {
    mount({ status: "starting", busy: "starting" });
    expect(
      screen.getByRole("button", { name: "Open in VS Code (demo)" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Stop demo" })).toBeDisabled();
  });

  it("disables Start while it is busy", () => {
    mount({ status: "created", busy: "creating" });
    expect(screen.getByRole("button", { name: "Start demo" })).toBeDisabled();
  });
});
