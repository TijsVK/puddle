// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import AttachButtons from "./AttachButtons.svelte";

afterEach(cleanup);

function mount(over: Parameters<typeof workspace>[1] = {}) {
  const calls = { start: vi.fn(), stop: vi.fn(), connect: vi.fn() };
  const w = workspace("demo", over);
  render(AttachButtons, {
    props: {
      workspace: w,
      onStart: calls.start,
      onStop: calls.stop,
      onConnect: calls.connect,
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

  it("opens the connect step and stops, on a running workspace", async () => {
    const { calls, w } = mount({ status: "running" });
    await fireEvent.click(
      screen.getByRole("button", { name: "Connect to demo" }),
    );
    expect(calls.connect).toHaveBeenCalledWith(w);
    await fireEvent.click(screen.getByRole("button", { name: "Stop demo" }));
    expect(calls.stop).toHaveBeenCalledWith(w);
  });

  it("has no separate VS Code or browser buttons: the connect step offers both", () => {
    mount({ status: "running" });
    expect(screen.queryByRole("button", { name: /VS Code/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Browser/ })).toBeNull();
  });

  it("disables what can't be done while the workspace changes", () => {
    mount({ status: "starting", busy: "starting" });
    expect(
      screen.getByRole("button", { name: "Connect to demo" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Stop demo" })).toBeDisabled();
  });

  it("disables Start while it is busy", () => {
    mount({ status: "created", busy: "creating" });
    expect(screen.getByRole("button", { name: "Start demo" })).toBeDisabled();
  });
});
