// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { asWorkspaceEvent } from "./events.ts";

describe("asWorkspaceEvent", () => {
  it("accepts the three events the workspace screens use", () => {
    const status = { type: "status_changed", sandbox: "w", status: "running" };
    const oom = { type: "oom_kill", sandbox: "w", pid: 7, process: "node" };
    const progress = {
      type: "workspace_progress",
      sandbox: "w",
      step: "cloning",
      detail: null,
    };
    expect(asWorkspaceEvent(status)).toEqual(status);
    expect(asWorkspaceEvent(oom)).toEqual(oom);
    expect(asWorkspaceEvent(progress)).toEqual(progress);
  });

  it.each([
    null,
    undefined,
    "text",
    42,
    {},
    { type: "status_changed" },
    { type: "status_changed", sandbox: "w" },
    { type: "status_changed", sandbox: 1, status: "running" },
    { type: "oom_kill", sandbox: "w", pid: "7", process: "node" },
    { type: "oom_kill", sandbox: "w", pid: 7 },
    { type: "workspace_progress", sandbox: "w" },
    { type: "pending_opened", sandbox: "w" },
    { type: "rules_changed" },
  ])("ignores %j", (raw) => {
    expect(asWorkspaceEvent(raw)).toBeNull();
  });
});
