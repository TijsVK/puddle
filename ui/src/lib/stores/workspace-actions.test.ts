// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import {
  FakeWorkspaces,
  cleanCheck,
  dirtyCheck,
  workspace,
} from "#lib/testing/fake-workspaces.ts";
import { ToastQueue } from "./toasts.svelte.ts";
import {
  WorkspaceActions,
  settledMessage,
} from "./workspace-actions.svelte.ts";
import { WorkspaceStore } from "./workspaces.svelte.ts";

let api: FakeWorkspaces;
let store: WorkspaceStore;
let toasts: ToastQueue;
let actions: WorkspaceActions;

beforeEach(async () => {
  api = new FakeWorkspaces();
  api.list = [
    workspace("down"),
    workspace("up", { status: "running", first_connect_notice_due: true }),
    workspace("trusted", { status: "running" }),
  ];
  store = new WorkspaceStore({ api: api as never });
  await store.refresh();
  toasts = new ToastQueue();
  actions = new WorkspaceActions(store, toasts);
});

const messages = () => toasts.items.map((t) => t.message);
const w = (name: string) => store.byName(name)!;

describe("start, stop and reclaim", () => {
  it("start and stop go to the service", async () => {
    await actions.start(w("down"));
    expect(api.calls).toContain("POST /api/workspaces/{id}/start");
    await actions.stop(w("trusted"));
    expect(api.calls).toContain("POST /api/workspaces/{id}/stop");
    await actions.reclaim(w("trusted"));
    expect(api.calls).toContain("POST /api/workspaces/{id}/reclaim");
    expect(toasts.items).toHaveLength(0);
  });

  it("a refusal is an error toast that stays longer", async () => {
    api.refuse.set("POST /api/workspaces/{id}/start", {
      status: 409,
      message: "busy",
    });
    await actions.start(w("down"));
    expect(toasts.items).toMatchObject([{ message: "busy", tone: "error" }]);
    api.refuse.set("POST /api/workspaces/{id}/stop", {
      status: 409,
      message: "not running",
    });
    await actions.stop(w("down"));
    api.refuse.set("POST /api/workspaces/{id}/reclaim", {
      status: 409,
      message: "busy too",
    });
    await actions.reclaim(w("down"));
    expect(messages()).toEqual(["busy", "not running", "busy too"]);
  });
});

describe("opening in VS Code", () => {
  it("asks first when the notice is due, and opens only after the yes", async () => {
    actions.attach(w("up"));
    expect(actions.noticeOpen).toBe(true);
    expect(actions.noticeFor?.name).toBe("up");
    expect(api.calls).not.toContain("POST /api/workspaces/{id}/attach");
    actions.confirmNotice();
    await expect.poll(() => messages()).toEqual(["Opening up in VS Code."]);
    expect(api.bodies.at(-1)).toEqual({ mode: "desktop" });
    expect(actions.noticeFor).toBeNull();
  });

  it("opens at once when the notice was accepted before", async () => {
    actions.attach(w("trusted"));
    expect(actions.noticeOpen).toBe(false);
    await expect
      .poll(() => messages())
      .toEqual(["Opening trusted in VS Code."]);
  });

  it("a confirm with nothing to confirm does nothing", () => {
    actions.confirmNotice();
    expect(api.calls).not.toContain("POST /api/workspaces/{id}/attach");
  });

  it("says why when VS Code could not be opened, with the service's words", async () => {
    api.attachReply = {
      opened: false,
      url: null,
      message: "VS Code isn't installed.",
    };
    actions.attach(w("trusted"));
    await expect
      .poll(() => toasts.items[0])
      .toMatchObject({
        message: "VS Code isn't installed.",
        tone: "error",
      });
  });

  it("has words of its own when the service gave none", async () => {
    api.attachReply = { opened: false, url: null, message: null };
    actions.attach(w("trusted"));
    await expect
      .poll(() => messages())
      .toEqual(["puddle couldn't open VS Code for trusted."]);
  });

  it("a refused attach is an error toast", async () => {
    api.refuse.set("POST /api/workspaces/{id}/attach", {
      status: 409,
      message: "not running",
    });
    actions.attach(w("trusted"));
    await expect.poll(() => messages()).toEqual(["not running"]);
  });
});

describe("deleting", () => {
  it("reads the check, then asks with what it found", async () => {
    api.check = dirtyCheck("down");
    const asking = actions.askDelete(w("down"));
    expect(actions.checking).toBe("down");
    await asking;
    expect(actions.checking).toBeNull();
    expect(actions.deleteOpen).toBe(true);
    expect(actions.deleting?.check.fingerprint).toBe("fp-dirty");
  });

  it("says so when the check can't be read", async () => {
    api.refuse.set("GET /api/workspaces/{id}/delete-check", {
      status: 409,
      message: "busy",
    });
    await actions.askDelete(w("down"));
    expect(actions.deleteOpen).toBe(false);
    expect(messages()).toEqual(["busy"]);
    expect(actions.checking).toBeNull();
  });

  it("deletes with the fingerprint it showed", async () => {
    api.check = dirtyCheck("down");
    await actions.askDelete(w("down"));
    await actions.confirmDelete();
    expect(api.bodies.at(-1)).toEqual({
      confirm: true,
      fingerprint: "fp-dirty",
    });
    expect(actions.deleteOpen).toBe(false);
    expect(messages()).toEqual(["Deleting down."]);
  });

  it("does nothing without a check, and nothing twice", async () => {
    await actions.confirmDelete();
    expect(api.calls).not.toContain("DELETE /api/workspaces/{id}");
    api.check = cleanCheck("down");
    await actions.askDelete(w("down"));
    const first = actions.confirmDelete();
    await actions.confirmDelete();
    await first;
    expect(api.calls.filter((c) => c.startsWith("DELETE"))).toHaveLength(1);
  });

  it("shows the new list when the workspace changed since the check", async () => {
    api.check = cleanCheck("down");
    await actions.askDelete(w("down"));
    api.check = dirtyCheck("down");
    api.refuse.set("DELETE /api/workspaces/{id}", {
      status: 409,
      message: "changed since you looked",
    });
    await actions.confirmDelete();
    expect(actions.deleteOpen).toBe(true);
    expect(actions.deleting).toMatchObject({
      working: false,
      error: "changed since you looked",
      check: { fingerprint: "fp-dirty" },
    });
    await actions.confirmDelete();
    expect(api.bodies.at(-1)).toEqual({
      confirm: true,
      fingerprint: "fp-dirty",
    });
    expect(actions.deleteOpen).toBe(false);
  });

  it("keeps the old list and the reason when it can't read the new one", async () => {
    api.check = cleanCheck("down");
    await actions.askDelete(w("down"));
    api.refuse.set("DELETE /api/workspaces/{id}", {
      status: 409,
      message: "changed",
    });
    api.refuse.set("GET /api/workspaces/{id}/delete-check", {
      status: 500,
      message: "x",
    });
    await actions.confirmDelete();
    expect(actions.deleting).toMatchObject({
      working: false,
      error: "changed",
      check: { fingerprint: "fp-clean" },
    });
  });

  it("closes and says so when the workspace is gone already", async () => {
    api.check = cleanCheck("down");
    await actions.askDelete(w("down"));
    api.list = api.list.filter((x) => x.name !== "down");
    await actions.confirmDelete();
    expect(actions.deleteOpen).toBe(false);
    expect(messages()).toEqual(["That workspace no longer exists."]);
  });

  it("keeps the dialog open with the reason after another refusal", async () => {
    api.check = cleanCheck("down");
    await actions.askDelete(w("down"));
    api.refuse.set("DELETE /api/workspaces/{id}", {
      status: 422,
      message: "confirm must be true",
    });
    await actions.confirmDelete();
    expect(actions.deleting).toMatchObject({
      working: false,
      error: "confirm must be true",
    });
    expect(actions.deleteOpen).toBe(true);
  });
});

describe("the rest", () => {
  it("opens the create dialog", () => {
    actions.openCreate();
    expect(actions.createOpen).toBe(true);
  });

  it("dismisses a failure the user saw", () => {
    store.progress = {
      down: { step: "failed", detail: "x", operation: null, failed: true },
    };
    actions.dismissProgress(w("down"));
    expect(store.progress["down"]).toBeUndefined();
  });

  it("toasts the end of an operation, and a failure as an error", () => {
    actions.settled({
      name: "up",
      operation: "starting",
      failed: false,
      detail: null,
    });
    actions.settled({
      name: "up",
      operation: "stopping",
      failed: true,
      detail: "no",
    });
    expect(toasts.items).toMatchObject([
      { message: "up is running.", tone: "info" },
      { message: "Stopping up failed: no", tone: "error" },
    ]);
  });
});

describe("settledMessage", () => {
  it.each([
    [{ operation: "creating", failed: false, detail: null }, "Created w."],
    [{ operation: "starting", failed: false, detail: null }, "w is running."],
    [{ operation: "stopping", failed: false, detail: null }, "Stopped w."],
    [
      { operation: "reclaiming", failed: false, detail: null },
      "Reclaimed free space on w.",
    ],
    [{ operation: "deleting", failed: false, detail: null }, "Deleted w."],
    [{ operation: null, failed: false, detail: null }, "w: done."],
    [
      { operation: "creating", failed: true, detail: "no repo" },
      "Creating w failed: no repo",
    ],
    [
      { operation: "deleting", failed: true, detail: null },
      "Deleting w failed.",
    ],
    [
      { operation: null, failed: true, detail: "x" },
      "Something went wrong with w: x",
    ],
    [
      { operation: null, failed: true, detail: null },
      "Something went wrong with w.",
    ],
  ] as const)("%j", (rest, text) => {
    expect(settledMessage({ name: "w", ...rest })).toBe(text);
  });
});
