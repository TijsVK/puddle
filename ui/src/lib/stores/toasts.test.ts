// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastQueue } from "./toasts.svelte.ts";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("ToastQueue", () => {
  it("leaves after 5 s by default and after `ms` when given", () => {
    const q = new ToastQueue();
    q.push("one");
    q.push("two", { ms: 1000, tone: "error" });
    expect(q.items.map((t) => [t.message, t.tone])).toEqual([
      ["one", "info"],
      ["two", "error"],
    ]);
    vi.advanceTimersByTime(1000);
    expect(q.items.map((t) => t.message)).toEqual(["one"]);
    vi.advanceTimersByTime(4000);
    expect(q.items).toEqual([]);
  });

  it("holds while hovered or focused and restarts the full wait after", () => {
    const q = new ToastQueue();
    const id = q.push("held");
    vi.advanceTimersByTime(4000);
    q.hold(id);
    vi.advanceTimersByTime(60_000);
    expect(q.items).toHaveLength(1);
    q.resume(id);
    vi.advanceTimersByTime(4999);
    expect(q.items).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(q.items).toEqual([]);
  });

  it("runs the action once and removes the toast", async () => {
    const q = new ToastQueue();
    const run = vi.fn();
    const id = q.push("undo me", { action: { label: "Undo", run } });
    await q.act(id);
    expect(run).toHaveBeenCalledOnce();
    expect(q.items).toEqual([]);
    await q.act(id);
    expect(run).toHaveBeenCalledOnce();
  });

  it("ignores resuming or holding a toast that is gone", () => {
    const q = new ToastQueue();
    q.resume(99);
    q.hold(99);
    q.dismiss(99);
    expect(q.items).toEqual([]);
  });
});
