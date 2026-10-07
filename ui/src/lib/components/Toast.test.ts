// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastQueue } from "#lib/stores/toasts.svelte.ts";
import Toast from "./Toast.svelte";

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("Toast", () => {
  it("announces a message politely and removes it after its time", async () => {
    const queue = new ToastQueue();
    render(Toast, { props: { queue } });
    expect(screen.getByRole("status").textContent?.trim()).toBe("");
    queue.push("Allowed example.com");
    await vi.advanceTimersByTimeAsync(0);
    expect(screen.getByRole("status")).toHaveTextContent("Allowed example.com");
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    await vi.advanceTimersByTimeAsync(5000);
    expect(screen.getByRole("status").textContent?.trim()).toBe("");
  });

  it("runs the action on click, and dismisses on the close button", async () => {
    const queue = new ToastQueue();
    const run = vi.fn();
    render(Toast, { props: { queue } });
    queue.push("one", { action: { label: "Undo", run } });
    queue.push("two", { tone: "error" });
    await vi.advanceTimersByTimeAsync(0);
    await fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(run).toHaveBeenCalledOnce();
    await fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await vi.advanceTimersByTimeAsync(0);
    expect(queue.items).toEqual([]);
  });

  it("holds a toast while the pointer or focus is on it", async () => {
    const queue = new ToastQueue();
    render(Toast, { props: { queue } });
    queue.push("held");
    await vi.advanceTimersByTimeAsync(0);
    const toast = screen.getByText("held").parentElement as HTMLElement;
    await fireEvent.mouseEnter(toast);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(queue.items).toHaveLength(1);
    await fireEvent.mouseLeave(toast);
    await fireEvent.focusIn(toast);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(queue.items).toHaveLength(1);
    await fireEvent.focusOut(toast);
    await vi.advanceTimersByTimeAsync(5000);
    expect(queue.items).toHaveLength(0);
  });

  it("uses the shared queue by default", () => {
    render(Toast);
    expect(
      screen.getByRole("region", { name: "Notifications" }),
    ).toBeInTheDocument();
  });
});
