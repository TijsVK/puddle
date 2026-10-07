// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { connection } from "#lib/testing/fake-audit.ts";
import AuditTable from "./AuditTable.svelte";

afterEach(cleanup);

const NOW = 1_000_000 + 5000 * 1000;

function many(count: number) {
  return Array.from({ length: count }, (_, i) => connection(count - i));
}

const body = () => document.querySelectorAll("tbody tr.row");

describe("AuditTable", () => {
  it("draws a table with the columns, one row per record, newest first", () => {
    render(AuditTable, { entries: many(3), now: NOW });
    expect(
      screen.getAllByRole("columnheader").map((h) => h.textContent?.trim()),
    ).toEqual([
      "Time",
      "Workspace",
      "Type",
      "Destination",
      "Outcome",
      "Detail",
    ]);
    expect(body()).toHaveLength(3);
    const first = within(body()[0] as HTMLElement);
    expect(first.getByText("h3.example.com:443")).toBeInTheDocument();
    expect(first.getByText("Allowed")).toBeInTheDocument();
    expect(first.getByText("demo")).toBeInTheDocument();
    expect(screen.getByRole("table")).toHaveAttribute("aria-rowcount", "4");
    expect(body()[1]).toHaveAttribute("aria-rowindex", "3");
  });
  it("says the row count is unknown while older records can still be loaded", () => {
    render(AuditTable, { entries: many(3), hasMore: true, now: NOW });
    expect(screen.getByRole("table")).toHaveAttribute("aria-rowcount", "-1");
  });
  it("shows puddle for a record that is about no workspace", () => {
    render(AuditTable, {
      entries: [
        {
          id: 1,
          record: {
            type: "audit_trimmed",
            ts: 1,
            deleted_records: 5,
            oldest_ts_kept: null,
          },
        },
      ],
      now: NOW,
    });
    expect(screen.getByText("puddle")).toBeInTheDocument();
    expect(screen.getByText("5 older records deleted")).toBeInTheDocument();
  });
  it("draws only a window of a long list, with the rest as padding", () => {
    render(AuditTable, { entries: many(5000), now: NOW });
    const drawn = body().length;
    expect(drawn).toBeGreaterThan(10);
    expect(drawn).toBeLessThan(60);
    const pads = document.querySelectorAll<HTMLElement>("tr.pad");
    expect(pads).toHaveLength(1);
    expect(pads[0]?.style.height).toBe(`${(5000 - drawn) * 36}px`);
  });
  it("moves the window with the scroll and says whether the user is at the top", async () => {
    const onTop = vi.fn();
    render(AuditTable, { entries: many(5000), now: NOW, onTop });
    const region = screen.getByRole("region", { name: "Activity records" });
    region.scrollTop = 36 * 1000;
    await fireEvent.scroll(region);
    await waitFor(() =>
      expect(body()[0]?.getAttribute("data-id")).toBe(String(5000 - 992)),
    );
    expect(onTop).toHaveBeenLastCalledWith(false);
    expect(document.querySelectorAll("tr.pad")).toHaveLength(2);
    region.scrollTop = 0;
    await fireEvent.scroll(region);
    await waitFor(() => expect(onTop).toHaveBeenLastCalledWith(true));
  });
  it("tells the page once when the list leaves the top, however many scroll events come", async () => {
    const onTop = vi.fn();
    render(AuditTable, { entries: many(100), now: NOW, onTop });
    const region = screen.getByRole("region", { name: "Activity records" });
    region.scrollTop = 100;
    await fireEvent.scroll(region);
    await fireEvent.scroll(region);
    await fireEvent.scroll(region);
    expect(onTop).toHaveBeenCalledTimes(1);
    expect(onTop).toHaveBeenCalledWith(false);
  });
  it("asks for older records when the last rows are near, and only if there are some", async () => {
    const onNearEnd = vi.fn();
    const { rerender } = render(AuditTable, {
      entries: many(30),
      hasMore: false,
      now: NOW,
      onNearEnd,
    });
    expect(onNearEnd).not.toHaveBeenCalled();
    await rerender({ entries: many(30), hasMore: true, now: NOW, onNearEnd });
    await waitFor(() => expect(onNearEnd).toHaveBeenCalled());
  });
  it("does not ask while the end is far away", () => {
    const onNearEnd = vi.fn();
    render(AuditTable, {
      entries: many(5000),
      hasMore: true,
      now: NOW,
      onNearEnd,
    });
    expect(onNearEnd).not.toHaveBeenCalled();
  });
  it("opens a row to its raw record, as text, and closes it again", async () => {
    const evil = connection(1, { host: "<img src=x onerror=alert(1)>.test" });
    render(AuditTable, { entries: [evil, ...many(0)], now: NOW });
    const button = screen.getByRole("button", {
      name: "Show the raw record of Connection",
    });
    expect(button).toHaveAttribute("aria-expanded", "false");
    await fireEvent.click(button);
    expect(
      screen.getByRole("button", { name: "Hide the raw record of Connection" }),
    ).toHaveAttribute("aria-expanded", "true");
    const raw = screen.getByLabelText("Raw record 1");
    expect(raw.textContent).toContain(
      '"host": "<img src=x onerror=alert(1)>.test"',
    );
    expect(raw.querySelector("img")).toBeNull();
    expect(document.querySelector("tr.detail")).not.toBeNull();
    await fireEvent.click(
      screen.getByRole("button", { name: /Hide the raw record/ }),
    );
    expect(document.querySelector("tr.detail")).toBeNull();
  });
  it("opens one row at a time, from a click anywhere on the row too", async () => {
    render(AuditTable, { entries: many(3), now: NOW });
    await fireEvent.click(body()[0] as HTMLElement);
    expect(document.querySelectorAll("tr.detail")).toHaveLength(1);
    await fireEvent.click(body()[1] as HTMLElement);
    expect(document.querySelectorAll("tr.detail")).toHaveLength(1);
    expect(screen.getByLabelText("Raw record 2")).toBeInTheDocument();
  });
  it("keeps a row open when records arrive above it", async () => {
    const { rerender } = render(AuditTable, { entries: many(3), now: NOW });
    await fireEvent.click(body()[0] as HTMLElement);
    await rerender({ entries: [connection(9), ...many(3)], now: NOW });
    expect(screen.getByLabelText("Raw record 3")).toBeInTheDocument();
    expect(body()).toHaveLength(4);
  });
  it("scrolls back to the top with a row open", async () => {
    const onTop = vi.fn();
    const { component } = render(AuditTable, {
      entries: many(200),
      now: NOW,
      onTop,
    });
    await fireEvent.click(body()[2] as HTMLElement);
    const region = screen.getByRole("region", { name: "Activity records" });
    region.scrollTop = 500;
    await fireEvent.scroll(region);
    await waitFor(() => expect(onTop).toHaveBeenLastCalledWith(false));
    component.scrollToTop();
    expect(onTop).toHaveBeenLastCalledWith(true);
    expect(region.scrollTop).toBe(0);
  });
});
