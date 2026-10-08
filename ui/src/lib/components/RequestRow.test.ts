// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { request } from "#lib/testing/fake-inbox.ts";
import RequestRow from "./RequestRow.svelte";

afterEach(cleanup);

const now = 1_000_000 + 5 * 60_000;

function mount(
  over: Record<string, unknown> = {},
  req = request(1, { attempts: 3, port: 8443 }),
) {
  const onDecide = vi.fn();
  const onFocusRow = vi.fn();
  const onMore = vi.fn();
  render(RequestRow, {
    props: {
      row: { request: req, domain: "example.com" },
      now,
      onDecide,
      onMore,
      onFocusRow,
      ...over,
    },
  } as never);
  return { onDecide, onMore, onFocusRow };
}

describe("RequestRow", () => {
  it("shows host:port, workspace, attempts and when it was first and last seen", () => {
    mount(
      {},
      request(1, {
        attempts: 3,
        port: 8443,
        last_seen: 1_000_000 + 4 * 60_000,
      }),
    );
    const li = screen.getByRole("listitem");
    expect(li).toHaveTextContent("h1.example.com:8443");
    expect(li).toHaveTextContent("Workspace demo");
    expect(li).toHaveTextContent("3 attempts");
    expect(li).toHaveTextContent(/First seen 5 minutes ago/);
    expect(li).toHaveTextContent(/Last seen 1 minute ago/);
    expect(li.querySelectorAll("time")).toHaveLength(2);
  });

  it("says '1 attempt' in the singular", () => {
    mount({}, request(1));
    expect(screen.getByRole("listitem")).toHaveTextContent("1 attempt ");
  });

  it("shows an untrusted host as text, never as markup", () => {
    mount(
      {},
      request(1, { host: '<img src=x onerror="alert(1)">.example.com' }),
    );
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByRole("listitem")).toHaveTextContent(
      '<img src=x onerror="alert(1)">.example.com',
    );
  });

  it("marks the current row and reports focus on it", async () => {
    const { onFocusRow } = mount({ current: true });
    const li = screen.getByRole("listitem");
    expect(li).toHaveAttribute("aria-current", "true");
    await fireEvent.focusIn(screen.getByRole("button", { name: /^Allow/ }));
    expect(onFocusRow).toHaveBeenCalledOnce();
  });

  it("is not marked current by default", () => {
    mount();
    expect(screen.getByRole("listitem")).not.toHaveAttribute("aria-current");
  });

  it("passes the chevron up with its row", async () => {
    const { onMore } = mount();
    await fireEvent.click(
      screen.getByRole("button", { name: /^More choices/ }),
    );
    expect(onMore).toHaveBeenCalledWith(
      expect.objectContaining({ request: expect.objectContaining({ id: 1 }) }),
      expect.any(HTMLElement),
    );
  });

  it("passes a decision up with its row", async () => {
    const { onDecide } = mount();
    await fireEvent.click(screen.getByRole("button", { name: /^Deny/ }));
    expect(onDecide).toHaveBeenCalledWith(
      expect.objectContaining({ request: expect.objectContaining({ id: 1 }) }),
      expect.objectContaining({ effect: "deny", scope: "workspace" }),
    );
  });

  it("names the toggle that blocks a local destination, links to it, and offers only Deny", () => {
    mount({ blockedBy: "private" }, request(2, { host: "192.168.1.10" }));
    expect(screen.queryByRole("button", { name: /^Allow/ })).toBeNull();
    expect(screen.getByRole("button", { name: /^Deny/ })).toBeInTheDocument();
    const note = screen.getByText(/can't be approved yet/, { exact: false });
    expect(note).toHaveTextContent("Private networks");
    expect(
      screen.getByRole("link", { name: "Private networks" }),
    ).toHaveAttribute("href", "/settings#local-destinations");
  });

  it("offers Allow for a local destination whose toggle is on, with no subdomain choice", () => {
    mount({ blockedBy: null }, request(2, { host: "192.168.1.10" }));
    expect(screen.getByRole("button", { name: /^Allow/ })).toBeInTheDocument();
    expect(screen.queryByText(/switched off/)).toBeNull();
  });
});
