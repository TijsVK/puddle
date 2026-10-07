// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const url = vi.hoisted(() => ({ pathname: "/inbox" }));
vi.mock("$app/state", () => ({
  page: {
    get url() {
      return new URL(`http://127.0.0.1${url.pathname}`);
    },
    status: 404,
    error: null,
  },
}));

const live = vi.hoisted(() => ({
  pending: 0,
  problem: null as null | "unauthorized" | "unreachable",
  start: vi.fn(() => () => undefined),
}));
vi.mock("#lib/stores/live.svelte.ts", () => ({ live }));

import Layout from "../../routes/+layout.svelte";
import ErrorPage from "../../routes/+error.svelte";
import ActivityPage from "../../routes/activity/+page.svelte";
import SettingsPage from "../../routes/settings/+page.svelte";
import { load as rootLoad } from "../../routes/+page.ts";
import { ssr, prerender } from "../../routes/+layout.ts";
import Sidebar from "./Sidebar.svelte";
import { theme } from "../theme/theme.svelte.ts";

beforeEach(() => {
  url.pathname = "/inbox";
  live.pending = 0;
  live.problem = null;
  live.start.mockClear();
  localStorage.clear();
  delete document.documentElement.dataset["theme"];
});
afterEach(cleanup);

describe("Sidebar", () => {
  it("lists the five sections and marks the current one", () => {
    url.pathname = "/rules/abc";
    render(Sidebar);
    const links = screen.getAllByRole("link");
    expect(links.map((l) => l.textContent?.trim())).toEqual([
      "Workspaces",
      "Inbox",
      "Rules",
      "Activity",
      "Settings",
    ]);
    expect(screen.getByRole("link", { name: "Rules" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: "Inbox" })).not.toHaveAttribute(
      "aria-current",
    );
    expect(
      screen.getByRole("navigation", { name: "Main" }),
    ).toBeInTheDocument();
  });

  it("shows the pending badge with an accessible name, only when there is something pending", () => {
    const { unmount } = render(Sidebar);
    expect(screen.queryByTestId("pending-badge")).toBeNull();
    unmount();
    live.pending = 4;
    render(Sidebar);
    expect(screen.getByTestId("pending-badge")).toHaveTextContent(
      "4 4 pending",
    );
    expect(
      screen.getByRole("link", { name: "Inbox 4 pending" }),
    ).toBeInTheDocument();
  });

  it("changes the theme from the toggle and remembers it", async () => {
    render(Sidebar);
    await fireEvent.click(
      screen.getByRole("radio", { name: "Dark" }).closest("button") ??
        screen.getByText("Dark"),
    );
    expect(document.documentElement.dataset["theme"]).toBe("dark");
    expect(localStorage.getItem("puddle.theme")).toBe("dark");
    await fireEvent.click(screen.getByText("System"));
    expect(document.documentElement.dataset["theme"]).toBeUndefined();
  });
});

describe("root layout", () => {
  it("renders the skip link, nav and page, applies the stored theme and starts the live state", () => {
    localStorage.setItem("puddle.theme", "light");
    const { unmount } = render(Layout, { children: (() => {}) as never });
    expect(
      screen.getByRole("link", { name: "Skip to content" }),
    ).toHaveAttribute("href", "#main");
    expect(screen.getByRole("main")).toHaveAttribute("id", "main");
    expect(document.documentElement.dataset["theme"]).toBe("light");
    expect(theme.choice).toBe("light");
    expect(live.start).toHaveBeenCalledTimes(1);
    expect(document.title).toBe("Inbox - puddle");
    unmount();
  });

  it("explains a refused or missing service in a status message", () => {
    live.problem = "unauthorized";
    const { unmount } = render(Layout, { children: (() => {}) as never });
    expect(screen.getByRole("status")).toHaveTextContent(/can't sign in/);
    unmount();
    live.problem = "unreachable";
    render(Layout, { children: (() => {}) as never });
    expect(screen.getByRole("status")).toHaveTextContent(/isn't answering/);
  });

  it("puts the pending count in the document title", () => {
    live.pending = 2;
    render(Layout, { children: (() => {}) as never });
    expect(document.title).toBe("Inbox (2) - puddle");
  });
});

describe("pages", () => {
  it.each([
    ["Activity", ActivityPage],
    ["Settings", SettingsPage],
  ])("%s has one h1 and an empty state", (name, component) => {
    render(component);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 1, name })).toBeInTheDocument();
  });

  it("the start page redirects to the workspaces, and the app renders in the browser only", () => {
    expect(() => rootLoad()).toThrowError(
      expect.objectContaining({ status: 307, location: "/workspaces" }),
    );
    expect({ ssr, prerender }).toEqual({ ssr: false, prerender: false });
  });

  it("the error page tells a 404 from another failure", () => {
    render(ErrorPage);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "Page not found",
    );
  });
});
