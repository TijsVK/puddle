// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const nav = vi.hoisted(() => ({
  path: "/welcome",
  search: "",
  goto: vi.fn(async (_to: string) => undefined),
}));
vi.mock("$app/state", () => ({
  page: {
    get url() {
      return new URL(`http://127.0.0.1${nav.path}${nav.search}`);
    },
  },
}));
vi.mock("$app/navigation", () => ({ goto: nav.goto }));

const h = await vi.hoisted(async () => {
  const first = await import("#lib/testing/fake-first-run.ts");
  const settings = await import("#lib/testing/fake-settings.ts");
  const ws = await import("#lib/testing/fake-workspaces.ts");
  const firstRun = new first.FakeFirstRun();
  const prefs = new settings.FakeSettings();
  const workspaces = new ws.FakeWorkspaces();
  const first_run_paths = ["/api/first-run", "/api/doctor"];
  // One client over the three fakes, by path, like the one API.
  const api = {
    GET: (path: string, init?: unknown) =>
      first_run_paths.includes(path)
        ? firstRun.GET(path)
        : path.startsWith("/api/workspaces")
          ? workspaces.GET(path, init as never)
          : prefs.GET(path),
    PUT: (path: string, init: { body: unknown }) =>
      path === "/api/first-run"
        ? firstRun.PUT(path, init)
        : prefs.PUT(path, init as never),
    POST: (path: string, init: never) => workspaces.POST(path, init),
  };
  return { api, firstRun, prefs, workspaces };
});
vi.mock("#lib/api/client.ts", () => ({ api: h.api }));

const network = vi.hoisted(() => ({
  report: null as unknown,
  status: "ready" as string,
}));
vi.mock("#lib/stores/network-health.svelte.ts", () => ({
  networkHealth: network,
}));

import { report } from "#lib/testing/fake-network.ts";
import { firstRun } from "#lib/stores/first-run.svelte.ts";
import { globalSettings } from "#lib/stores/global-settings.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import { density } from "#lib/theme/density.svelte.ts";
import { theme } from "#lib/theme/theme.svelte.ts";
import Layout from "./+layout.svelte";
import Welcome from "./+page.svelte";
import Certificates from "./certificates/+page.svelte";
import Look from "./look/+page.svelte";
import Workspace from "./workspace/+page.svelte";

beforeEach(() => {
  nav.path = "/welcome";
  nav.search = "";
  nav.goto.mockClear();
  h.firstRun.calls = [];
  h.firstRun.bodies = [];
  h.firstRun.down = false;
  h.firstRun.refusePut = false;
  h.firstRun.state = {
    completed: false,
    completed_at: null,
    dev_certificate: "not_checked",
  };
  h.prefs.reset();
  h.workspaces.list = [];
  h.workspaces.calls = [];
  h.workspaces.bodies = [];
  h.workspaces.refuse.clear();
  firstRun.state = null;
  firstRun.status = "loading";
  globalSettings.view = null;
  globalSettings.consents = null;
  globalSettings.status = "loading";
  network.report = report();
  network.status = "ready";
  toasts.items = [];
  localStorage.clear();
  delete document.documentElement.dataset["theme"];
  delete document.documentElement.dataset["density"];
  theme.choice = "system";
  density.choice = "comfortable";
});
afterEach(cleanup);

describe("the flow's frame", () => {
  it("lists the steps in order and marks the current one and the ones done", () => {
    nav.path = "/welcome/connect";
    render(Layout, { children: (() => {}) as never });
    const steps = screen.getByRole("list", { name: "Setup steps" });
    const items = within(steps).getAllByRole("listitem");
    expect(
      items.map((li) => li.textContent?.replace(/\s+/g, " ").trim()),
    ).toEqual([
      "1 Welcome, done",
      "2 System check, done",
      "3 Certificates, done",
      "4 Connect",
      "5 Look",
      "6 First workspace",
    ]);
    expect(
      items.filter((li) => li.getAttribute("aria-current") === "step"),
    ).toEqual([items[3]]);
    expect(screen.getByText("puddle")).toBeInTheDocument();
  });

  it("leaves the step bar out when the system check runs on its own from Settings", () => {
    nav.path = "/welcome/check";
    nav.search = "?from=settings";
    render(Layout, { children: (() => {}) as never });
    expect(screen.queryByRole("list", { name: "Setup steps" })).toBeNull();
  });
});

describe("welcome step", () => {
  it("greets, and goes on to the system check", () => {
    render(Welcome);
    expect(
      screen.getByRole("heading", { level: 1, name: "Welcome to puddle" }),
    ).toHaveFocus();
    expect(screen.getByRole("link", { name: "Get started" })).toHaveAttribute(
      "href",
      "/welcome/check",
    );
  });

  it("skipping the setup records it and opens the workspace list", async () => {
    render(Welcome);
    await fireEvent.click(screen.getByRole("button", { name: "Skip setup" }));
    await waitFor(() => expect(nav.goto).toHaveBeenCalledWith("/workspaces"));
    expect(h.firstRun.bodies).toEqual([{ completed: true }]);
    expect(h.firstRun.state.completed).toBe(true);
    expect(toasts.items).toEqual([]);
  });

  it("opens the workspace list even when it could not keep that, and says so", async () => {
    h.firstRun.refusePut = true;
    render(Welcome);
    await fireEvent.click(screen.getByRole("button", { name: "Skip setup" }));
    await waitFor(() => expect(nav.goto).toHaveBeenCalledWith("/workspaces"));
    expect(toasts.items[0]?.message).toMatch(
      /newer puddle.*may show again next time/,
    );
    expect(toasts.items[0]?.tone).toBe("error");
  });
});

describe("certificates step", () => {
  it("says the development certificate was not checked and counts the company roots", async () => {
    render(Certificates);
    const list = screen.getByRole("list", { name: "Certificates" });
    await waitFor(() =>
      expect(h.firstRun.calls).toContain("GET /api/first-run"),
    );
    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent(
      "Development certificate: not checked yet",
    );
    expect(items[1]).toHaveTextContent("1 company root certificate found");
    expect(
      screen.getByRole("link", { name: /Network health/ }),
    ).toHaveAttribute("href", "/settings/network-health");
    expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
      "href",
      "/welcome/check",
    );
    expect(screen.getByRole("link", { name: "Continue" })).toHaveAttribute(
      "href",
      "/welcome/connect",
    );
  });

  it("says once that puddle uses an existing .NET development certificate", async () => {
    h.firstRun.state = {
      ...h.firstRun.state,
      dev_certificate: "reusing_existing",
    };
    render(Certificates);
    expect(
      await screen.findByText(
        "Using your existing .NET development certificate",
      ),
    ).toBeVisible();
    expect(screen.getByText(/No trust dialog needed/)).toBeVisible();
  });

  it("says when the company roots could not be read", () => {
    network.report = null;
    network.status = "failed";
    render(Certificates);
    expect(screen.getByText("Company certificates: not read")).toBeVisible();
    cleanup();
    network.status = "loading";
    render(Certificates);
    expect(screen.getByText("Company certificates")).toBeVisible();
    cleanup();
    network.status = "unavailable";
    render(Certificates);
    expect(screen.getByText("Company certificates: not read")).toBeVisible();
  });
});

describe("look step", () => {
  const radio = (name: string) =>
    screen.getByRole("radio", { name: new RegExp(`^${name}`) });

  it("offers the theme and the density with the stored ones selected", () => {
    render(Look);
    expect(
      screen.getByRole("heading", { level: 1, name: "Look" }),
    ).toHaveFocus();
    expect(radio("Follow my system")).toBeChecked();
    expect(radio("Comfortable")).toBeChecked();
    expect(screen.getByRole("link", { name: "Continue" })).toHaveAttribute(
      "href",
      "/welcome/workspace",
    );
    expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
      "href",
      "/welcome/connect",
    );
  });

  it("applies a theme at once and keeps it in the settings", async () => {
    render(Look);
    await fireEvent.click(radio("Dark"));
    expect(await screen.findByText("Theme saved.")).toBeVisible();
    expect(document.documentElement.dataset["theme"]).toBe("dark");
    expect(h.prefs.ui.theme).toBe("dark");
    expect(radio("Dark")).toBeChecked();
  });

  it("applies a density at once and keeps it in the settings", async () => {
    render(Look);
    await fireEvent.click(radio("Compact"));
    expect(await screen.findByText("Density saved.")).toBeVisible();
    expect(document.documentElement.dataset["density"]).toBe("compact");
    expect(h.prefs.ui.density).toBe("compact");
  });

  it("says when a choice applied here could not be kept", async () => {
    render(Look);
    h.prefs.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "no",
    });
    await fireEvent.click(radio("Light"));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The theme changed here but puddle couldn't save it.",
    );
    h.prefs.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "no",
    });
    await fireEvent.click(radio("Compact"));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "The density changed here but puddle couldn't save it.",
      ),
    );
  });
});

describe("first workspace step", () => {
  it("offers to create one or skip, and goes back to the look step", () => {
    render(Workspace);
    expect(
      screen.getByRole("heading", { level: 1, name: "Your first workspace" }),
    ).toHaveFocus();
    expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
      "href",
      "/welcome/look",
    );
    expect(screen.getByRole("button", { name: "Skip" })).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Create a workspace" }),
    ).toBeEnabled();
  });

  it("skipping ends the flow without a workspace", async () => {
    render(Workspace);
    await fireEvent.click(screen.getByRole("button", { name: "Skip" }));
    await waitFor(() => expect(nav.goto).toHaveBeenCalledWith("/workspaces"));
    expect(h.firstRun.state.completed).toBe(true);
    expect(h.workspaces.calls).toEqual([]);
  });

  it("creates the workspace in the usual form, then ends the flow", async () => {
    render(Workspace);
    await fireEvent.click(
      screen.getByRole("button", { name: "Create a workspace" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "New workspace" });
    await fireEvent.input(within(dialog).getByLabelText(/Git repository/), {
      target: { value: "https://github.com/acme/shop-api.git" },
    });
    expect(within(dialog).getByLabelText("Name")).toHaveValue("shop-api");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Create workspace" }),
    );
    await waitFor(() => expect(nav.goto).toHaveBeenCalledWith("/workspaces"));
    expect(h.workspaces.bodies[0]).toMatchObject({
      name: "shop-api",
      repo_url: "https://github.com/acme/shop-api.git",
    });
    expect(h.firstRun.state.completed).toBe(true);
  });

  it("keeps the flow open when the workspace is refused, with the reason in the form", async () => {
    h.workspaces.refuse.set("POST /api/workspaces", {
      status: 422,
      message: "SSH addresses aren't supported yet",
    });
    render(Workspace);
    await fireEvent.click(
      screen.getByRole("button", { name: "Create a workspace" }),
    );
    const dialog = await screen.findByRole("dialog");
    await fireEvent.input(within(dialog).getByLabelText(/Git repository/), {
      target: { value: "https://github.com/acme/shop-api.git" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Create workspace" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "SSH addresses aren't supported yet",
    );
    expect(nav.goto).not.toHaveBeenCalled();
    expect(h.firstRun.state.completed).toBe(false);
  });

  it("opens the list even when it could not keep that the flow is done, and says so", async () => {
    h.firstRun.refusePut = true;
    render(Workspace);
    await fireEvent.click(screen.getByRole("button", { name: "Skip" }));
    await waitFor(() => expect(nav.goto).toHaveBeenCalledWith("/workspaces"));
    expect(toasts.items[0]?.message).toMatch(
      /newer puddle.*may show again next time/,
    );
  });
});
