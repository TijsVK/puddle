// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const url = vi.hoisted(() => ({ pathname: "/workspaces/demo", id: "demo" }));
vi.mock("$app/state", () => ({
  page: {
    get url() {
      return new URL(`http://127.0.0.1${url.pathname}`);
    },
    get params() {
      return { id: url.id };
    },
  },
}));
const goto = vi.hoisted(() => vi.fn());
vi.mock("$app/navigation", () => ({ goto }));

const h = await vi.hoisted(async () => {
  const inbox = await import("#lib/testing/fake-inbox.ts");
  const ws = await import("#lib/testing/fake-workspaces.ts");
  const rules = await import("#lib/testing/fake-rules.ts");
  return {
    inbox: new inbox.FakeInbox(),
    source: new inbox.FakeSource(),
    request: inbox.request,
    api: new ws.FakeWorkspaces(),
    workspace: ws.workspace,
    rules: new rules.FakeRules(),
    rule: rules.rule,
  };
});

vi.mock("#lib/stores/pending.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/pending.svelte.ts")>();
  return {
    ...mod,
    pending: new mod.PendingStore({
      api: h.inbox as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});
vi.mock("#lib/stores/workspaces.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/workspaces.svelte.ts")>();
  return {
    ...mod,
    workspaces: new mod.WorkspaceStore({
      api: h.api as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});
vi.mock("#lib/stores/rules.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/rules.svelte.ts")>();
  return {
    ...mod,
    rulesStore: new mod.RulesStore({
      api: h.rules as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});
vi.mock("#lib/api/client.ts", () => ({ api: h.api }));

import { pending } from "#lib/stores/pending.svelte.ts";
import { rulesStore } from "#lib/stores/rules.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import { workspaceActions } from "#lib/stores/workspace-actions.svelte.ts";
import { workspaces } from "#lib/stores/workspaces.svelte.ts";
import { cleanCheck, dirtyCheck } from "#lib/testing/fake-workspaces.ts";
import DetailLayout from "./+layout.svelte";
import Overview from "./+page.svelte";
import Network from "./network/+page.svelte";
import Settings from "./settings/+page.svelte";
import Environment from "./environment/+page.svelte";
import ShellInit from "./shell-init/+page.svelte";
import Ports from "./ports/+page.svelte";

const { inbox, api, workspace, request, rules, rule } = h;

/** The overrides a workspace has now (all inherited, for one never changed). */
async function settingsOf(name: string) {
  const { data } = (await api.GET("/api/settings/workspaces/{workspace}", {
    params: { path: { workspace: name } },
  })) as unknown as { data: { overrides: Record<string, unknown> } };
  return data.overrides as never as (typeof api.overrides)[string];
}

function reset() {
  url.pathname = "/workspaces/demo";
  url.id = "demo";
  goto.mockReset();
  inbox.open = [];
  inbox.rules = [];
  inbox.calls = [];
  inbox.toggles = {};
  api.list = [workspace("demo", { status: "running" })];
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.check = null;
  api.overrides = {};
  api.refuse.clear();
  rules.rules = [];
  rules.calls = [];
  pending.rows = [];
  pending.status = "loading";
  rulesStore.rules = [];
  rulesStore.status = "loading";
  workspaces.list = [];
  workspaces.status = "loading";
  workspaces.progress = {};
  workspaces.oom = {};
  workspaceActions.createOpen = false;
  workspaceActions.connectOpen = false;
  workspaceActions.trustOpen = false;
  workspaceActions.deleteOpen = false;
  workspaceActions.deleting = null;
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
}

beforeEach(reset);
afterEach(cleanup);

async function load() {
  await Promise.all([
    workspaces.refresh(),
    pending.refresh(),
    rulesStore.refresh(),
  ]);
}

describe("the detail layout", () => {
  it("shows the name, the state, the actions and the tabs with the current one marked", async () => {
    await load();
    render(DetailLayout, { children: (() => {}) as never });
    expect(
      await screen.findByRole("heading", { level: 1, name: "demo" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Stop demo" }),
    ).toBeInTheDocument();
    const tabs = within(
      screen.getByRole("navigation", { name: "Workspace sections" }),
    );
    expect(tabs.getAllByRole("link").map((l) => l.textContent?.trim())).toEqual(
      ["Overview", "Network", "Environment", "Shell init", "Ports", "Settings"],
    );
    expect(tabs.getByRole("link", { name: "Overview" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(tabs.getByRole("link", { name: "Settings" })).toHaveAttribute(
      "href",
      "/workspaces/demo/settings",
    );
  });

  it("marks another tab, and counts what waits on the network tab", async () => {
    url.pathname = "/workspaces/demo/network";
    inbox.add(request(1, { workspace: "demo" as never }), "example.com");
    inbox.add(request(2, { workspace: "other" as never }), "example.com");
    await load();
    render(DetailLayout, { children: (() => {}) as never });
    const link = await screen.findByRole("link", { name: /Network/ });
    expect(link).toHaveAttribute("aria-current", "page");
    expect(link).toHaveTextContent("1 waiting");
  });

  it("shows the progress line while something runs and says Start for a stopped workspace", async () => {
    api.list = [workspace("demo", { status: "stopped" })];
    await load();
    render(DetailLayout, { children: (() => {}) as never });
    await fireEvent.click(
      await screen.findByRole("button", { name: "Start demo" }),
    );
    await vi.waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("Starting"),
    );
  });

  it("says when there is no such workspace", async () => {
    url.id = "nope";
    await load();
    render(DetailLayout, { children: (() => {}) as never });
    expect(
      await screen.findByRole("heading", { name: "No such workspace" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to the workspaces" }),
    ).toHaveAttribute("href", "/workspaces");
    expect(goto).not.toHaveBeenCalled();
  });

  it("shows loading and failure lines before the workspace is known", async () => {
    render(DetailLayout, { children: (() => {}) as never });
    expect(screen.getByText(/Loading workspace/)).toBeInTheDocument();
    api.down = true;
    await workspaces.refresh();
    expect(
      await screen.findByText(/Couldn't read the workspace/),
    ).toBeInTheDocument();
  });

  it("goes back to the list when the workspace it showed is gone", async () => {
    await load();
    render(DetailLayout, { children: (() => {}) as never });
    await screen.findByRole("heading", { level: 1, name: "demo" });
    api.list = [];
    await workspaces.refresh();
    await vi.waitFor(() => expect(goto).toHaveBeenCalledWith("/workspaces"));
  });
});

describe("the trusted mark", () => {
  it("shows on the workspace page only while direct SSH is on", async () => {
    api.list = [workspace("demo", { status: "running", direct_ssh: true })];
    await workspaces.refresh();
    const { unmount } = render(DetailLayout, { children: (() => {}) as never });
    expect(await screen.findByText("Trusted")).toBeInTheDocument();
    unmount();
    api.list = [workspace("demo", { status: "running" })];
    await workspaces.refresh();
    render(DetailLayout, { children: (() => {}) as never });
    await screen.findByRole("heading", { name: "demo" });
    expect(screen.queryByText("Trusted")).toBeNull();
  });
});

describe("the overview", () => {
  it("shows state, image, repository, resources and the network summary", async () => {
    rules.rules = [
      rule(1, { scope: { type: "workspace", workspace: "demo" } }),
      rule(2),
      rule(3, { expires_at: 1 }),
    ];
    inbox.add(request(1, { workspace: "demo" as never }), "example.com");
    await load();
    render(Overview);
    expect(await screen.findByText("ws-demo")).toBeInTheDocument();
    expect(
      screen.getByText("https://github.com/acme/demo.git"),
    ).toBeInTheDocument();
    expect(screen.getByText("2 GiB of 32 GiB used")).toBeInTheDocument();
    expect(screen.getByText("8 GiB")).toBeInTheDocument();
    await vi.waitFor(() =>
      expect(
        screen.getByText(
          "1 waiting · 1 workspace rule · 1 rule for every workspace",
        ),
      ).toBeInTheDocument(),
    );
    await vi.waitFor(() =>
      expect(screen.getByText("global default")).toBeInTheDocument(),
    );
  });

  it("says where the memory comes from, and copes with settings that can't be read", async () => {
    await workspaces.refresh();
    api.overrides["demo"] = {
      ...(await settingsOf("demo")),
      memory: 4096,
    };
    await load();
    const view = render(Overview);
    await vi.waitFor(() =>
      expect(screen.getByText("workspace override")).toBeInTheDocument(),
    );
    view.unmount();
    api.refuse.set("GET /api/settings/workspaces/{workspace}", {
      status: 500,
      message: "x",
    });
    render(Overview);
    await screen.findByText("ws-demo");
    expect(screen.queryByText("workspace override")).toBeNull();
  });

  it("shows an out-of-memory notice that can be dismissed", async () => {
    await load();
    render(Overview);
    await screen.findByText("ws-demo");
    expect(screen.queryByRole("alert")).toBeNull();
    workspaces.handleEvent({
      type: "oom_kill",
      workspace: "demo",
      pid: 77,
      process: "node",
    });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Out of memory");
    expect(alert).toHaveTextContent("node");
    expect(alert).toHaveTextContent("process 77");
    expect(
      within(alert).getByRole("link", { name: "Change memory" }),
    ).toHaveAttribute("href", "/workspaces/demo/settings");
    await fireEvent.click(
      within(alert).getByRole("button", { name: "Dismiss" }),
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reclaims space on a running workspace, and not while it is changing", async () => {
    await load();
    render(Overview);
    await fireEvent.click(
      await screen.findByRole("button", { name: "Reclaim space" }),
    );
    await vi.waitFor(() =>
      expect(api.calls).toContain("POST /api/workspaces/{id}/reclaim"),
    );
    await vi.waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Reclaim space" }),
      ).toBeDisabled(),
    );
  });

  it("can't delete a running workspace and says why", async () => {
    await load();
    render(Overview);
    const del = await screen.findByRole("button", {
      name: "Delete workspace…",
    });
    expect(del).toBeDisabled();
    expect(
      screen.getByText("Stop the workspace before deleting it."),
    ).toBeInTheDocument();
  });

  it("checks what a delete would lose, then opens the dialog with it", async () => {
    api.list = [workspace("demo", { status: "stopped" })];
    api.check = dirtyCheck("demo");
    await load();
    render(Overview);
    const del = await screen.findByRole("button", {
      name: "Delete workspace…",
    });
    expect(del).toBeEnabled();
    expect(
      screen.queryByText("Stop the workspace before deleting it."),
    ).toBeNull();
    await fireEvent.click(del);
    await vi.waitFor(() => expect(workspaceActions.deleteOpen).toBe(true));
    expect(workspaceActions.deleting?.check.fingerprint).toBe("fp-dirty");
  });

  it("says a workspace with no volume can be restored or deleted, and that deleting loses nothing", async () => {
    api.list = [workspace("demo", { status: "volume_missing" })];
    api.check = cleanCheck("demo", { volume_missing: true });
    await load();
    render(Overview);
    expect(await screen.findByText(/Its disk is gone/)).toBeInTheDocument();
    expect(
      screen.getByText(/delete the workspace below; nothing is lost/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/deleting only removes the workspace from puddle/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Delete workspace…" }),
    ).toBeEnabled();
  });

  it("shows nothing for a workspace it doesn't know", async () => {
    url.id = "nope";
    await load();
    const { container } = render(Overview);
    expect(container.textContent?.trim()).toBe("");
    api.check = cleanCheck("x");
  });
});

describe("the network tab", () => {
  beforeEach(() => {
    url.pathname = "/workspaces/demo/network";
  });

  it("lists this workspace's waiting requests, newest first, and not another's", async () => {
    inbox.add(
      request(1, {
        workspace: "demo" as never,
        host: "old.example.com",
        first_seen: 1,
      }),
      "example.com",
    );
    inbox.add(
      request(2, {
        workspace: "demo" as never,
        host: "new.example.com",
        first_seen: 9,
      }),
      "example.com",
    );
    inbox.add(
      request(3, { workspace: "other" as never, host: "theirs.example.org" }),
      "example.org",
    );
    await load();
    render(Network);
    await screen.findByText("new.example.com");
    const hosts = [...document.querySelectorAll("li.req .host")].map(
      (e) => e.textContent,
    );
    expect(hosts).toEqual(["new.example.com", "old.example.com"]);
    expect(screen.queryByText("theirs.example.org")).toBeNull();
    expect(screen.getByRole("heading", { name: /Waiting/ })).toHaveTextContent(
      "2",
    );
  });

  it("says when nothing waits, and when requests are still loading", async () => {
    await workspaces.refresh();
    render(Network);
    expect(await screen.findByText(/Loading requests/)).toBeInTheDocument();
    await load();
    expect(
      await screen.findByText("Nothing is waiting for demo."),
    ).toBeInTheDocument();
  });

  it("allows a request with one click, and the row leaves", async () => {
    inbox.add(
      request(1, { workspace: "demo" as never, host: "a.example.com" }),
      "example.com",
    );
    await load();
    render(Network);
    await fireEvent.click(
      await screen.findByRole("button", { name: /^Allow/ }),
    );
    await vi.waitFor(() =>
      expect(
        screen.getByText("Nothing is waiting for demo."),
      ).toBeInTheDocument(),
    );
    expect(inbox.calls).toContain("POST /api/pending/{id}/approve");
  });

  it("shows the rules that apply, read-only, and links to the rules page", async () => {
    rules.rules = [
      rule(1, {
        pattern: "mine.example.com",
        scope: { type: "workspace", workspace: "demo" },
      }),
      rule(2, { pattern: "everyone.example.com" }),
      rule(3, {
        pattern: "theirs.example.com",
        scope: { type: "workspace", workspace: "other" },
      }),
    ];
    await load();
    render(Network);
    const table = await screen.findByRole("table");
    expect(table).toHaveTextContent("mine.example.com");
    expect(table).toHaveTextContent("everyone.example.com");
    expect(table).not.toHaveTextContent("theirs.example.com");
    expect(within(table).queryAllByRole("button")).toHaveLength(0);
    expect(screen.getByRole("link", { name: "All rules" })).toHaveAttribute(
      "href",
      "/rules",
    );
  });

  it("says so when no rule applies yet", async () => {
    await load();
    render(Network);
    expect(
      await screen.findByText(/No rule applies to demo yet/),
    ).toBeInTheDocument();
  });

  it("shows nothing for a workspace it doesn't know", async () => {
    url.id = "nope";
    await load();
    const { container } = render(Network);
    expect(container.textContent?.trim()).toBe("");
  });
});

describe("the settings tab", () => {
  beforeEach(() => {
    url.pathname = "/workspaces/demo/settings";
  });

  async function open() {
    await load();
    render(Settings);
    return screen.findByLabelText(
      "Memory for this workspace",
    ) as Promise<HTMLSelectElement>;
  }

  it("shows each setting with where its value comes from", async () => {
    const memory = await open();
    expect(memory.value).toBe("");
    expect(
      screen.getByText(/A change applies at the next restart/),
    ).toBeInTheDocument();
    expect(screen.getAllByText("global setting").length).toBeGreaterThan(0);
    expect(screen.getAllByText("puddle's default").length).toBeGreaterThan(0);
    for (const label of [
      "This computer (loopback)",
      "Private networks",
      "Link-local",
      "Cloud metadata",
      "Other special ranges",
      "Pages reading the clipboard",
    ]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    expect(document.getElementById("local-destinations")).not.toBeNull();
  });

  it("saves a memory choice at once and says the next start applies it", async () => {
    const memory = await open();
    await fireEvent.change(memory, { target: { value: "16384" } });
    await screen.findByText("Memory saved.");
    expect(api.overrides["demo"]?.memory).toBe(16_384);
    expect(
      await screen.findByText(
        "The new memory applies the next time the workspace starts.",
      ),
    ).toBeInTheDocument();
    await fireEvent.change(memory, { target: { value: "" } });
    await vi.waitFor(() => expect(api.overrides["demo"]?.memory).toBeNull());
  });

  it("doesn't mention a restart for a workspace that isn't running", async () => {
    api.list = [workspace("demo", { status: "stopped" })];
    const memory = await open();
    await fireEvent.change(memory, { target: { value: "4096" } });
    await screen.findByText("Memory saved.");
    expect(screen.queryByText(/applies the next time/)).toBeNull();
  });

  it("turns direct SSH off or back to the global default at once, and asks the trust text before on", async () => {
    await open();
    const select = screen.getByLabelText(
      "Allow direct SSH",
    ) as HTMLSelectElement;
    expect(select.value).toBe("inherit");
    await fireEvent.change(select, { target: { value: "on" } });
    expect(workspaceActions.trustOpen).toBe(true);
    expect(workspaceActions.trustFor?.name).toBe("demo");
    expect(api.overrides["demo"]?.direct_ssh ?? null).toBeNull();
    expect(select.value).toBe("inherit");
    await fireEvent.change(select, { target: { value: "off" } });
    await screen.findByText("Allow direct SSH saved.");
    expect(api.overrides["demo"]?.direct_ssh).toBe(false);
    await fireEvent.change(select, { target: { value: "inherit" } });
    await vi.waitFor(() =>
      expect(api.overrides["demo"]?.direct_ssh).toBeNull(),
    );
  });

  it("saves a local toggle and the clipboard, keeping the others as they were", async () => {
    await open();
    await fireEvent.change(screen.getByLabelText("Private networks"), {
      target: { value: "on" },
    });
    await screen.findByText("Private networks saved.");
    expect(api.overrides["demo"]?.local_toggles.private).toBe(true);
    expect(api.overrides["demo"]?.local_toggles.loopback).toBeNull();
    await fireEvent.change(
      screen.getByLabelText("Pages reading the clipboard"),
      {
        target: { value: "deny" },
      },
    );
    await screen.findByText("Clipboard saved.");
    expect(api.overrides["demo"]?.clipboard_read).toBe("deny");
    expect(api.overrides["demo"]?.local_toggles.private).toBe(true);
    await fireEvent.change(
      screen.getByLabelText("Pages reading the clipboard"),
      {
        target: { value: "inherit" },
      },
    );
    await vi.waitFor(() =>
      expect(api.overrides["demo"]?.clipboard_read).toBeNull(),
    );
    await fireEvent.change(screen.getByLabelText("Private networks"), {
      target: { value: "off" },
    });
    await vi.waitFor(() =>
      expect(api.overrides["demo"]?.local_toggles.private).toBe(false),
    );
  });

  it("puts the choice back and says why when the save is refused", async () => {
    const memory = await open();
    api.refuse.set("PUT /api/settings/workspaces/{workspace}", {
      status: 422,
      message: "memory is too small",
    });
    await fireEvent.change(memory, { target: { value: "4096" } });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "memory is too small",
    );
    expect(memory.value).toBe("");
    api.refuse.set("PUT /api/settings/workspaces/{workspace}", {
      status: 422,
      message: "no",
    });
    const toggle = screen.getByLabelText("Link-local") as HTMLSelectElement;
    await fireEvent.change(toggle, { target: { value: "on" } });
    await vi.waitFor(() => expect(toggle.value).toBe("inherit"));
    api.refuse.set("PUT /api/settings/workspaces/{workspace}", {
      status: 422,
      message: "no",
    });
    const clipboard = screen.getByLabelText(
      "Pages reading the clipboard",
    ) as HTMLSelectElement;
    await fireEvent.change(clipboard, { target: { value: "allow" } });
    await vi.waitFor(() => expect(clipboard.value).toBe("inherit"));
  });

  it("says when the settings can't be read, and while they load", async () => {
    await load();
    api.refuse.set("GET /api/settings/workspaces/{workspace}", {
      status: 500,
      message: "x",
    });
    render(Settings);
    expect(screen.getByText(/Loading settings/)).toBeInTheDocument();
    expect(
      await screen.findByText(/Couldn't read this workspace's settings/),
    ).toBeInTheDocument();
  });

  it("shows nothing for a workspace it doesn't know", async () => {
    url.id = "nope";
    await load();
    const { container } = render(Settings);
    expect(container.textContent?.trim()).toBe("");
  });
});

describe("the tabs that come later", () => {
  it.each([
    ["Environment", Environment],
    ["Shell init", ShellInit],
    ["Ports", Ports],
  ])("%s says it is not available yet", (name, component) => {
    render(component);
    expect(screen.getByRole("heading", { level: 2, name })).toBeInTheDocument();
    expect(
      screen.getByText("This part of the workspace page is not available yet."),
    ).toBeInTheDocument();
  });
});
