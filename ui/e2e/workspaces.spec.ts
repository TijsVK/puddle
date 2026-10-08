// SPDX-License-Identifier: GPL-3.0-or-later
// The workspace screens against the real API on the fixture backend (fake workspace service).
// Every test starts from the `lived-in` scenario on its worker's own backend: web-shop running,
// docs-site stopped with unsaved work, data-tools never started, and requests waiting for each.
// Operations finish at once unless a test holds them (`hold_workspaces`) to look at the busy
// state; the page clock is the fixture's.
import type { APIRequestContext, Locator, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

interface Ws {
  name: string;
  status: string;
  busy: string | null;
  direct_ssh: boolean;
  memory_mib: number;
}

async function workspaceList(
  request: APIRequestContext,
  backend: Backend,
): Promise<Ws[]> {
  const response = await request.get("/api/workspaces", {
    headers: auth(backend),
  });
  return ((await response.json()) as { workspaces: Ws[] }).workspaces;
}

async function pendingCount(
  request: APIRequestContext,
  backend: Backend,
): Promise<number> {
  const response = await request.get("/api/pending", {
    headers: auth(backend),
  });
  return ((await response.json()) as { requests: unknown[] }).requests.length;
}

test.beforeEach(async ({ backend }) => {
  await backend.control.reset("lived-in");
});

async function openList(page: Page, backend: Backend, path = "/workspaces") {
  await backend.installClock(page);
  await backend.signIn(page);
  await page.goto(path);
  await expect(
    page.getByRole("heading", { level: 1, name: "Workspaces" }),
  ).toBeVisible();
}

const card = (page: Page, name: string): Locator =>
  page.getByRole("article", { name });

const toast = (page: Page, text: string | RegExp): Locator =>
  page.getByRole("status").filter({ hasText: text });

async function openDetail(
  page: Page,
  backend: Backend,
  name: string,
  tab = "",
): Promise<void> {
  await backend.installClock(page);
  await backend.signIn(page);
  await page.goto(`/workspaces/${name}${tab ? `/${tab}` : ""}`);
  await expect(
    page.getByRole("heading", { level: 1, name, exact: true }),
  ).toBeVisible();
}

test.describe("the list and the start screen", () => {
  test("the app starts on the workspaces, with a strip for waiting requests", async ({
    page,
    request,
    backend,
  }) => {
    await backend.installClock(page);
    await backend.signIn(page);
    await page.goto("/");
    await expect(page).toHaveURL(/\/workspaces$/);
    const waiting = await pendingCount(request, backend);
    expect(waiting).toBeGreaterThan(3);
    const strip = page
      .getByRole("status")
      .filter({ hasText: "requests waiting" });
    await expect(strip).toContainText(`${waiting} requests waiting`);
    await expect(strip).toContainText("Latest:");
    await strip.getByRole("link", { name: "Review" }).click();
    await expect(page).toHaveURL(/\/inbox$/);
  });

  test("a card per workspace with its state, size and waiting requests", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    await expect(page.getByRole("article")).toHaveCount(3);
    const running = card(page, "web-shop");
    await expect(running).toContainText("Running");
    await expect(running).toContainText("https://github.com/acme/web-shop.git");
    await expect(running).toContainText("6 GiB of 32 GiB used");
    await expect(running).toContainText("14 days ago");
    await expect(running.getByRole("link", { name: /waiting$/ })).toBeVisible();
    await expect(card(page, "docs-site")).toContainText("Stopped");
    await expect(card(page, "docs-site")).toContainText("4 GiB memory");
    await expect(card(page, "data-tools")).toContainText("Not started");
    await expect(
      running.getByRole("button", { name: "Connect to web-shop" }),
    ).toBeEnabled();
    await expect(running).not.toContainText("Trusted");
    await expect(
      card(page, "docs-site").getByRole("button", { name: "Start docs-site" }),
    ).toBeEnabled();
  });

  test("no workspaces shows what to do", async ({ page, backend }) => {
    await backend.control.reset("empty");
    await openList(page, backend);
    await expect(
      page.getByRole("heading", { name: "No workspaces yet" }),
    ).toBeVisible();
    await expect(page.getByText("requests waiting")).toHaveCount(0);
    await page.getByRole("button", { name: "New workspace" }).last().click();
    await expect(
      page.getByRole("dialog", { name: "New workspace" }),
    ).toBeVisible();
  });

  test("a card opens the details", async ({ page, backend }) => {
    await openList(page, backend);
    await card(page, "docs-site")
      .getByRole("link", { name: /^Details/ })
      .click();
    await expect(page).toHaveURL(/\/workspaces\/docs-site$/);
    await expect(
      page.getByRole("heading", { level: 1, name: "docs-site" }),
    ).toBeVisible();
  });

  test("a request that arrives updates the strip and the card live", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    const before = await pendingCount(request, backend);
    await expect(page.getByText(`${before} requests waiting`)).toBeVisible();
    await backend.control.step({
      do: "request",
      workspace: "data-tools",
      host: "live.example.org",
    });
    await expect(
      page.getByText(`${before + 1} requests waiting`),
    ).toBeVisible();
    await expect(
      page.getByRole("status").filter({ hasText: "live.example.org" }),
    ).toBeVisible();
  });
});

test.describe("creating", () => {
  async function openCreate(page: Page): Promise<Locator> {
    await page.getByRole("button", { name: "New workspace" }).first().click();
    const dialog = page.getByRole("dialog", { name: "New workspace" });
    await expect(dialog).toBeVisible();
    return dialog;
  }

  test("creates from a repository URL, naming it after the repository", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.step({ do: "hold_workspaces" });
    const dialog = await openCreate(page);
    await expect(dialog.getByLabel("Git repository (HTTPS)")).toBeFocused();
    await dialog
      .getByLabel("Git repository (HTTPS)")
      .fill("https://github.com/acme/Ledger_Service.git");
    await expect(dialog.getByLabel("Name")).toHaveValue("ledger-service");
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(dialog).toHaveCount(0);
    const created = card(page, "ledger-service");
    await expect(created).toContainText("Creating");
    await expect(
      created.getByRole("button", { name: "Start ledger-service" }),
    ).toBeDisabled();
    // The service reports where it is.
    await backend.control.emit({
      type: "workspace_progress",
      workspace: "ledger-service",
      step: "cloning",
      detail: "https://github.com/acme/Ledger_Service.git",
    });
    await expect(created).toContainText("Cloning the repository");
    await expect(created).toContainText("step 3 of 3");
    await backend.control.step({ do: "release_workspaces" });
    await expect(toast(page, "Created ledger-service.")).toBeVisible();
    await expect(created).toContainText("Not started");
    await expect(created).not.toContainText("Cloning");
    const made = (await workspaceList(request, backend)).find(
      (w) => w.name === "ledger-service",
    );
    expect(made?.busy).toBeNull();
  });

  test("a typed name is kept; memory and image go to the API", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    const dialog = await openCreate(page);
    await dialog.getByLabel("Name").fill("my-name");
    await dialog
      .getByLabel("Git repository (HTTPS)")
      .fill("https://example.org/other.git");
    await expect(dialog.getByLabel("Name")).toHaveValue("my-name");
    await dialog.getByText("Image and memory").click();
    await dialog.getByLabel("Memory (GiB)").fill("3");
    await dialog.getByLabel("Image").fill("ghcr.io/acme/dev:1");
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(card(page, "my-name")).toBeVisible();
    const made = (await workspaceList(request, backend)).find(
      (w) => w.name === "my-name",
    );
    expect(made?.memory_mib).toBe(3072);
  });

  test("checks the fields before asking; an SSH address gets the message", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    const before = (await workspaceList(request, backend)).length;
    const dialog = await openCreate(page);
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(dialog.getByRole("alert")).toHaveCount(2);
    await expect(dialog.getByLabel("Git repository (HTTPS)")).toBeFocused();
    await dialog
      .getByLabel("Git repository (HTTPS)")
      .fill("git@github.com:acme/web-shop.git");
    await dialog.getByLabel("Name").fill("Bad Name");
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(dialog.getByRole("alert").first()).toContainText(
      "SSH remotes are not supported yet; use the repository's HTTPS URL instead.",
    );
    await expect(dialog.getByLabel("Name")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    await expect(dialog.getByRole("alert").nth(1)).toContainText(
      "lowercase letters",
    );
    expect((await workspaceList(request, backend)).length).toBe(before);
  });

  test("a name that is taken is refused by the service and shown at the name", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    const before = (await workspaceList(request, backend)).length;
    const dialog = await openCreate(page);
    await dialog
      .getByLabel("Git repository (HTTPS)")
      .fill("https://github.com/acme/web-shop.git");
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(dialog.getByLabel("Name")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    await expect(dialog.getByRole("alert")).toContainText("already exists");
    await expect(dialog.getByLabel("Name")).toBeFocused();
    expect((await workspaceList(request, backend)).length).toBe(before);
  });

  test("a clone that fails says why and leaves nothing behind", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.step({
      do: "fail_workspace",
      operation: "create",
      reason: "repository not found",
    });
    const dialog = await openCreate(page);
    await dialog
      .getByLabel("Git repository (HTTPS)")
      .fill("https://github.com/acme/missing.git");
    await dialog.getByRole("button", { name: "Create workspace" }).click();
    await expect(
      toast(page, /Creating missing failed: repository not found/),
    ).toBeVisible();
    await expect(card(page, "missing")).toHaveCount(0);
    expect(
      (await workspaceList(request, backend)).some((w) => w.name === "missing"),
    ).toBe(false);
  });

  test("Cancel and Escape close it and forget what was typed", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    const dialog = await openCreate(page);
    await dialog.getByLabel("Name").fill("half-done");
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "New workspace" }).first(),
    ).toBeFocused();
    const again = await openCreate(page);
    await expect(again.getByLabel("Name")).toHaveValue("");
    await again.getByRole("button", { name: "Cancel" }).click();
    await expect(again).toHaveCount(0);
  });
});

test.describe("start and stop", () => {
  test("start shows progress, then the workspace runs", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.step({ do: "hold_workspaces" });
    const docs = card(page, "docs-site");
    await docs.getByRole("button", { name: "Start docs-site" }).click();
    await expect(docs).toContainText("Starting");
    await expect(docs.getByRole("status")).toBeVisible();
    await backend.control.emit({
      type: "workspace_progress",
      workspace: "docs-site",
      step: "syncing",
      detail: null,
    });
    await expect(docs).toContainText("Syncing your settings");
    await expect(docs).toContainText("step 2 of 2");
    await backend.control.step({ do: "release_workspaces" });
    await expect(toast(page, "docs-site is running.")).toBeVisible();
    await expect(docs).toContainText("Running");
    await expect(
      docs.getByRole("button", { name: "Connect to docs-site" }),
    ).toBeEnabled();
    expect(
      (await workspaceList(request, backend)).find(
        (w) => w.name === "docs-site",
      )?.status,
    ).toBe("running");
  });

  test("a start that fails ends crashed and shows the reason until dismissed", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.step({
      do: "fail_workspace",
      operation: "start",
      reason: "the VM did not boot",
    });
    const docs = card(page, "docs-site");
    await docs.getByRole("button", { name: "Start docs-site" }).click();
    await expect(
      toast(page, "Starting docs-site failed: the VM did not boot"),
    ).toBeVisible();
    await expect(docs).toContainText("Crashed");
    const failure = docs.getByRole("alert");
    await expect(failure).toContainText("Starting failed");
    await expect(failure).toContainText("the VM did not boot");
    await expect(
      docs.getByRole("button", { name: "Start docs-site" }),
    ).toBeEnabled();
    await failure.getByRole("button", { name: "Dismiss" }).click();
    await expect(docs.getByRole("alert")).toHaveCount(0);
  });

  test("stop shows progress and ends stopped; a stop that fails stays running", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    const shop = card(page, "web-shop");
    await backend.control.step({ do: "hold_workspaces" });
    await shop.getByRole("button", { name: "Stop web-shop" }).click();
    await expect(shop).toContainText("Stopping");
    await expect(
      shop.getByRole("button", { name: "Stop web-shop" }),
    ).toBeDisabled();
    await backend.control.step({ do: "release_workspaces" });
    await expect(toast(page, "Stopped web-shop.")).toBeVisible();
    await expect(shop).toContainText("Stopped");

    await backend.control.step({ do: "release_workspaces" });
    await shop.getByRole("button", { name: "Start web-shop" }).click();
    await expect(shop).toContainText("Running");
    await backend.control.step({
      do: "fail_workspace",
      operation: "stop",
      reason: "the guest did not answer",
    });
    await shop.getByRole("button", { name: "Stop web-shop" }).click();
    await expect(
      toast(page, "Stopping web-shop failed: the guest did not answer"),
    ).toBeVisible();
    await expect(shop).toContainText("Running");
  });

  test("a workspace stopped from elsewhere changes the card at once", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.emit({
      type: "status_changed",
      workspace: "web-shop",
      status: "stopped",
    });
    await expect(card(page, "web-shop")).toContainText("Stopped");
    await expect(
      card(page, "web-shop").getByRole("button", { name: "Start web-shop" }),
    ).toBeEnabled();
  });

  test("a restarted service is picked up again", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    await backend.control.restart();
    await request.post("/api/workspaces/web-shop/stop", {
      headers: auth(backend),
    });
    await expect(card(page, "web-shop")).toContainText("Stopped", {
      timeout: 20_000,
    });
  });
});

test.describe("connecting", () => {
  test("the step puts the browser editor first and keeps direct SSH off until allowed", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    await card(page, "web-shop")
      .getByRole("button", { name: "Connect to web-shop" })
      .click();
    const step = page.getByRole("dialog", { name: "Connect to web-shop" });
    await expect(step.getByRole("heading", { level: 3 })).toHaveText([
      "In the browser",
      "On this computer",
    ]);
    await expect(
      step.getByRole("button", { name: "Open in the browser" }),
    ).toBeDisabled();
    await expect(
      step.getByRole("checkbox", { name: "Allow direct SSH" }),
    ).not.toBeChecked();
    await expect(
      step.getByRole("button", { name: "Open in VS Code" }),
    ).toBeDisabled();
  });

  test("allowing direct SSH says what it trusts, then marks the workspace trusted", async ({
    page,
    request,
    backend,
  }) => {
    await openList(page, backend);
    const shop = card(page, "web-shop");
    await shop.getByRole("button", { name: "Connect to web-shop" }).click();
    const step = page.getByRole("dialog", { name: "Connect to web-shop" });
    await step.getByRole("checkbox", { name: "Allow direct SSH" }).click();
    const trust = page.getByRole("alertdialog", {
      name: "Allow direct SSH to web-shop?",
    });
    await expect(trust).toContainText("trusted workspace");
    await expect(trust).toContainText("GitHub token");
    await expect(trust.getByRole("button", { name: "Cancel" })).toBeFocused();
    await trust.getByRole("button", { name: "Cancel" }).click();
    await expect(
      step.getByRole("checkbox", { name: "Allow direct SSH" }),
    ).not.toBeChecked();
    expect(
      (await workspaceList(request, backend)).find((w) => w.name === "web-shop")
        ?.direct_ssh,
    ).toBe(false);

    await step.getByRole("checkbox", { name: "Allow direct SSH" }).click();
    await trust.getByRole("button", { name: "Allow direct SSH" }).click();
    await expect(
      toast(page, "Direct SSH is on for web-shop: it is trusted now."),
    ).toBeVisible();
    await expect(
      step.getByRole("checkbox", { name: "Allow direct SSH" }),
    ).toBeChecked();
    await expect(step).toContainText("Trusted");
    await expect(shop).toContainText("Trusted");

    await step.getByRole("button", { name: "Open in VS Code" }).click();
    await expect(toast(page, "Opening web-shop in VS Code.")).toBeVisible();
  });

  test("turning it off needs no question and drops the trusted mark", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop");
    await page.getByRole("button", { name: "Connect to web-shop" }).click();
    const step = page.getByRole("dialog", { name: "Connect to web-shop" });
    await step.getByRole("checkbox", { name: "Allow direct SSH" }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Allow direct SSH" })
      .click();
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByText("Trusted").first()).toBeVisible();
    await step.getByRole("checkbox", { name: "Allow direct SSH" }).click();
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(toast(page, "Direct SSH is off for web-shop.")).toBeVisible();
    await expect
      .poll(
        async () =>
          (await workspaceList(request, backend)).find(
            (w) => w.name === "web-shop",
          )?.direct_ssh,
      )
      .toBe(false);
  });
});

test.describe("deleting", () => {
  test("lists what would be lost and needs the box ticked", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site");
    await page.getByRole("button", { name: "Delete workspace…" }).click();
    const dialog = page.getByRole("alertdialog", { name: "Delete docs-site?" });
    await expect(dialog).toContainText("Uncommitted changes");
    await expect(dialog).toContainText("M content/intro.md");
    await expect(dialog).toContainText("?? drafts/launch.md");
    await expect(dialog).toContainText("3f2a9c1 Rewrite the intro");
    await expect(dialog).toContainText("stash@{0}");
    await expect(dialog).toContainText("scratch");
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
    const remove = dialog.getByRole("button", { name: "Delete workspace" });
    await expect(remove).toBeDisabled();
    await dialog
      .getByRole("checkbox", { name: /I understand this work will be lost/ })
      .click();
    await expect(remove).toBeEnabled();
    await remove.click();
    await expect(toast(page, "Deleted docs-site.")).toBeVisible();
    await expect(page).toHaveURL(/\/workspaces$/);
    await expect(page.getByRole("article")).toHaveCount(2);
    expect(
      (await workspaceList(request, backend)).some(
        (w) => w.name === "docs-site",
      ),
    ).toBe(false);
  });

  test("Cancel deletes nothing and returns to the button", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site");
    const button = page.getByRole("button", { name: "Delete workspace…" });
    await button.click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Cancel" })
      .click();
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(button).toBeFocused();
    expect((await workspaceList(request, backend)).length).toBe(3);
  });

  test("a clean workspace says so, and still asks", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "data-tools");
    await page.getByRole("button", { name: "Delete workspace…" }).click();
    const dialog = page.getByRole("alertdialog");
    await expect(dialog).toContainText("found nothing unsaved");
    await expect(
      dialog.getByRole("button", { name: "Delete workspace" }),
    ).toBeDisabled();
    await dialog.getByRole("checkbox", { name: /Delete data-tools/ }).click();
    await dialog.getByRole("button", { name: "Delete workspace" }).click();
    await expect(toast(page, "Deleted data-tools.")).toBeVisible();
  });

  test("a running workspace can't be deleted", async ({ page, backend }) => {
    await openDetail(page, backend, "web-shop");
    await expect(
      page.getByRole("button", { name: "Delete workspace…" }),
    ).toBeDisabled();
    await expect(
      page.getByText("Stop the workspace before deleting it."),
    ).toBeVisible();
  });

  test("a delete that fails says why and the workspace stays", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "data-tools");
    await backend.control.step({
      do: "fail_workspace",
      operation: "delete",
      reason: "the volume is in use",
    });
    await page.getByRole("button", { name: "Delete workspace…" }).click();
    const dialog = page.getByRole("alertdialog");
    await dialog.getByRole("checkbox").click();
    await dialog.getByRole("button", { name: "Delete workspace" }).click();
    await expect(
      toast(page, "Deleting data-tools failed: the volume is in use"),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { level: 1, name: "data-tools" }),
    ).toBeVisible();
    expect(
      (await workspaceList(request, backend)).some(
        (w) => w.name === "data-tools",
      ),
    ).toBe(true);
  });

  test("deleted from elsewhere takes the open page back to the list", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "data-tools");
    const check = await request.get("/api/workspaces/data-tools/delete-check", {
      headers: auth(backend),
    });
    const { fingerprint } = (await check.json()) as { fingerprint: string };
    await request.delete("/api/workspaces/data-tools", {
      headers: auth(backend),
      data: { confirm: true, fingerprint },
    });
    await expect(page).toHaveURL(/\/workspaces$/, { timeout: 15_000 });
    await expect(page.getByRole("article")).toHaveCount(2);
  });

  test("an unknown workspace says so", async ({ page, backend }) => {
    await backend.installClock(page);
    await backend.signIn(page);
    await page.goto("/workspaces/nope");
    await expect(
      page.getByRole("heading", { name: "No such workspace" }),
    ).toBeVisible();
    await page.getByRole("link", { name: "Back to the workspaces" }).click();
    await expect(page).toHaveURL(/\/workspaces$/);
  });
});

test.describe("the detail page", () => {
  test("overview: state, resources, network summary and the tabs", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop");
    const tabs = page.getByRole("navigation", { name: "Workspace sections" });
    await expect(tabs.getByRole("link")).toHaveText([
      /Overview/,
      /Network/,
      /Git/,
      /Environment/,
      /Shell init/,
      /Ports/,
      /Settings/,
    ]);
    await expect(tabs.getByRole("link", { name: /Overview/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(page.getByText("ws-web-shop")).toBeVisible();
    await expect(
      page.getByText("global default").or(page.getByText("puddle's default")),
    ).toBeVisible();
    await expect(page.getByRole("region", { name: "Network" })).toContainText(
      /\d+ waiting · 3 workspace rules/,
    );
    await expect(page.getByText("6 GiB of 32 GiB used")).toBeVisible();
  });

  test("a kill by the out-of-memory killer shows a notice that links to the memory setting", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop");
    await backend.control.script("oom");
    const notice = page.getByRole("alert");
    await expect(notice).toContainText("Out of memory");
    await expect(notice).toContainText("node");
    await expect(notice).toContainText("process 4242");
    await notice.getByRole("link", { name: "Change memory" }).click();
    await expect(page).toHaveURL(/\/workspaces\/web-shop\/settings$/);
    await page.getByRole("link", { name: "Overview" }).click();
    await expect(page.getByRole("alert")).toContainText("Out of memory");
    await page.getByRole("button", { name: "Dismiss", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveCount(0);
  });

  test("the card on the list flags the kill too", async ({ page, backend }) => {
    await openList(page, backend);
    await backend.control.script("oom");
    await expect(card(page, "web-shop")).toContainText("Out of memory");
  });

  test("reclaim space runs and reports", async ({ page, backend }) => {
    await openDetail(page, backend, "web-shop");
    await backend.control.step({ do: "hold_workspaces" });
    await page.getByRole("button", { name: "Reclaim space" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: "Reclaiming" }),
    ).toBeVisible();
    await backend.control.step({ do: "release_workspaces" });
    await expect(
      toast(page, "Reclaimed free space on web-shop."),
    ).toBeVisible();
  });

  test("the later tabs are there and say they are not ready", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop");
    for (const tab of ["Environment", "Shell init", "Ports"]) {
      await page.getByRole("link", { name: tab }).click();
      await expect(
        page.getByText("This part of the workspace page is not available yet."),
      ).toBeVisible();
      await expect(page.getByRole("link", { name: tab })).toHaveAttribute(
        "aria-current",
        "page",
      );
    }
  });

  test("start and stop work from the detail page", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site");
    await page.getByRole("button", { name: "Start docs-site" }).click();
    await expect(toast(page, "docs-site is running.")).toBeVisible();
    await page.getByRole("button", { name: "Stop docs-site" }).click();
    await expect(toast(page, "Stopped docs-site.")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Start docs-site" }),
    ).toBeEnabled();
  });
});

test.describe("the network tab", () => {
  test("shows this workspace's waiting requests and the rules that apply", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop", "network");
    const waiting = page.locator("li.req");
    await expect(waiting.first()).toBeVisible();
    for (const text of await waiting.allTextContents())
      expect(text).toContain("web-shop");
    await expect(page.getByText("telemetry.example.net").first()).toBeVisible();
    const rules = page.getByRole("table");
    await expect(rules).toContainText("registry.npmjs.org"); // for every workspace
    await expect(rules).toContainText("api.example.com");
    await expect(rules).not.toContainText("ads.example.net"); // docs-site's rule
    await expect(
      page
        .getByRole("navigation", { name: "Workspace sections" })
        .getByRole("link", { name: /Network/ }),
    ).toContainText(String(await waiting.count()));
    await expect(rules.getByRole("button")).toHaveCount(0);
  });

  test("a decision made here removes the row, counts down the tab and can be undone", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site", "network");
    const rows = page.locator("li.req");
    // The heading shows before the requests are read: count only once a row is there.
    await expect(rows.first()).toBeVisible();
    const n = await rows.count();
    const total = await pendingCount(request, backend);
    await rows
      .first()
      .getByRole("button", { name: /^Allow/ })
      .first()
      .click();
    await expect(rows).toHaveCount(n - 1);
    await expect(toast(page, /^Allowed/)).toBeVisible();
    expect(await pendingCount(request, backend)).toBe(total - 1);
    await page.getByRole("button", { name: "Undo" }).click();
    await expect(toast(page, /Undone/)).toBeVisible();
  });

  test("nothing waiting says so", async ({ page, backend }) => {
    await backend.control.reset("empty");
    await backend.control.reset("lived-in");
    await openDetail(page, backend, "data-tools", "network");
    // data-tools has requests in this scenario; decide them all.
    const rows = page.locator("li.req");
    await expect(rows.first()).toBeVisible();
    // Wait for each row to go before the next click: a row that is still on its way out can
    // be counted but not clicked, and the click then waits for a button that never returns.
    for (let left = await rows.count(); left > 0; left -= 1) {
      await rows.first().getByRole("button", { name: /^Deny/ }).click();
      await expect(rows).toHaveCount(left - 1);
    }
    await expect(
      page.getByText("Nothing is waiting for data-tools."),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Waiting" })).toBeFocused();
  });
});

test.describe("the settings tab", () => {
  test("memory: choose a size, it is kept and applies at the next start", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop", "settings");
    const memory = page.getByLabel("Memory for this workspace");
    await expect(memory).toHaveValue("");
    await expect(
      page.getByText(/A change applies at the next restart/),
    ).toBeVisible();
    await memory.selectOption({ label: "16 GiB" });
    await expect(page.getByText("Memory saved.")).toBeVisible();
    await expect(
      page.getByText(
        "The new memory applies the next time the workspace starts.",
      ),
    ).toBeVisible();
    await expect(
      page.locator(".chip", { hasText: "this workspace" }).first(),
    ).toBeVisible();
    const stored = await request.get("/api/settings/workspaces/web-shop", {
      headers: auth(backend),
    });
    const view = (await stored.json()) as {
      overrides: { memory: number | null };
    };
    expect(view.overrides.memory).toBe(16_384);
    await page.reload();
    await expect(page.getByLabel("Memory for this workspace")).toHaveValue(
      "16384",
    );
    await page.getByLabel("Memory for this workspace").selectOption("");
    await expect(page.getByText("Memory saved.")).toBeVisible();
    const again = await request.get("/api/settings/workspaces/web-shop", {
      headers: auth(backend),
    });
    expect(
      ((await again.json()) as { overrides: { memory: unknown } }).overrides
        .memory,
    ).toBeNull();
  });

  test("local destinations and clipboard follow the global setting until set here", async ({
    page,
    request,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop", "settings");
    const loopback = page.getByLabel("This computer (loopback)");
    await expect(loopback).toHaveValue("inherit");
    await expect(loopback.locator("option").first()).toContainText(
      "Use the global setting (not allowed)",
    );
    await loopback.selectOption("on");
    await expect(
      page.getByText("This computer (loopback) saved."),
    ).toBeVisible();
    const clipboard = page.getByLabel("Pages reading the clipboard");
    await expect(clipboard).toHaveValue("inherit");
    await clipboard.selectOption("deny");
    await expect(page.getByText("Clipboard saved.")).toBeVisible();
    const stored = (await (
      await request.get("/api/settings/workspaces/web-shop", {
        headers: auth(backend),
      })
    ).json()) as {
      overrides: {
        local_toggles: { loopback: boolean | null; private: boolean | null };
        clipboard_read: string | null;
      };
      effective: {
        local_toggles: { loopback: { source: string; value: boolean } };
      };
    };
    expect(stored.overrides.local_toggles.loopback).toBe(true);
    expect(stored.overrides.local_toggles.private).toBeNull();
    expect(stored.overrides.clipboard_read).toBe("deny");
    expect(stored.effective.local_toggles.loopback).toEqual({
      value: true,
      source: "workspace",
    });
    await loopback.selectOption("inherit");
    await expect(
      page.getByText("This computer (loopback) saved."),
    ).toBeVisible();
  });

  test("a refused save says why and puts the choice back", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "web-shop", "settings");
    await page.route("**/api/settings/workspaces/web-shop", async (route) => {
      if (route.request().method() === "PUT") {
        await route.fulfill({
          status: 422,
          contentType: "application/json",
          body: JSON.stringify({
            error: "invalid",
            message: "memory is too small",
          }),
        });
      } else await route.continue();
    });
    const memory = page.getByLabel("Memory for this workspace");
    await memory.selectOption({ label: "4 GiB" });
    await expect(page.getByRole("alert")).toContainText("memory is too small");
    await expect(memory).toHaveValue("");
  });
});

test.describe("keyboard only", () => {
  test("create, start, and delete without a pointer", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    await page.getByRole("button", { name: "New workspace" }).first().focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: "New workspace" });
    await expect(dialog.getByLabel("Git repository (HTTPS)")).toBeFocused();
    await page.keyboard.type("https://github.com/acme/keys.git");
    await page.keyboard.press("Enter");
    await expect(dialog).toHaveCount(0);
    const created = card(page, "keys");
    await expect(created).toContainText("Not started");
    await expect(
      page.getByRole("button", { name: "New workspace" }).first(),
    ).toBeFocused();

    await created.getByRole("button", { name: "Start keys" }).focus();
    await page.keyboard.press("Enter");
    await expect(created).toContainText("Running");
    await created.getByRole("button", { name: "Stop keys" }).focus();
    await page.keyboard.press("Enter");
    await expect(created).toContainText("Stopped");

    await created.getByRole("link", { name: /^Details/ }).focus();
    await page.keyboard.press("Enter");
    const del = page.getByRole("button", { name: "Delete workspace…" });
    await del.focus();
    await page.keyboard.press("Enter");
    const confirm = page.getByRole("alertdialog");
    await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(confirm.getByRole("checkbox")).toBeFocused();
    await page.keyboard.press("Space");
    await expect(confirm.getByRole("checkbox")).toBeChecked();
    await page.keyboard.press("Tab"); // Cancel again: the safe button comes before Delete
    await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(
      confirm.getByRole("button", { name: "Delete workspace" }),
    ).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/workspaces$/);
    await expect(card(page, "keys")).toHaveCount(0);
  });

  test("Escape closes the delete dialog and focus returns to its button", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site");
    const del = page.getByRole("button", { name: "Delete workspace…" });
    await del.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("alertdialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(del).toBeFocused();
  });
});

test.describe("accessibility", () => {
  // One scan costs about a second in WebKit and the whole walk used to be one test, close to
  // its 30 s limit on a loaded host: each stop is a test of its own, so none is near it.
  for (const scheme of ["light", "dark"] as const) {
    test(`axe finds nothing in ${scheme}: list, dialogs and failures`, async ({
      page,
      backend,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await watchCsp(page);
      await openList(page, backend);
      expect(await axeViolations(page), "list").toEqual([]);

      await page.getByRole("button", { name: "New workspace" }).first().click();
      const create = page.getByRole("dialog", { name: "New workspace" });
      await create.getByRole("button", { name: "Create workspace" }).click();
      await expect(create.getByRole("alert")).toHaveCount(2);
      await create.getByText("Image and memory").click();
      expect(await axeViolations(page), "create with errors").toEqual([]);
      await create.getByRole("button", { name: "Cancel" }).click();

      const docs = card(page, "docs-site");
      await docs.getByRole("button", { name: "Start docs-site" }).click();
      await expect(docs).toContainText("Running");
      await docs.getByRole("button", { name: "Connect to docs-site" }).click();
      expect(await axeViolations(page), "connect step").toEqual([]);
      await page.getByRole("checkbox", { name: "Allow direct SSH" }).click();
      expect(await axeViolations(page), "direct SSH trust text").toEqual([]);
      await page.keyboard.press("Escape");
      await page.keyboard.press("Escape");

      await backend.control.step({
        do: "fail_workspace",
        operation: "start",
        reason: "boom",
      });
      await card(page, "data-tools")
        .getByRole("button", { name: "Start data-tools" })
        .click();
      await expect(card(page, "data-tools").getByRole("alert")).toBeVisible();
      expect(await axeViolations(page), "failure and toast").toEqual([]);
      expect(await csp()).toEqual([]);
    });

    test(`axe finds nothing in ${scheme}: the overview with a notice and the delete dialog`, async ({
      page,
      backend,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await watchCsp(page);
      await openDetail(page, backend, "web-shop");
      await backend.control.script("oom");
      await expect(page.getByRole("alert")).toBeVisible();
      expect(await axeViolations(page), "overview with the notice").toEqual([]);

      await page.goto("/workspaces/data-tools");
      await expect(
        page.getByRole("heading", { level: 1, name: "data-tools" }),
      ).toBeVisible();
      await page.getByRole("button", { name: "Delete workspace…" }).click();
      const confirm = page.getByRole("alertdialog");
      await expect(confirm).toBeVisible();
      expect(await axeViolations(page), "delete clean").toEqual([]);
      await page.keyboard.press("Escape");
      expect(await csp()).toEqual([]);
    });

    for (const tab of [
      "network",
      "git",
      "environment",
      "shell-init",
      "ports",
      "settings",
    ]) {
      test(`axe finds nothing in ${scheme}: the ${tab} tab`, async ({
        page,
        backend,
      }) => {
        await page.emulateMedia({ colorScheme: scheme });
        const csp = await watchCsp(page);
        // The notice is up when the tab opens, as it is in use.
        await openDetail(page, backend, "web-shop");
        await backend.control.script("oom");
        await expect(page.getByRole("alert")).toBeVisible();
        await page.goto(`/workspaces/web-shop/${tab}`);
        await expect(
          page.getByRole("heading", { level: 1, name: "web-shop" }),
        ).toBeVisible();
        await expect(page.getByText("Loading")).toHaveCount(0);
        expect(await axeViolations(page), tab).toEqual([]);
        expect(await csp()).toEqual([]);
      });
    }
  }

  test("the delete dialog with a long list passes axe too", async ({
    page,
    backend,
  }) => {
    await openDetail(page, backend, "docs-site");
    await page.getByRole("button", { name: "Delete workspace…" }).click();
    await expect(page.getByRole("alertdialog")).toContainText("stash@{0}");
    expect(await axeViolations(page), "delete with losses").toEqual([]);
  });

  test("the buttons are at least 24 by 24 CSS pixels (WCAG 2.5.8)", async ({
    page,
    backend,
  }) => {
    await openList(page, backend);
    const buttons = await card(page, "web-shop").getByRole("button").all();
    expect(buttons.length).toBeGreaterThanOrEqual(2);
    for (const button of [
      ...buttons,
      ...(await page.getByRole("button", { name: "New workspace" }).all()),
    ]) {
      const box = await button.boundingBox();
      expect(box?.width ?? 0).toBeGreaterThanOrEqual(24);
      expect(box?.height ?? 0).toBeGreaterThanOrEqual(24);
    }
  });
});

test.describe("a workspace whose volume is gone", () => {
  test("says so on the card and the page, and deleting it is allowed and loses nothing", async ({
    page,
    backend,
  }) => {
    await backend.control.reset("volume-missing");
    await openList(page, backend);
    const lost = card(page, "lost-disk");
    await expect(lost).toContainText("Volume missing");
    await expect(lost).toContainText("Restore the volume ws-lost-disk");
    await expect(
      lost.getByRole("button", { name: "Start lost-disk" }),
    ).toBeEnabled();
    expect(await axeViolations(page), "list").toEqual([]);

    await lost.getByRole("link", { name: /^Details/ }).click();
    await expect(page.getByText("Its disk is gone")).toBeVisible();
    await page.getByRole("button", { name: "Delete workspace…" }).click();
    const confirm = page.getByRole("alertdialog");
    await expect(confirm).toContainText("nothing is lost");
    expect(await axeViolations(page), "delete dialog").toEqual([]);
    await confirm.getByRole("checkbox", { name: "Delete lost-disk" }).check();
    await confirm.getByRole("button", { name: "Delete workspace" }).click();
    await expect(page).toHaveURL(/\/workspaces$/);
    await expect(card(page, "lost-disk")).toHaveCount(0);
  });
});
