// SPDX-License-Identifier: GPL-3.0-or-later
// The settings screen against the real API on the fixture backend (in-memory settings). Each
// test has a backend of its own, reset before it. Waits are on conditions (a response, a
// focus), never on key order or time.
import type { APIRequestContext, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

const TERMS = "https://code.visualstudio.com/license/server";

interface Stored {
  sandbox_defaults: Record<string, unknown> & {
    memory: number | null;
    local_toggles: Record<string, boolean | null>;
  };
  vscode_server: {
    server: string | null;
    telemetry: boolean | null;
    auto_update: boolean | null;
  };
  ui: Record<string, unknown>;
}

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

async function stored(
  request: APIRequestContext,
  backend: Backend,
): Promise<Stored> {
  const r = await request.get("/api/settings", { headers: auth(backend) });
  return (await r.json()) as Stored;
}

async function consent(
  request: APIRequestContext,
  backend: Backend,
): Promise<{ state: string; terms_version?: string }> {
  const r = await request.get("/api/consents", { headers: auth(backend) });
  return ((await r.json()) as { vscode_server: { state: string } })
    .vscode_server;
}

async function openSettings(page: Page, backend: Backend) {
  await backend.signIn(page);
  await page.goto("/settings");
  await expect(
    page.getByRole("heading", { level: 2, name: "Appearance" }),
  ).toBeVisible();
}

/** Waits for a settings save to reach the API. */
const saved = (page: Page) =>
  page.waitForResponse(
    (r) => r.request().method() === "PUT" && r.url().endsWith("/api/settings"),
  );

test("shows every section with puddle's defaults, no CSP violations", async ({
  page,
  backend,
}) => {
  const csp = await watchCsp(page);
  await openSettings(page, backend);
  for (const name of [
    "Notifications",
    "Workspaces",
    "Network",
    "Browser VS Code",
    "Git and credentials",
    "Privacy",
    "About",
  ]) {
    await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
  }
  await expect(page.getByLabel("Default memory")).toHaveValue("8192");
  await expect(page.getByLabel("Server", { exact: true })).toHaveValue(
    "code_server",
  );
  await expect(page.getByText(/Open VSX/)).toBeVisible();
  await expect(page.getByText(/sends nothing about you/)).toBeVisible();
  expect(await csp()).toEqual([]);
});

for (const scheme of ["light", "dark"] as const) {
  test(`axe finds nothing on the screen or in the popup in ${scheme}`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openSettings(page, backend);
    expect(await axeViolations(page), "screen").toEqual([]);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    await expect(page.getByRole("dialog")).toBeVisible();
    expect(await axeViolations(page), "popup").toEqual([]);
  });
}

test("the global direct SSH default is off, asks the trust text, and is kept", async ({
  page,
  backend,
}) => {
  await openSettings(page, backend);
  const box = page.getByLabel("Allow direct SSH for new workspaces");
  await expect(box).not.toBeChecked();
  await box.click();
  const trust = page.getByRole("alertdialog", {
    name: "Allow direct SSH for new workspaces?",
  });
  await expect(trust).toContainText("GitHub token");
  expect(await axeViolations(page), "trust text").toEqual([]);
  await trust.getByRole("button", { name: "Cancel" }).click();
  await expect(box).not.toBeChecked();
  await box.click();
  await trust.getByRole("button", { name: "Allow for new workspaces" }).click();
  await expect(page.getByText("Allow direct SSH saved.")).toBeVisible();
  await page.reload();
  await expect(
    page.getByLabel("Allow direct SSH for new workspaces"),
  ).toBeChecked();
});

test("the licences open on request and are scrollable by keyboard", async ({
  page,
  backend,
}) => {
  await openSettings(page, backend);
  await page.getByText("Third-party licences").click();
  const text = page.getByLabel("Third-party licences", { exact: true });
  await expect(text).toContainText("Third-party software shipped");
  await text.focus();
  await expect(text).toBeFocused();
  expect(await axeViolations(page)).toEqual([]);
});

test("the theme is kept by puddle: it comes back after the page forgets everything", async ({
  page,
  backend,
  request,
}) => {
  await openSettings(page, backend);
  const done = saved(page);
  await page.getByLabel("Theme", { exact: true }).selectOption("dark");
  await done;
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  expect((await stored(request, backend)).ui["theme"]).toBe("dark");

  // A new launch has a new origin: nothing in the page's storage survives.
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByLabel("Theme", { exact: true })).toHaveValue("dark");
});

test("changes are saved at once and survive a reload", async ({
  page,
  backend,
  request,
}) => {
  await openSettings(page, backend);
  let done = saved(page);
  await page.getByLabel("Default memory").selectOption("16384");
  await done;
  done = saved(page);
  await page.getByLabel("Private networks").check();
  await done;
  done = saved(page);
  await page.getByLabel("Sound").check();
  await done;
  done = saved(page);
  await page.getByLabel("Closing the window").selectOption("quit");
  await done;

  const now = await stored(request, backend);
  expect(now.sandbox_defaults.memory).toBe(16_384);
  expect(now.sandbox_defaults.local_toggles["private"]).toBe(true);
  expect(now.sandbox_defaults.local_toggles["loopback"]).toBeNull();
  expect(now.ui["sound"]).toBe(true);
  expect(now.ui["close_behaviour"]).toBe("quit");

  await page.reload();
  await expect(page.getByLabel("Default memory")).toHaveValue("16384");
  await expect(page.getByLabel("Private networks")).toBeChecked();
  await expect(page.getByLabel("Sound")).toBeChecked();
  await expect(page.getByLabel("Closing the window")).toHaveValue("quit");
});

test("a reconnection grace outside the range is refused before anything is sent", async ({
  page,
  backend,
  request,
}) => {
  await openSettings(page, backend);
  const grace = page.getByLabel("Reconnection grace (seconds)");
  await grace.fill("5");
  await grace.blur();
  await expect(page.getByText(/Use between 30 and 86400/)).toBeVisible();
  expect(
    (await stored(request, backend)).sandbox_defaults["reconnection_grace"],
  ).toBeNull();
  const done = saved(page);
  await grace.fill("900");
  await grace.blur();
  await done;
  expect(
    (await stored(request, backend)).sandbox_defaults["reconnection_grace"],
  ).toBe(900);
});

test.describe("Microsoft's VS Code server", () => {
  test("declining or closing the popup keeps code-server and records nothing", async ({
    page,
    backend,
    request,
  }) => {
    await openSettings(page, backend);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText(
      "puddle downloads the server from Microsoft",
    );
    await expect(
      dialog.getByRole("link", { name: /licence terms/ }),
    ).toHaveAttribute("href", TERMS);
    await expect(
      dialog.getByLabel("Allow the server to send telemetry to Microsoft"),
    ).not.toBeChecked();
    await dialog.getByRole("button", { name: "Keep code-server" }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByLabel("Server", { exact: true })).toHaveValue(
      "code_server",
    );
    expect((await consent(request, backend)).state).toBe("not_asked");
    expect((await stored(request, backend)).vscode_server.server).toBeNull();
  });

  test("Escape closes the popup and gives focus back to the choice", async ({
    page,
    backend,
    request,
  }) => {
    await openSettings(page, backend);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    // The dialog moves focus in after it opens; wait for that, then act.
    await expect(dialog.locator(":focus")).toHaveCount(1);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(page.getByLabel("Server", { exact: true })).toBeFocused();
    expect((await consent(request, backend)).state).toBe("not_asked");
  });

  test("accepting records the consent with the terms and switches the server", async ({
    page,
    backend,
    request,
  }) => {
    await openSettings(page, backend);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    const dialog = page.getByRole("dialog");
    await dialog
      .getByRole("button", { name: "Accept and use Microsoft's server" })
      .click();
    await expect(dialog).toBeHidden();
    await expect(page.getByLabel("Server", { exact: true })).toHaveValue(
      "microsoft",
    );
    await expect(page.getByLabel("Send Microsoft telemetry")).not.toBeChecked();
    const c = await consent(request, backend);
    expect(c.state).toBe("granted");
    expect(c.terms_version).toBe(TERMS);
    const s = await stored(request, backend);
    expect(s.vscode_server.server).toBe("microsoft");
    expect(s.vscode_server.telemetry).toBe(false);

    await page.reload();
    await expect(page.getByLabel("Server", { exact: true })).toHaveValue(
      "microsoft",
    );
    await expect(
      page.getByText(/You accepted Microsoft's terms on/),
    ).toBeVisible();
    // Switching back keeps the consent; switching again does not ask.
    let done = saved(page);
    await page
      .getByLabel("Server", { exact: true })
      .selectOption("code_server");
    await done;
    done = saved(page);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    await done;
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });

  test("telemetry is only on when the box was checked", async ({
    page,
    backend,
    request,
  }) => {
    await openSettings(page, backend);
    await page.getByLabel("Server", { exact: true }).selectOption("microsoft");
    const dialog = page.getByRole("dialog");
    await dialog
      .getByLabel("Allow the server to send telemetry to Microsoft")
      .check();
    await dialog
      .getByRole("button", { name: "Accept and use Microsoft's server" })
      .click();
    await expect(dialog).toBeHidden();
    await expect(page.getByLabel("Send Microsoft telemetry")).toBeChecked();
    expect((await stored(request, backend)).vscode_server.telemetry).toBe(true);
  });

  test("the API itself refuses Microsoft's server without consent", async ({
    backend,
    request,
  }) => {
    const r = await request.put("/api/settings", {
      headers: auth(backend),
      data: { vscode_server: { server: "microsoft" } },
    });
    expect(r.status()).toBe(422);
  });
});
