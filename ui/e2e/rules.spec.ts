// SPDX-License-Identifier: GPL-3.0-or-later
// The rules screen against the real API on the fixture backend. Every test starts from the
// `lived-in` scenario (7 rules: global and per workspace, permanent and expiring) on its worker's
// own backend. The page clock is the fixture's, so relative times and expiries agree with the API.
import type { APIRequestContext, Locator, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

interface Rule {
  id: number;
  effect: "allow" | "deny";
  pattern: string;
  pattern_kind: "exact" | "suffix";
  scope: { type: "global" } | { type: "sandbox"; sandbox: string };
  expires_at: number | null;
}

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

async function rules(
  request: APIRequestContext,
  backend: Backend,
): Promise<Rule[]> {
  const response = await request.get("/api/rules", { headers: auth(backend) });
  return ((await response.json()) as { rules: Rule[] }).rules;
}

test.beforeEach(async ({ backend }) => {
  await backend.control.reset("lived-in");
});

const rowFor = (page: Page, pattern: string, workspace?: string): Locator =>
  page
    .locator("tbody tr", {
      has: page.locator("td.host", {
        hasText: new RegExp(
          `^\\s*${pattern.replace(/[.*]/g, "\\$&")}( and subdomains)?\\s*$`,
        ),
      }),
    })
    .filter(workspace ? { hasText: workspace } : {});

async function openRules(page: Page, backend: Backend): Promise<void> {
  await backend.installClock(page);
  await backend.signIn(page);
  await page.goto("/rules");
  await expect(
    page.getByRole("heading", { level: 1, name: "Rules" }),
  ).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(7);
}

const hostsShown = (page: Page) =>
  page.locator("tbody tr td.host .mono").allTextContents();

test.describe("the list", () => {
  test("shows global and workspace rules with effect, expiry and the precedence line", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    await expect(page.getByText(/most specific rule wins/i)).toBeVisible();
    const global = rowFor(page, "registry.npmjs.org");
    await expect(global).toContainText("Allow");
    await expect(global).toContainText("Every workspace");
    await expect(global).toContainText("Never");
    const suffix = rowFor(page, "*.crates.io");
    await expect(suffix).toContainText("web-shop");
    await expect(suffix).toContainText("and subdomains");
    const expiring = rowFor(page, "api.example.com");
    await expect(expiring).toContainText("in 3 hours");
    await expect(expiring.locator("time").first()).toHaveAttribute(
      "title",
      /2026/,
    );
    await expect(rowFor(page, "telemetry.example.net")).toContainText("Deny");
  });

  test("an expiry that passes shows without a reload", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    const row = rowFor(page, "api.example.com");
    await expect(row).toContainText("in 3 hours");
    await backend.control.advance(5 * 3_600_000);
    await page.clock.fastForward(5 * 3_600_000);
    await expect(row).toHaveCount(0); // the sweeper removed it, and the next poll sees that
  });
});

test.describe("filters and sort", () => {
  test("filter by host, workspace, effect and state; clear", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    await page.getByLabel("Host contains").fill("CRATES");
    await expect(page.locator("tbody tr")).toHaveCount(2);
    await expect(page.locator(".count")).toHaveText("2 of 7 rules");
    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(page.locator("tbody tr")).toHaveCount(7);

    await page.getByLabel("Workspace", { exact: true }).selectOption("global");
    await expect(page.locator("tbody tr")).toHaveCount(3);
    await page
      .getByLabel("Workspace", { exact: true })
      .selectOption("docs-site");
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await page.getByLabel("Workspace", { exact: true }).selectOption("any");
    await page.getByLabel("Effect", { exact: true }).selectOption("deny");
    await expect(page.locator("tbody tr")).toHaveCount(2);

    await page.getByLabel("Effect", { exact: true }).selectOption("any");
    await page.getByLabel("State").selectOption("expired");
    await expect(page.getByText("No rule matches")).toBeVisible();
    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(page.locator("tbody tr")).toHaveCount(7);
  });

  test("an expired rule shows as expired and the state filter finds it", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    // The page's clock moves on; the API's sweeper has not run yet.
    await page.clock.fastForward(5 * 3_600_000);
    await page.getByLabel("State").selectOption("expired");
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await expect(rowFor(page, "api.example.com")).toContainText(
      "no longer applies",
    );
  });

  test("sorting by host is alphabetical and flips", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    await page.getByRole("button", { name: "Sort by host" }).click();
    const asc = await hostsShown(page);
    expect(asc).toEqual([...asc].sort((a, b) => a.localeCompare(b)));
    await page.getByRole("button", { name: "Sort by host" }).click();
    expect(await hostsShown(page)).toEqual(asc.slice().reverse());
    await expect(
      page.getByRole("columnheader", { name: /host/i }),
    ).toHaveAttribute("aria-sort", "descending");
  });
});

test.describe("adding", () => {
  async function openAdd(page: Page): Promise<Locator> {
    await page.getByRole("button", { name: "Add rule" }).first().click();
    const dialog = page.getByRole("dialog", { name: "Add a rule" });
    await expect(dialog).toBeVisible();
    return dialog;
  }

  test("adds an exact deny for one workspace, with an expiry of 1 hour", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const dialog = await openAdd(page);
    await dialog.getByLabel("Host").fill("tracker.example.org");
    await dialog.getByRole("radio", { name: "Deny" }).check();
    await dialog.getByLabel("Workspace name").fill("docs-site");
    await dialog.getByLabel("Expires").selectOption({ label: "In 1 hour" });
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(dialog).toHaveCount(0);
    const row = rowFor(page, "tracker.example.org");
    await expect(row).toContainText("Deny");
    await expect(row).toContainText("docs-site");
    await expect(row).toContainText("in 1 hour");
    await expect(page.getByRole("status")).toContainText(
      "Added: deny tracker.example.org for workspace docs-site.",
    );
    const rule = (await rules(request, backend)).find(
      (r) => r.pattern === "tracker.example.org",
    );
    expect(rule?.scope).toEqual({ type: "sandbox", sandbox: "docs-site" });
    const now = (await backend.control.state()).now_ms;
    expect((rule?.expires_at ?? 0) - now).toBeGreaterThanOrEqual(3_600_000);
    expect((rule?.expires_at ?? 0) - now).toBeLessThan(3_600_000 + 60_000);
  });

  test("*.suffix is stored as a suffix rule", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const dialog = await openAdd(page);
    await dialog.getByLabel("Host").fill("*.cdn.example.org");
    await dialog.getByLabel("Workspace name").fill("web-shop");
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(rowFor(page, "*.cdn.example.org")).toContainText(
      "and subdomains",
    );
    const rule = (await rules(request, backend)).find(
      (r) => r.pattern === ".cdn.example.org",
    );
    expect(rule?.pattern_kind).toBe("suffix");
  });

  test("a public suffix is refused by the server and shown at the field", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const before = (await rules(request, backend)).length;
    const dialog = await openAdd(page);
    await dialog.getByLabel("Host").fill("*.com");
    await dialog.getByLabel("Workspace name").fill("web-shop");
    await dialog.getByRole("button", { name: "Add rule" }).click();
    const error = dialog.getByRole("alert");
    await expect(error).toContainText(/public suffix/i);
    await expect(dialog.getByLabel("Host")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    await expect(dialog.getByLabel("Host")).toHaveValue("*.com");
    expect((await rules(request, backend)).length).toBe(before);
    // Correcting it works.
    await dialog.getByLabel("Host").fill("*.example.com");
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(dialog).toHaveCount(0);
    expect((await rules(request, backend)).length).toBe(before + 1);
  });

  test("a bad host is refused inline; empty fields never reach the server", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    const dialog = await openAdd(page);
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(dialog.getByRole("alert")).toHaveCount(2);
    await dialog.getByLabel("Host").fill("not a host");
    await dialog.getByLabel("Workspace name").fill("web-shop");
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(dialog.getByRole("alert")).toHaveCount(1);
    await expect(dialog).toBeVisible();
  });

  test("a rule for every workspace asks first; Cancel returns to the form", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const before = (await rules(request, backend)).length;
    const dialog = await openAdd(page);
    await dialog.getByLabel("Host").fill("everywhere.example.org");
    await dialog.getByRole("radio", { name: /^Every workspace/ }).check();
    await dialog.getByRole("button", { name: "Add rule" }).click();
    const confirm = page.getByRole("alertdialog", {
      name: "Allow for every workspace?",
    });
    await expect(confirm).toContainText("everywhere.example.org");
    expect((await rules(request, backend)).length).toBe(before);
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByLabel("Host")).toHaveValue(
      "everywhere.example.org",
    );
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Allow in every workspace" })
      .click();
    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(rowFor(page, "everywhere.example.org")).toContainText(
      "Every workspace",
    );
    expect((await rules(request, backend)).length).toBe(before + 1);
  });

  test("a new rule that decides a pending request closes it and the badge follows", async ({
    page,
    backend,
  }) => {
    await backend.control.step({
      do: "request",
      sandbox: "web-shop",
      host: "closes.example.org",
    });
    await openRules(page, backend);
    const badge = page.getByTestId("pending-badge");
    await expect(badge).toBeVisible();
    const count = Number(
      ((await badge.textContent()) ?? "").trim().split(/\s/)[0],
    );
    const dialog = await openAdd(page);
    await dialog.getByLabel("Host").fill("closes.example.org");
    await dialog.getByLabel("Workspace name").fill("web-shop");
    await dialog.getByRole("button", { name: "Add rule" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(async () => {
      const text = (await badge.textContent()) ?? "";
      expect(Number(text.trim().split(/\s/)[0])).toBe(count - 1);
    }).toPass();
  });
});

test.describe("changing the expiry", () => {
  test("makes an expiring rule permanent, and a permanent rule expire", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const expiring = rowFor(page, "api.example.com");
    await expiring
      .getByRole("button", { name: /^Change expiry: allow api.example.com/ })
      .click();
    const dialog = page.getByRole("dialog", { name: "Change expiry" });
    await expect(dialog).toContainText("api.example.com");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog.getByRole("alert")).toContainText(/choose when/i);
    await dialog
      .getByLabel("Ends")
      .selectOption({ label: "Never (permanent)" });
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(expiring).toContainText("Never");
    expect(
      (await rules(request, backend)).find(
        (r) => r.pattern === "api.example.com",
      )?.expires_at,
    ).toBeNull();

    const permanent = rowFor(page, "registry.npmjs.org");
    await permanent.getByRole("button", { name: /^Change expiry/ }).click();
    await dialog.getByLabel("Ends").selectOption({ label: "In 8 hours" });
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(permanent).toContainText("in 8 hours");
    const now = (await backend.control.state()).now_ms;
    const changed = (await rules(request, backend)).find(
      (r) => r.pattern === "registry.npmjs.org",
    );
    expect((changed?.expires_at ?? 0) - now).toBeGreaterThanOrEqual(28_800_000);
    expect((changed?.expires_at ?? 0) - now).toBeLessThan(28_800_000 + 60_000);
  });

  test("a rule deleted elsewhere is reported and leaves the list", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const target = (await rules(request, backend)).find(
      (r) => r.pattern === "api.example.com",
    );
    await rowFor(page, "api.example.com")
      .getByRole("button", { name: /^Change expiry/ })
      .click();
    await request.delete(`/api/rules/${target?.id}`, {
      headers: auth(backend),
    });
    const dialog = page.getByRole("dialog", { name: "Change expiry" });
    await dialog.getByLabel("Ends").selectOption({ label: "In 1 day" });
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog.getByRole("alert")).toContainText("already gone");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(rowFor(page, "api.example.com")).toHaveCount(0);
  });
});

test.describe("deleting", () => {
  test("asks, names the rule, and deletes on confirm; Cancel keeps it", async ({
    page,
    request,
    backend,
  }) => {
    await openRules(page, backend);
    const row = rowFor(page, "telemetry.example.net");
    await row.getByRole("button", { name: /^Delete rule/ }).click();
    const confirm = page.getByRole("alertdialog", {
      name: "Delete this rule?",
    });
    await expect(confirm).toContainText(
      "deny telemetry.example.net for every workspace",
    );
    await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(row).toBeVisible();

    await row.getByRole("button", { name: /^Delete rule/ }).click();
    await confirm.getByRole("button", { name: "Delete rule" }).click();
    await expect(confirm).toHaveCount(0);
    await expect(row).toHaveCount(0);
    await expect(page.getByRole("status")).toContainText(
      "Deleted: deny telemetry.example.net",
    );
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "telemetry.example.net",
      ),
    ).toBe(false);
    // Focus did not fall to the page.
    await expect(page.locator("body")).not.toBeFocused();
    expect(
      await page.evaluate(() => document.activeElement?.closest("tr") !== null),
    ).toBe(true);
  });

  test("the last rule going leaves the empty state and focus on the heading", async ({
    page,
    backend,
  }) => {
    await backend.control.reset("default");
    await backend.control.step({
      do: "rule",
      effect: "allow",
      pattern: "only.example.org",
    });
    await backend.installClock(page);
    await backend.signIn(page);
    await page.goto("/rules");
    await page.getByRole("button", { name: /^Delete rule/ }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Delete rule" })
      .click();
    await expect(
      page.getByRole("heading", { name: "No rules yet" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeFocused();
  });
});

test.describe("staying current", () => {
  test("a rule changed from outside appears without a reload (refetch fallback)", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    await backend.control.step({
      do: "rule",
      effect: "deny",
      pattern: "elsewhere.example.org",
    });
    await page.clock.fastForward(11_000);
    await expect(rowFor(page, "elsewhere.example.org")).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(8);
  });

  test("a restarted API is picked up again", async ({ page, backend }) => {
    await openRules(page, backend);
    await backend.control.restart();
    await backend.control.step({
      do: "rule",
      effect: "allow",
      pattern: "after-restart.example.org",
    });
    await expect(rowFor(page, "after-restart.example.org")).toBeVisible({
      timeout: 20_000,
    });
  });
});

test.describe("keyboard only", () => {
  test("add, change expiry and delete without a pointer", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    await page.getByRole("button", { name: "Add rule" }).first().focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: "Add a rule" });
    await expect(dialog.getByLabel("Host")).toBeFocused();
    await page.keyboard.type("keys.example.org");
    await page.keyboard.press("Tab"); // the checked radio of the group (Allow)
    await page.keyboard.press("ArrowRight"); // Deny
    await expect(dialog.getByRole("radio", { name: "Deny" })).toBeChecked();
    await dialog.getByLabel("Workspace name").fill("web-shop");
    await dialog.getByLabel("Workspace name").press("Enter");
    await expect(dialog).toHaveCount(0);
    const row = rowFor(page, "keys.example.org");
    await expect(row).toContainText("Deny");
    // Focus returns somewhere sensible, not to the page.
    await expect(
      page.getByRole("button", { name: "Add rule" }).first(),
    ).toBeFocused();

    await row.getByRole("button", { name: /^Change expiry/ }).focus();
    await page.keyboard.press("Enter");
    const expiry = page.getByRole("dialog", { name: "Change expiry" });
    await expect(expiry.getByLabel("Ends")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(expiry).toHaveCount(0);
    await expect(
      row.getByRole("button", { name: /^Change expiry/ }),
    ).toBeFocused();

    await row.getByRole("button", { name: /^Delete rule/ }).focus();
    await page.keyboard.press("Enter");
    const confirm = page.getByRole("alertdialog");
    await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await expect(row).toHaveCount(0);
  });
});

test.describe("accessibility", () => {
  for (const scheme of ["light", "dark"] as const) {
    test(`axe finds nothing in ${scheme}: the list, the dialogs, the empty state`, async ({
      page,
      backend,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await watchCsp(page);
      await openRules(page, backend);
      expect(await axeViolations(page), "list").toEqual([]);

      await page.getByRole("button", { name: "Add rule" }).first().click();
      const add = page.getByRole("dialog", { name: "Add a rule" });
      await add.getByRole("button", { name: "Add rule" }).click();
      await expect(add.getByRole("alert")).toHaveCount(2);
      expect(await axeViolations(page), "add with errors").toEqual([]);
      await add.getByRole("button", { name: "Cancel" }).click();

      await rowFor(page, "api.example.com")
        .getByRole("button", { name: /^Change expiry/ })
        .click();
      expect(await axeViolations(page), "expiry").toEqual([]);
      await page.keyboard.press("Escape");

      await rowFor(page, "api.example.com")
        .getByRole("button", { name: /^Delete rule/ })
        .click();
      expect(await axeViolations(page), "delete").toEqual([]);
      await page
        .getByRole("button", { name: "Delete rule", exact: true })
        .click();
      await expect(page.getByRole("status")).toContainText("Deleted");
      expect(await axeViolations(page), "toast").toEqual([]);
      expect(await csp()).toEqual([]);

      await backend.control.reset("empty");
      await page.reload();
      await expect(
        page.getByRole("heading", { name: "No rules yet" }),
      ).toBeVisible();
      expect(await axeViolations(page), "empty").toEqual([]);
    });
  }

  test("the buttons are at least 24 by 24 CSS pixels (WCAG 2.5.8)", async ({
    page,
    backend,
  }) => {
    await openRules(page, backend);
    const buttons = await page
      .locator("tbody tr")
      .first()
      .getByRole("button")
      .all();
    expect(buttons).toHaveLength(2);
    for (const button of [
      ...buttons,
      ...(await page.getByRole("button", { name: /^Sort by/ }).all()),
    ]) {
      const box = await button.boundingBox();
      expect(box?.width ?? 0).toBeGreaterThanOrEqual(24);
      expect(box?.height ?? 0).toBeGreaterThanOrEqual(24);
    }
  });
});
