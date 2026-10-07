// SPDX-License-Identifier: GPL-3.0-or-later
// The approval inbox against the real API on the fixture backend, in the browsers the
// app ships in. Every test starts from the `default` scenario (one pending request, demo ->
// registry.example.org) on its worker's own backend, so a test may decide anything it likes.
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

/** A workspace asks for a host (the fixture opens a pending request, as the proxy would). */
async function ask(
  backend: Backend,
  sandbox: string,
  host: string,
  more: Record<string, unknown> = {},
): Promise<void> {
  await backend.control.step({ do: "request", sandbox, host, ...more });
}

const rowFor = (page: Page, host: string): Locator =>
  page.locator("li.req", {
    has: page.locator(".host", {
      hasText: new RegExp(`^${host.replace(/\./g, "\\.")}$`),
    }),
  });

async function openInbox(page: Page, backend: Backend): Promise<void> {
  await backend.signIn(page);
  await page.goto("/inbox");
  await expect(
    page.getByRole("heading", { level: 1, name: "Inbox" }),
  ).toBeVisible();
}

async function openOptions(row: Locator, page: Page): Promise<Locator> {
  await row.getByRole("button", { name: /^More choices for/ }).click();
  const dialog = page.getByRole("dialog", { name: /^Choices for/ });
  await expect(dialog).toBeVisible();
  return dialog;
}

test.describe("deciding", () => {
  test("approve here: one click, this workspace, exact host, permanent", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "allow.example.com");
    await openInbox(page, backend);
    const row = rowFor(page, "allow.example.com");
    await expect(row).toContainText("Workspace shop");
    await row
      .getByRole("button", { name: "Allow allow.example.com for shop" })
      .click();
    await expect(row).toHaveCount(0);
    await expect(page.getByRole("status")).toContainText(
      "Allowed allow.example.com for workspace shop, permanently.",
    );
    const rule = (await rules(request, backend)).find(
      (r) => r.pattern === "allow.example.com",
    );
    expect(rule).toMatchObject({
      effect: "allow",
      pattern_kind: "exact",
      scope: { type: "sandbox", sandbox: "shop" },
      expires_at: null,
    });
    await expect(
      page.getByRole("region", { name: "Decided just now" }),
    ).toContainText("allow.example.com");
  });

  test("deny here", async ({ page, request, backend }) => {
    await ask(backend, "shop", "deny.example.com");
    await openInbox(page, backend);
    await rowFor(page, "deny.example.com")
      .getByRole("button", { name: "Deny deny.example.com for shop" })
      .click();
    await expect(rowFor(page, "deny.example.com")).toHaveCount(0);
    expect(
      (await rules(request, backend)).find(
        (r) => r.pattern === "deny.example.com",
      ),
    ).toMatchObject({
      effect: "deny",
      scope: { type: "sandbox", sandbox: "shop" },
    });
  });

  test("every workspace asks first; Cancel changes nothing, Confirm decides", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "global.example.com");
    await openInbox(page, backend);
    const row = rowFor(page, "global.example.com");
    let dialog = await openOptions(row, page);
    await dialog.getByRole("radio", { name: /^Every workspace/ }).check();
    await dialog.getByRole("button", { name: "Allow", exact: true }).click();
    const confirm = page.getByRole("alertdialog", {
      name: "Allow for every workspace?",
    });
    await expect(confirm).toContainText(
      "Allow global.example.com for every workspace, permanently",
    );
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(confirm).toHaveCount(0);
    await expect(row).toHaveCount(1);
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "global.example.com",
      ),
    ).toBe(false);

    dialog = await openOptions(row, page);
    await dialog.getByRole("radio", { name: /^Every workspace/ }).check();
    await dialog.getByRole("button", { name: "Allow", exact: true }).click();
    await page
      .getByRole("button", { name: "Allow in every workspace" })
      .click();
    await expect(row).toHaveCount(0);
    expect(
      (await rules(request, backend)).find(
        (r) => r.pattern === "global.example.com",
      ),
    ).toMatchObject({ effect: "allow", scope: { type: "global" } });
  });

  test("every workspace, denied, is confirmed as a deny", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "globaldeny.example.com");
    await openInbox(page, backend);
    const dialog = await openOptions(
      rowFor(page, "globaldeny.example.com"),
      page,
    );
    await dialog.getByRole("radio", { name: /^Every workspace/ }).check();
    await dialog.getByRole("button", { name: "Deny", exact: true }).click();
    await expect(
      page.getByRole("alertdialog", { name: "Deny for every workspace?" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Deny in every workspace" }).click();
    await expect(rowFor(page, "globaldeny.example.com")).toHaveCount(0);
    expect(
      (await rules(request, backend)).find(
        (r) => r.pattern === "globaldeny.example.com",
      ),
    ).toMatchObject({ effect: "deny", scope: { type: "global" } });
  });

  test("a suffix rule covers the registrable domain and closes the other rows it decides", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "a.suffix.example.com");
    await ask(backend, "shop", "b.suffix.example.com");
    await ask(backend, "docs", "c.suffix.example.com");
    await openInbox(page, backend);
    const dialog = await openOptions(
      rowFor(page, "a.suffix.example.com"),
      page,
    );
    await dialog
      .getByRole("radio", { name: /^Everything under example\.com/ })
      .check();
    await dialog.getByRole("button", { name: "Allow", exact: true }).click();
    await expect(rowFor(page, "a.suffix.example.com")).toHaveCount(0);
    await expect(rowFor(page, "b.suffix.example.com")).toHaveCount(0);
    // Another workspace's request is not covered by a rule for this one.
    await expect(rowFor(page, "c.suffix.example.com")).toHaveCount(1);
    await expect(page.getByRole("status")).toContainText(
      "also closed 1 other request",
    );
    expect(
      (await rules(request, backend)).find((r) => r.pattern_kind === "suffix"),
    ).toMatchObject({
      pattern: ".example.com",
      effect: "allow",
      scope: { type: "sandbox", sandbox: "shop" },
    });
  });

  test("a duration sets an expiry", async ({ page, request, backend }) => {
    await ask(backend, "shop", "duration.example.com");
    await openInbox(page, backend);
    const dialog = await openOptions(
      rowFor(page, "duration.example.com"),
      page,
    );
    await dialog
      .getByRole("combobox", { name: "How long" })
      .selectOption({ label: "1 hour" });
    await dialog.getByRole("button", { name: "Allow", exact: true }).click();
    await expect(rowFor(page, "duration.example.com")).toHaveCount(0);
    const rule = (await rules(request, backend)).find(
      (r) => r.pattern === "duration.example.com",
    );
    const now = (await backend.control.state()).now_ms;
    expect((rule?.expires_at ?? 0) - now).toBe(3_600_000);
  });

  test("undo from the toast deletes the rule; the list says so", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "undo.example.com");
    await openInbox(page, backend);
    await rowFor(page, "undo.example.com")
      .getByRole("button", { name: /^Allow/ })
      .click();
    await expect(rowFor(page, "undo.example.com")).toHaveCount(0);
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "undo.example.com",
      ),
    ).toBe(true);
    await page.getByRole("button", { name: "Undo", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Undone");
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "undo.example.com",
      ),
    ).toBe(false);
    await expect(
      page
        .getByRole("region", { name: "Decided just now" })
        .getByText("undo.example.com"),
    ).toHaveCount(0);
  });

  test("undo from Decided just now, after the toast has gone", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "undolist.example.com");
    await openInbox(page, backend);
    await rowFor(page, "undolist.example.com")
      .getByRole("button", { name: /^Deny/ })
      .click();
    const list = page.getByRole("region", { name: "Decided just now" });
    await expect(list).toContainText("undolist.example.com");
    await expect(
      page.getByRole("button", { name: "Undo", exact: true }),
    ).toHaveCount(0, { timeout: 15_000 });
    await list
      .getByRole("button", { name: /^Undo: Denied undolist\.example\.com/ })
      .click();
    await expect
      .poll(async () =>
        (await rules(request, backend)).some(
          (r) => r.pattern === "undolist.example.com",
        ),
      )
      .toBe(false);
  });

  test("a request decided elsewhere leaves the list at once, as the events say", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "gone.example.com");
    await openInbox(page, backend);
    const row = rowFor(page, "gone.example.com");
    await expect(row).toHaveCount(1);
    const pending = (await (
      await request.get("/api/pending", { headers: auth(backend) })
    ).json()) as { requests: { id: number; host: string }[] };
    const id = pending.requests.find((r) => r.host === "gone.example.com")?.id;
    await request.post(`/api/pending/${id}/deny`, {
      headers: auth(backend),
      data: {},
    });
    await expect(row).toHaveCount(0, { timeout: 20_000 });
  });

  test("a request decided elsewhere, with the stream down, is refused politely and leaves the list", async ({
    page,
    request,
    backend,
  }) => {
    await page.route("**/api/events", (route) => route.abort());
    await ask(backend, "shop", "stale.example.com");
    await openInbox(page, backend);
    const row = rowFor(page, "stale.example.com");
    await expect(row).toHaveCount(1);
    // Decided behind the page's back, as the CLI would.
    const pending = (await (
      await request.get("/api/pending", { headers: auth(backend) })
    ).json()) as { requests: { id: number; host: string }[] };
    const id = pending.requests.find((r) => r.host === "stale.example.com")?.id;
    await request.post(`/api/pending/${id}/deny`, {
      headers: auth(backend),
      data: {},
    });
    await row.getByRole("button", { name: /^Allow/ }).click();
    await expect(page.getByRole("status")).toContainText("already decided");
    await expect(row).toHaveCount(0);
  });
});

test.describe("live", () => {
  test("a request that arrives while the page is open shows up, and its attempts count up", async ({
    page,
    backend,
  }) => {
    await openInbox(page, backend);
    await expect(rowFor(page, "live.example.com")).toHaveCount(0);
    await ask(backend, "shop", "live.example.com");
    await expect(rowFor(page, "live.example.com")).toBeVisible({
      timeout: 20_000,
    });
    await expect(page).toHaveTitle("Inbox (2) - puddle");
    await expect(page.getByTestId("pending-badge")).toContainText("2 pending");
    await ask(backend, "shop", "live.example.com", { repeat: 2 });
    await expect(rowFor(page, "live.example.com")).toContainText("3 attempts", {
      timeout: 20_000,
    });
  });

  test("with the event stream down, the list still converges by polling", async ({
    page,
    backend,
  }) => {
    await page.route("**/api/events", (route) => route.abort());
    await openInbox(page, backend);
    await ask(backend, "shop", "nostream.example.com");
    await expect(rowFor(page, "nostream.example.com")).toBeVisible({
      timeout: 20_000,
    });
  });

  test("a restarted API makes the page resync at once", async ({
    page,
    backend,
  }) => {
    await openInbox(page, backend);
    await ask(backend, "shop", "resync.example.com");
    await backend.control.restart();
    await expect(rowFor(page, "resync.example.com")).toBeVisible({
      timeout: 20_000,
    });
  });

  test("the badge and the title follow decisions at once", async ({
    page,
    backend,
  }) => {
    await ask(backend, "shop", "badge.example.com");
    await openInbox(page, backend);
    await expect(page).toHaveTitle("Inbox (2) - puddle");
    await rowFor(page, "badge.example.com")
      .getByRole("button", { name: /^Allow/ })
      .click();
    await expect(rowFor(page, "badge.example.com")).toHaveCount(0);
    await expect(page).toHaveTitle("Inbox (1) - puddle");
    await expect(page.getByTestId("pending-badge")).toContainText("1 pending");
  });

  test("times are relative to the clock", async ({ page, backend }) => {
    await ask(backend, "shop", "clock.example.com", { ago_ms: 5 * 60_000 });
    await ask(backend, "shop", "clock.example.com", { repeat: 1 });
    await backend.installClock(page);
    await openInbox(page, backend);
    await expect(rowFor(page, "clock.example.com")).toContainText(
      "First seen 5 minutes ago",
    );
    await expect(rowFor(page, "clock.example.com")).toContainText(
      "Last seen just now",
    );
  });
});

test.describe("what can't be approved, and what is held back", () => {
  test("a local destination with its toggle off names the toggle and offers only Deny", async ({
    page,
    backend,
  }) => {
    await ask(backend, "shop", "192.168.77.7");
    await openInbox(page, backend);
    const row = rowFor(page, "192.168.77.7");
    await expect(row).toContainText(
      "Private networks destinations are switched off",
    );
    await expect(
      row.getByRole("link", { name: "Private networks" }),
    ).toHaveAttribute("href", "/settings#local-destinations");
    await expect(row.getByRole("button", { name: /^Allow/ })).toHaveCount(0);
    await expect(row.getByRole("button", { name: /^Deny/ })).toBeVisible();
  });

  test("requests over the rate limit are summarised as held back", async ({
    page,
    backend,
  }) => {
    await backend.control.step({
      do: "bulk",
      sandbox: "flood",
      count: 70,
      domain: "flood.example.net",
    });
    await openInbox(page, backend);
    const line = page.locator(".held", { hasText: "flood" });
    await expect(line).toContainText(/\d+ more requests? from/);
    await expect(line).toContainText("held back");
  });
});

test.describe("keyboard only", () => {
  /** J or K until the row for `host` is the current one. */
  async function moveTo(page: Page, host: string): Promise<void> {
    const rows = page.locator("li.req");
    const index = (target: Locator) =>
      target.evaluate((el) =>
        [...document.querySelectorAll("li.req")].indexOf(el),
      );
    const wanted = await index(rowFor(page, host));
    const current = await index(page.locator("li.req[aria-current='true']"));
    if (wanted === current) await rows.nth(wanted).focus();
    const key = wanted >= current ? "j" : "k";
    for (let i = 0; i < Math.abs(wanted - current); i += 1) {
      await page.keyboard.press(key);
    }
    await expect(rowFor(page, host)).toHaveAttribute("aria-current", "true");
    await expect(rows.nth(wanted)).toBeFocused();
  }

  async function reach(page: Page, host: string): Promise<void> {
    await rowFor(page, host).waitFor();
    await page.locator("main").focus();
    await moveTo(page, host);
  }

  test("J/K move, A allows, D denies; focus lands on the next row", async ({
    page,
    request,
    backend,
  }) => {
    for (const host of ["k0.example.com", "k1.example.com", "k2.example.com"]) {
      await ask(backend, "shop", host);
    }
    await openInbox(page, backend);
    await reach(page, "k0.example.com");
    await page.keyboard.press("a");
    await expect(rowFor(page, "k0.example.com")).toHaveCount(0);
    await expect
      .poll(() =>
        page.evaluate(() => document.activeElement?.matches("li.req") ?? false),
      )
      .toBe(true);
    await moveTo(page, "k1.example.com");
    await page.keyboard.press("d");
    await expect(rowFor(page, "k1.example.com")).toHaveCount(0);
    const all = await rules(request, backend);
    expect(all.find((r) => r.pattern === "k0.example.com")?.effect).toBe(
      "allow",
    );
    expect(all.find((r) => r.pattern === "k1.example.com")?.effect).toBe(
      "deny",
    );
  });

  test("Tab reaches Allow, the chevron and Deny of a row in order; the options are a normal form that Escape closes", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "form.example.com");
    await openInbox(page, backend);
    const row = rowFor(page, "form.example.com");
    await row.waitFor();
    await row.getByRole("button", { name: /^Allow/ }).focus();
    await page.keyboard.press("Tab");
    const chevron = row.getByRole("button", { name: /^More choices/ });
    await expect(chevron).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(row.getByRole("button", { name: /^Deny/ })).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: /^Choices for/ });
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(chevron).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(dialog).toBeVisible();
    // Opening moves focus into the form on its own, one frame after it shows. Wait for that
    // instead of pressing Tab at it: a Tab that lands before the move is swallowed by it.
    const first = dialog.getByRole("radio").first();
    await expect(first).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(
      dialog.getByRole("radio", { name: /^Only form/ }),
    ).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await expect(first).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(chevron).toBeFocused();
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "form.example.com",
      ),
    ).toBe(false);
  });

  test("Enter on a row opens its options; every workspace by keyboard is confirmed with Cancel focused first", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "kglobal.example.com");
    await openInbox(page, backend);
    await reach(page, "kglobal.example.com");
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: /^Choices for/ });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("radio", { name: /^Every workspace/ }).focus();
    await page.keyboard.press("Space");
    await dialog.getByRole("button", { name: "Allow", exact: true }).focus();
    await page.keyboard.press("Enter");
    const confirm = page.getByRole("alertdialog");
    await expect(confirm).toBeVisible();
    await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(
      confirm.getByRole("button", { name: "Allow in every workspace" }),
    ).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(confirm).toHaveCount(0);
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "kglobal.example.com",
      ),
    ).toBe(false);
    // The second time, confirm with the keyboard.
    await page.keyboard.press("Enter");
    const again = page.getByRole("dialog", { name: /^Choices for/ });
    await again.getByRole("radio", { name: /^Every workspace/ }).focus();
    await page.keyboard.press("Space");
    await again.getByRole("button", { name: "Allow", exact: true }).focus();
    await page.keyboard.press("Enter");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await expect(rowFor(page, "kglobal.example.com")).toHaveCount(0);
    expect(
      (await rules(request, backend)).find(
        (r) => r.pattern === "kglobal.example.com",
      )?.scope,
    ).toEqual({ type: "global" });
  });

  test("shortcuts do nothing while a field has focus or a dialog is open", async ({
    page,
    request,
    backend,
  }) => {
    await ask(backend, "shop", "inert.example.com");
    await openInbox(page, backend);
    await reach(page, "inert.example.com");
    const row = rowFor(page, "inert.example.com");
    await row.getByRole("button", { name: /^More choices/ }).click();
    const dialog = page.getByRole("dialog", { name: /^Choices for/ });
    await dialog.getByRole("combobox", { name: "How long" }).focus();
    await page.keyboard.press("d");
    await page.keyboard.press("a");
    await expect(row).toHaveCount(1);
    expect(
      (await rules(request, backend)).some(
        (r) => r.pattern === "inert.example.com",
      ),
    ).toBe(false);
  });
});

test.describe("accessibility", () => {
  for (const scheme of ["light", "dark"] as const) {
    test(`axe finds nothing in ${scheme}: the list, the options, the confirm, the empty state`, async ({
      page,
      backend,
    }) => {
      await ask(backend, "shop", "a.axe.example.com");
      await ask(backend, "shop", "b.axe.example.com");
      await ask(backend, "shop", "192.168.88.8");
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await watchCsp(page);
      await openInbox(page, backend);
      const row = rowFor(page, "a.axe.example.com");
      await expect(row).toBeVisible();
      expect(await axeViolations(page), "list").toEqual([]);

      const dialog = await openOptions(row, page);
      await dialog.getByRole("radio", { name: /^Every workspace/ }).check();
      expect(await axeViolations(page), "options").toEqual([]);

      await dialog.getByRole("button", { name: "Allow", exact: true }).click();
      await expect(page.getByRole("alertdialog")).toBeVisible();
      expect(await axeViolations(page), "confirm").toEqual([]);
      await page.getByRole("button", { name: "Cancel" }).click();

      await rowFor(page, "b.axe.example.com")
        .getByRole("button", { name: /^Deny/ })
        .click();
      await expect(page.getByRole("status")).toContainText("Denied");
      expect(await axeViolations(page), "toast and decided list").toEqual([]);
      expect(await csp()).toEqual([]);

      await backend.control.reset("empty");
      await page.reload();
      await expect(
        page.getByRole("heading", { name: "All quiet" }),
      ).toBeVisible();
      expect(await axeViolations(page), "empty").toEqual([]);
    });
  }

  test("the buttons are at least 24 by 24 CSS pixels (WCAG 2.5.8)", async ({
    page,
    backend,
  }) => {
    await openInbox(page, backend);
    const row = rowFor(page, "registry.example.org");
    await expect(row).toBeVisible();
    const buttons = await row.getByRole("button").all();
    expect(buttons).toHaveLength(3);
    for (const button of buttons) {
      const box = await button.boundingBox();
      expect(box?.width ?? 0).toBeGreaterThanOrEqual(24);
      expect(box?.height ?? 0).toBeGreaterThanOrEqual(24);
    }
  });
});
