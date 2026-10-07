// SPDX-License-Identifier: GPL-3.0-or-later
import { axeViolations, expect, signIn, test, watchCsp } from "./support";

const sections = [
  { path: "/inbox", name: "Inbox" },
  { path: "/workspaces", name: "Workspaces" },
  { path: "/rules", name: "Rules" },
  { path: "/activity", name: "Activity" },
  { path: "/settings", name: "Settings" },
];

test.describe("the app shell, served by the real API", () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page);
  });

  test("the start page lands on the inbox with the live pending count", async ({
    page,
  }) => {
    const violations = await watchCsp(page);
    await page.goto("/");
    await expect(page).toHaveURL(/\/inbox$/);
    await expect(
      page.getByRole("heading", { level: 1, name: "Inbox" }),
    ).toBeVisible();
    await expect(page.getByTestId("pending-badge")).toContainText("1 pending");
    await expect(page).toHaveTitle("Inbox (1) - puddle");
    expect(await violations()).toEqual([]);
  });

  test("all five sections are reachable from the sidebar, and the current one is marked", async ({
    page,
  }) => {
    await page.goto("/inbox");
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link")).toHaveCount(5);
    for (const { path, name } of sections) {
      await nav.getByRole("link", { name: new RegExp(`^${name}`) }).click();
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
      await expect(
        nav.getByRole("link", { name: new RegExp(`^${name}`) }),
      ).toHaveAttribute("aria-current", "page");
    }
  });

  test("a client-side route loads directly, and an unknown one says so", async ({
    page,
  }) => {
    await page.goto("/rules");
    await expect(
      page.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeVisible();
    await page.goto("/no-such-page");
    await expect(
      page.getByRole("heading", { level: 1, name: "Page not found" }),
    ).toBeVisible();
  });

  test("keyboard: the skip link comes first and moves focus to the content", async ({
    page,
  }) => {
    await page.goto("/rules");
    await expect(
      page.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(
      page.getByRole("link", { name: "Skip to content" }),
    ).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("main")).toBeFocused();
  });

  test("keyboard: Tab visits the five section links, then the theme choices", async ({
    page,
  }) => {
    await page.goto("/rules");
    await expect(
      page.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeVisible();
    const order: string[] = [];
    for (let i = 0; i < 7; i += 1) {
      await page.keyboard.press("Tab");
      order.push(
        await page.evaluate(() =>
          (document.activeElement?.textContent ?? "")
            .trim()
            .replace(/\s+/g, " "),
        ),
      );
    }
    expect(order[0]).toBe("Skip to content");
    expect(order[1]).toMatch(/^Inbox/);
    expect(order.slice(2, 6)).toEqual([
      "Workspaces",
      "Rules",
      "Activity",
      "Settings",
    ]);
    expect(order[6]).toMatch(/^(System|Light|Dark)$/);
  });

  test("theme: follows the OS, can be overridden, and the choice survives a reload", async ({
    page,
  }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto("/inbox");
    const scheme = () =>
      page.evaluate(
        () => getComputedStyle(document.documentElement).colorScheme,
      );
    expect(await scheme()).toBe("light dark");
    const bg = () =>
      page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    const darkBg = await bg();

    await page.getByRole("radio", { name: "Light" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    const lightBg = await bg();
    expect(lightBg).not.toBe(darkBg);

    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.getByRole("radio", { name: "System" }).click();
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.*/);
    expect(await bg()).toBe(darkBg);
  });

  for (const scheme of ["light", "dark"] as const) {
    test(`axe finds nothing on any route in ${scheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      for (const { path } of sections) {
        await page.goto(path);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        expect(await axeViolations(page), `${path} (${scheme})`).toEqual([]);
      }
      await page.goto("/no-such-page");
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      expect(await axeViolations(page), `404 (${scheme})`).toEqual([]);
    });
  }

  test("axe finds nothing with the theme override set either way", async ({
    page,
  }) => {
    await page.goto("/settings");
    for (const choice of ["Light", "Dark"]) {
      await page.getByRole("radio", { name: choice }).click();
      expect(await axeViolations(page), choice).toEqual([]);
    }
  });
});

test.describe("the origin and the token", () => {
  test("static files need no token; the API does; the page is served locked down", async ({
    request,
  }) => {
    const page = await request.get("/inbox");
    expect(page.status()).toBe(200);
    const csp = page.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(page.headers()["x-frame-options"]).toBe("DENY");
    expect((await request.get("/api/pending")).status()).toBe(401);
  });

  test("without a token the shell says it cannot sign in, and stays usable", async ({
    page,
  }) => {
    await page.goto("/inbox");
    await expect(page.getByRole("status")).toContainText("can't sign in");
    await expect(
      page.getByRole("heading", { level: 1, name: "Inbox" }),
    ).toBeVisible();
    expect(await axeViolations(page)).toEqual([]);
  });
});
