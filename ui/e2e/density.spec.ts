// SPDX-License-Identifier: GPL-3.0-or-later
// The density setting (comfortable / compact) against the real API on the fixture backend:
// chosen in Settings, kept by puddle, applied live, still accessible in both densities, with a
// visual baseline of each. Waits are on conditions, never on time.
import type { Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations } from "./support";

const DENSITIES = ["comfortable", "compact"] as const;
const SCREENS = [
  { path: "/settings", heading: "Settings" },
  { path: "/workspaces", heading: "Workspaces" },
  { path: "/rules", heading: "Rules" },
  { path: "/activity", heading: "Activity" },
];

const saved = (page: Page) =>
  page.waitForResponse(
    (r) => r.request().method() === "PUT" && r.url().endsWith("/api/settings"),
  );

async function setDensity(page: Page, value: string) {
  const done = saved(page);
  await page.getByLabel("Density", { exact: true }).selectOption(value);
  await done;
}

async function open(page: Page, backend: Backend, path: string) {
  await backend.signIn(page);
  await page.goto(path);
}

const spaceFour = (page: Page) =>
  page.evaluate(() =>
    parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue("--space-4"),
    ),
  );

test.describe("the density setting", () => {
  test("is comfortable by default, changes the whole app live, and puddle keeps it", async ({
    page,
    backend,
    request,
  }) => {
    await open(page, backend, "/settings");
    await expect(page.getByLabel("Density", { exact: true })).toHaveValue(
      "comfortable",
    );
    await expect(page.locator("html")).not.toHaveAttribute(
      "data-density",
      /.*/,
    );
    const roomy = await spaceFour(page);

    // A marker on the window proves the page is not reloaded by the change.
    await page.evaluate(() => {
      (window as unknown as { __kept: boolean }).__kept = true;
    });
    await setDensity(page, "compact");
    await expect(page.locator("html")).toHaveAttribute(
      "data-density",
      "compact",
    );
    expect(await spaceFour(page)).toBeLessThan(roomy);
    expect(
      await page.evaluate(
        () => (window as unknown as { __kept?: boolean }).__kept,
      ),
    ).toBe(true);

    // The sidebar links go to another screen without a reload and keep it.
    await page
      .getByRole("navigation", { name: "Main" })
      .getByRole("link", { name: /^Rules/ })
      .click();
    await expect(
      page.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute(
      "data-density",
      "compact",
    );

    const view = await request.get("/api/settings", {
      headers: { Authorization: `Bearer ${backend.token}` },
    });
    expect(
      ((await view.json()) as { ui: { density: string } }).ui.density,
    ).toBe("compact");

    // A new launch has a new origin: nothing in the page's storage survives, puddle remembers.
    await page.evaluate(() => localStorage.clear());
    await page.goto("/settings");
    await expect(page.getByLabel("Density", { exact: true })).toHaveValue(
      "compact",
    );
    await expect(page.locator("html")).toHaveAttribute(
      "data-density",
      "compact",
    );

    await setDensity(page, "comfortable");
    await expect(page.locator("html")).not.toHaveAttribute(
      "data-density",
      /.*/,
    );
    expect(await spaceFour(page)).toBe(roomy);
  });

  for (const density of DENSITIES) {
    test(`${density}: axe finds nothing, targets stay at least 24px, focus is visible`, async ({
      page,
      backend,
    }) => {
      await open(page, backend, "/settings");
      await setDensity(page, density);
      for (const { path, heading } of SCREENS) {
        await page
          .getByRole("navigation", { name: "Main" })
          .getByRole("link", { name: new RegExp(`^${heading}`) })
          .click();
        await expect(
          page.getByRole("heading", { level: 1, name: heading }),
        ).toBeVisible();
        expect(await axeViolations(page), path).toEqual([]);

        const small = await page.evaluate(() => {
          const out: string[] = [];
          const sel = "button, select, input:not([type=hidden]), [role=radio]";
          for (const el of document.querySelectorAll(sel)) {
            const r = el.getBoundingClientRect();
            if (r.width === 0 || r.height === 0) continue;
            if (r.height < 24 || r.width < 24)
              out.push(
                `${el.tagName} ${el.getAttribute("aria-label") ?? el.id} ${r.width}x${r.height}`,
              );
          }
          return out;
        });
        expect(small, `${path} targets under 24px`).toEqual([]);
      }

      // The focus ring is the same two pixels in both densities.
      await page.keyboard.press("Tab");
      const ring = await page.evaluate(() => {
        const s = getComputedStyle(document.activeElement as Element);
        return { width: s.outlineWidth, style: s.outlineStyle };
      });
      expect(ring).toEqual({ width: "2px", style: "solid" });
    });
  }
});

// Visual baselines: taken on the Linux gate host, one per browser. The Windows project
// renders with other fonts, so it has none.
test.describe("visual baselines", () => {
  test.skip(
    process.platform === "win32",
    "baselines exist for the Linux gate host only",
  );
  test.use({ viewport: { width: 1280, height: 800 } });

  for (const density of DENSITIES) {
    for (const { path, heading } of SCREENS) {
      test(`${density}: ${path}`, async ({ page, backend }) => {
        await open(page, backend, "/settings");
        await setDensity(page, density);
        await page.goto(path);
        await expect(
          page.getByRole("heading", { level: 1, name: heading }),
        ).toBeVisible();
        if (density === "compact")
          await expect(page.locator("html")).toHaveAttribute(
            "data-density",
            "compact",
          );
        await expect(page).toHaveScreenshot(`${density}-${path.slice(1)}.png`, {
          animations: "disabled",
          caret: "hide",
        });
      });
    }
  }
});
