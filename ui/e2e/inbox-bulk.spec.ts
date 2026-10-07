// SPDX-License-Identifier: GPL-3.0-or-later
// The inbox with 500 open requests (the fixture's `spread` step opens them): it must show them
// at once.
import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";

/** Data arrival to first paint, and to the last row painted, in the page just loaded. */
async function timings(page: Page) {
  await expect(page.locator("li.req")).toHaveCount(501);
  return page.evaluate(async () => {
    const at = (name: string) =>
      performance.getEntriesByName(name)[0]?.startTime ?? -1;
    for (let i = 0; i < 100 && at("puddle:inbox-all-painted") < 0; i += 1) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const data = at("puddle:inbox-data");
    return {
      first: at("puddle:inbox-painted") - data,
      all: at("puddle:inbox-all-painted") - data,
    };
  });
}

test.beforeEach(async ({ backend, page }) => {
  await backend.control.step({ do: "spread", count: 500 });
  await backend.signIn(page);
});

// Wall-clock time on a busy machine (CI runners, a machine mid-build) is noisy, so the bar is
// held by the best of five loads; a real slowdown moves all five.
test("500 open requests: the first rows paint in under 200 ms after their data arrives, all of them soon after", async ({
  page,
}) => {
  const runs = [];
  for (let i = 0; i < 5; i += 1) {
    await page.goto("/inbox");
    runs.push(await timings(page));
  }
  const first = Math.min(...runs.map((r) => r.first));
  const all = Math.min(...runs.map((r) => r.all));
  expect(first).toBeGreaterThan(0);
  expect(all).toBeGreaterThanOrEqual(first);
  test.info().annotations.push({
    type: "inbox-500",
    description: `best of 5: first paint ${first.toFixed(0)} ms, all rows ${all.toFixed(0)} ms (runs: ${runs.map((r) => r.first.toFixed(0)).join(", ")})`,
  });
  expect(first, "data to first paint").toBeLessThan(200);
  expect(all, "data to all 501 rows painted").toBeLessThan(1000);
});

test("a 500-row inbox is still driven by the keyboard", async ({ page }) => {
  await page.goto("/inbox");
  await expect(page.locator("li.req")).toHaveCount(501);
  await page.locator("main").focus();
  await page.keyboard.press("j");
  await page.keyboard.press("j");
  await expect(page.locator("li.req[aria-current='true']")).toBeFocused();
});
