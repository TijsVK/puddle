// SPDX-License-Identifier: GPL-3.0-or-later
// The fixture backend itself, from the browser's side: scripted requests reach the shell's live
// count, a restart makes the page resync, and reset gives each test its own start.
import { expect, test } from "./fixture";

test.describe("the UI fixture backend", () => {
  test.beforeEach(async ({ backend, page }) => {
    await backend.signIn(page);
    await backend.installClock(page);
  });

  test("starts every test from the default scenario: one pending request", async ({
    backend,
    page,
  }) => {
    await page.goto("/inbox");
    await expect(page.getByTestId("pending-badge")).toContainText("1 pending");
    expect((await backend.control.state()).scenario).toBe("default");
  });

  test("a scripted arrival shows in the shell after the page resyncs", async ({
    backend,
    page,
  }) => {
    await page.goto("/inbox");
    await expect(page.getByTestId("pending-badge")).toContainText("1 pending");
    await backend.control.step({
      do: "bulk",
      workspace: "demo",
      count: 4,
      domain: "arrivals.example.org",
    });
    // Ending the event stream makes the page reconnect and refetch (`onResync`).
    await backend.control.restart();
    await expect(page.getByTestId("pending-badge")).toContainText("5 pending");
  });

  test("reset undoes it for the next test", async ({ backend, page }) => {
    await page.goto("/inbox");
    await expect(page.getByTestId("pending-badge")).toContainText("1 pending");
    expect((await backend.control.state()).pending).toBe(1);
  });

  test("a scenario's own script runs, and the clock moves on request", async ({
    backend,
  }) => {
    await backend.control.reset("lived-in");
    const before = await backend.control.state();
    expect(before.scripts).toContain("arrivals");
    await backend.control.script("arrivals");
    await backend.control.advance(60_000);
    const after = await backend.control.state();
    expect(after.pending).toBe(before.pending + 3);
    expect(after.now_ms).toBe(before.now_ms + 60_000);
  });
});
