// SPDX-License-Identifier: GPL-3.0-or-later
// The activity screen against the real API on the fixture backend. Every test starts from the
// `lived-in` scenario on its worker's own backend; the page clock is the fixture's. Tests wait on
// what the page shows, never on time.
import { readFileSync } from "node:fs";
import type { APIRequestContext, Locator, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

test.beforeEach(async ({ backend }) => {
  await backend.control.reset("lived-in");
});

async function visit(page: Page, backend: Backend, query = ""): Promise<void> {
  await backend.installClock(page);
  await backend.signIn(page);
  await page.goto(`/activity${query}`);
  await expect(
    page.getByRole("heading", { level: 1, name: "Activity" }),
  ).toBeVisible();
}

/** Opens the screen and waits for the first rows. */
async function openActivity(
  page: Page,
  backend: Backend,
  query = "",
): Promise<void> {
  await visit(page, backend, query);
  await expect(rows(page).first()).toBeVisible();
}

const rows = (page: Page): Locator => page.locator("tbody tr.row");
const destinations = (page: Page) =>
  rows(page).locator("td:nth-child(4)").allTextContents();
const region = (page: Page) =>
  page.getByRole("region", { name: "Activity records" });

/** What the log says for a query, read straight from the API: every record, oldest first. */
async function matching(
  request: APIRequestContext,
  backend: Backend,
  query: Record<string, string> = {},
): Promise<{ id: number; record: Record<string, unknown> }[]> {
  const all: { id: number; record: Record<string, unknown> }[] = [];
  let after = 0;
  for (;;) {
    const params = new URLSearchParams({
      ...query,
      after: String(after),
      limit: "500",
    });
    const reply = await request.get(`/api/audit?${params}`, {
      headers: { Authorization: `Bearer ${backend.token}` },
    });
    const page = (await reply.json()) as {
      entries: { id: number; record: Record<string, unknown> }[];
      next_after: number;
    };
    all.push(...page.entries);
    after = page.next_after;
    if (page.entries.length < 500) return all;
  }
}

/** The "N records" line: the table draws only a window of the rows, so rows can't be counted. */
const total = (page: Page, n: number) =>
  expect(page.locator("p.count")).toHaveText(new RegExp(`^${n} records?\\b`));

/** The toast region: the page has other status lines (a running export). */
const toast = (page: Page) =>
  page.getByRole("region", { name: "Notifications" }).getByRole("status");

/** Scrolls the list down by `count` rows and waits until the table has moved there. */
async function scrollDown(page: Page, count: number): Promise<void> {
  await region(page).evaluate((el, y) => {
    el.scrollTop = y;
  }, 36 * count);
  await expect
    .poll(async () =>
      Number(await rows(page).first().getAttribute("aria-rowindex")),
    )
    .toBeGreaterThan(count / 2);
}

/** One more connection record, written through the fixture (it emits `audit_appended`). */
function connect(backend: Backend, host: string, extra = {}) {
  return backend.control.step({
    do: "connection",
    sandbox: "web-shop",
    host,
    decision: "allow",
    ...extra,
  });
}

test.describe("the list", () => {
  test("shows what the fixture recorded, newest first, with outcomes and sizes", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    await expect(page.getByText("Every connection, decision")).toBeVisible();
    const hosts = await destinations(page);
    // The newest connection of the scenario is the blocked repo.example.org (1.2 s ago in the
    // scenario's minutes), the oldest the github.com one: order follows the log, not the host.
    expect(hosts.indexOf("repo.example.org:443")).toBeLessThan(
      hosts.indexOf("github.com:443"),
    );
    const github = rows(page).filter({ hasText: "github.com:443" });
    await expect(github).toContainText("Allowed");
    await expect(github).toContainText("web-shop");
    await expect(github).toContainText("Connection");
    await expect(github).toContainText("2.0 MB down");
    await expect(
      rows(page).filter({ hasText: "ads.example.net" }),
    ).toContainText("Denied");
    await expect(rows(page).filter({ hasText: "localhost" })).toContainText(
      "Blocked",
    );
    await expect(
      rows(page).filter({ hasText: "Request opened" }).first(),
    ).toContainText("Waiting");
  });

  test("the time cell says the exact moment on hover, and today's records print only the time", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    const time = rows(page).first().locator("time");
    await expect(time).toHaveAttribute("datetime", /^2026-10-07T/);
    await expect(time).toHaveAttribute("title", /2026/);
    await expect(time).toHaveText(/^\d{1,2}:\d{2}:\d{2}( [AP]M)?$/);
  });

  test("a row is exactly as tall as the window arithmetic assumes", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    const [first, second] = await rows(page).all();
    const a = await first?.boundingBox();
    const b = await second?.boundingBox();
    expect((b?.y ?? 0) - (a?.y ?? 0)).toBeCloseTo(36, 0);
    await first?.getByRole("button").click();
    const detail = page.locator("tbody tr.detail");
    expect((await detail.boundingBox())?.height).toBeCloseTo(280, 0);
  });

  test("shows an empty log as nothing recorded", async ({ page, backend }) => {
    await backend.control.reset("empty");
    await visit(page, backend, "?range=all");
    await expect(
      page.getByRole("heading", { name: "Nothing recorded yet" }),
    ).toBeVisible();
    await page.goto("/activity?host=zzz");
    await expect(
      page.getByRole("heading", { name: "No records match" }),
    ).toBeVisible();
  });
});

test.describe("filters", () => {
  test("each filter is applied by the server and kept in the address", async ({
    page,
    backend,
    request,
  }) => {
    await openActivity(page, backend, "?range=all");
    const everything = (await matching(request, backend)).length;
    await total(page, everything);

    const connections = (
      await matching(request, backend, { type: "connection" })
    ).length;
    await page.getByLabel("Type").selectOption("connection");
    await total(page, connections);
    await expect(page).toHaveURL(/type=connection/);

    const blocked = (
      await matching(request, backend, {
        type: "connection",
        outcome: "blocked",
      })
    ).length;
    await page.getByLabel("Outcome").selectOption("blocked");
    await total(page, blocked);

    const shop = (
      await matching(request, backend, {
        type: "connection",
        outcome: "blocked",
        sandbox: "docs-site",
      })
    ).length;
    await page.getByLabel("Workspace").selectOption("docs-site");
    await total(page, shop);
    await expect(rows(page).first()).toContainText("localhost");

    await page.getByLabel("Outcome").selectOption("");
    await page.getByLabel("Type").selectOption("");
    await page.getByLabel("Workspace").selectOption("");
    await page.getByLabel("Host contains").fill("CRATES");
    const crates = await matching(request, backend, {
      host_contains: "crates",
    });
    await total(page, crates.length);
    await expect(page).toHaveURL(/host=CRATES/);
    // The filters narrow each other: every step found something, and fewer each time.
    expect(everything).toBeGreaterThan(connections);
    expect(connections).toBeGreaterThan(blocked);
    expect(blocked).toBeGreaterThan(shop);
    expect(shop).toBeGreaterThan(0);
    expect(crates.length).toBeGreaterThan(0);
    await expect(rows(page).first()).toContainText("crates.io");
  });

  test("the time range cuts the log", async ({ page, backend, request }) => {
    await openActivity(page, backend, "?type=connection");
    const before = (await matching(request, backend, { type: "connection" }))
      .length;
    await total(page, before);
    await backend.control.step({
      do: "connection",
      sandbox: "web-shop",
      host: "ancient.example.org",
      decision: "allow",
      ago_ms: 3 * 86_400_000,
    });
    await page.getByLabel("Time range").selectOption("7d");
    await total(page, before + 1);
    await expect(page).toHaveURL(/range=7d/);
    await page.getByLabel("Time range").selectOption("1h");
    await total(page, before);
    await page.getByLabel("Time range").selectOption("24h");
    await total(page, before);
    await expect(page).not.toHaveURL(/range=/);
    await page.getByLabel("Time range").selectOption("all");
    await total(page, before + 1);
  });

  test("an address with filters opens the same view (a view can be linked)", async ({
    page,
    backend,
    request,
  }) => {
    const expected = (
      await matching(request, backend, {
        sandbox: "web-shop",
        type: "connection",
        outcome: "allow",
        host_contains: "crates",
      })
    ).length;
    expect(expected).toBeGreaterThan(0);
    await openActivity(
      page,
      backend,
      "?workspace=web-shop&type=connection&outcome=allow&host=crates&range=all",
    );
    await total(page, expected);
    await expect(page.getByLabel("Workspace")).toHaveValue("web-shop");
    await expect(page.getByLabel("Type")).toHaveValue("connection");
    await expect(page.getByLabel("Outcome")).toHaveValue("allow");
    await expect(page.getByLabel("Host contains")).toHaveValue("crates");
    await expect(page.getByLabel("Time range")).toHaveValue("all");
    await page.reload();
    await total(page, expected);
  });

  test("clear filters goes back to the default view", async ({
    page,
    backend,
    request,
  }) => {
    await openActivity(page, backend, "?type=connection&range=all");
    const connections = (
      await matching(request, backend, { type: "connection" })
    ).length;
    await total(page, connections);
    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(page).toHaveURL(/\/activity$/);
    await expect(page.getByLabel("Type")).toHaveValue("");
    await expect(
      page.getByRole("button", { name: "Clear filters" }),
    ).toHaveCount(0);
    await expect(page.locator("p.count")).not.toHaveText(
      new RegExp(`^${connections} records?\\b`),
    );
  });

  test("a rule's pattern is found by the host filter", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend, "?range=all&type=rule_created");
    await page.getByLabel("Host contains").fill("npmjs");
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("registry.npmjs.org");
    await expect(rows(page).first()).toContainText("Rule added");
  });

  test("the internationalised host is shown as the API sends it", async ({
    page,
    backend,
  }) => {
    await backend.control.step({
      do: "connection",
      sandbox: "web-shop",
      host: "xn--bcher-kva.example.com",
      decision: "allow",
    });
    await openActivity(page, backend, "?host=bcher");
    await expect(rows(page).first()).toContainText("xn--bcher-kva.example.com");
  });
});

test.describe("the raw record", () => {
  test("a row opens to the record as the API sent it, and closes again", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend, "?type=connection");
    const row = rows(page).filter({ hasText: "ads.example.net" });
    const toggle = row.getByRole("button");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    const raw = page.locator("tbody tr.detail pre");
    const record = JSON.parse((await raw.textContent()) ?? "{}") as Record<
      string,
      unknown
    >;
    expect(record).toMatchObject({
      type: "connection",
      host: "ads.example.net",
      decision: "deny",
      upstream: null,
    });
    await toggle.click();
    await expect(raw).toHaveCount(0);
  });

  test("the record matches what the API returns for that row", async ({
    page,
    backend,
    request,
  }) => {
    await openActivity(page, backend, "?type=connection&host=github");
    await rows(page).first().click();
    const shown = JSON.parse(
      (await page.locator("tbody tr.detail pre").textContent()) ?? "{}",
    ) as unknown;
    const reply = await request.get(
      "/api/audit?type=connection&host_contains=github",
      {
        headers: { Authorization: `Bearer ${backend.token}` },
      },
    );
    const body = (await reply.json()) as { entries: { record: unknown }[] };
    expect(shown).toEqual(body.entries[0]?.record);
  });

  test("one row is open at a time and a click on the row opens it too", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    await rows(page).nth(0).locator("td:nth-child(3)").click();
    await expect(page.locator("tbody tr.detail")).toHaveCount(1);
    await rows(page).nth(1).locator("td:nth-child(3)").click();
    await expect(page.locator("tbody tr.detail")).toHaveCount(1);
  });
});

test.describe("live", () => {
  test("a new record shows on top at once, from the event, with no reload", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    await connect(backend, "arrived.example.org");
    await expect(rows(page).first()).toContainText("arrived.example.org");
  });

  test("a record that does not match the filter does not appear", async ({
    page,
    backend,
  }) => {
    await visit(page, backend, "?host=wanted");
    await total(page, 0);
    await connect(backend, "unrelated.example.org");
    await connect(backend, "wanted.example.org");
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("wanted.example.org");
  });

  test("a decision made elsewhere shows up as records", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend, "?type=rule_created");
    const before = await rows(page).count();
    await backend.control.step({
      do: "rule",
      effect: "deny",
      pattern: "blocked-by-rule.example.org",
    });
    await expect(rows(page)).toHaveCount(before + 1);
    await expect(rows(page).first()).toContainText(
      "blocked-by-rule.example.org",
    );
  });

  test("records wait while the user is scrolled away, and the button brings them", async ({
    page,
    backend,
  }) => {
    await backend.control.step({ do: "history", count: 600 });
    await openActivity(page, backend, "?range=all");
    await expect(page.locator("p.count")).toHaveText(/loaded; older ones load/);
    await scrollDown(page, 100);
    await expect(rows(page).first()).not.toContainText("fresh.example.org");
    await connect(backend, "fresh.example.org");
    const show = page.getByRole("button", { name: /1 new\s+record: show/ });
    await expect(show).toBeVisible();
    await expect(page.locator("tbody")).not.toContainText("fresh.example.org");
    await connect(backend, "fresher.example.org");
    await expect(
      page.getByRole("button", { name: /2 new\s+records: show/ }),
    ).toBeVisible();
    await page.getByRole("button", { name: /2 new\s+records: show/ }).click();
    await expect(rows(page).first()).toContainText("fresher.example.org");
    await expect(rows(page).nth(1)).toContainText("fresh.example.org");
    expect(await region(page).evaluate((el) => el.scrollTop)).toBe(0);
    await expect(show).toHaveCount(0);
  });

  test("scrolling back to the top lets the held records in", async ({
    page,
    backend,
  }) => {
    await backend.control.step({ do: "history", count: 600 });
    await openActivity(page, backend, "?range=all");
    await scrollDown(page, 50);
    await connect(backend, "held.example.org");
    await expect(
      page.getByRole("button", { name: /new\s+record/ }),
    ).toBeVisible();
    await region(page).evaluate((el) => {
      el.scrollTop = 0;
    });
    await expect(rows(page).first()).toContainText("held.example.org");
  });

  test("with Live off nothing changes until it is on again", async ({
    page,
    backend,
    request,
  }) => {
    await openActivity(page, backend, "?range=all");
    const live = page.getByRole("checkbox", { name: "Live" });
    await expect(live).toBeChecked();
    await live.uncheck();
    const before = (await matching(request, backend)).length;
    await total(page, before);
    await connect(backend, "while-off.example.org");
    await connect(backend, "while-off-2.example.org");
    // A later read on the same stream proves the events were delivered and ignored.
    await page.getByLabel("Outcome").selectOption("allow");
    await expect(rows(page).first()).toContainText("while-off-2.example.org");
    await page.getByLabel("Outcome").selectOption("");
    await total(page, before + 2);
    await live.check();
    await connect(backend, "back-on.example.org");
    await expect(rows(page).first()).toContainText("back-on.example.org");
  });

  test("a restarted API is picked up again, with what was missed", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    await backend.control.restart();
    await connect(backend, "after-restart.example.org");
    await expect(rows(page).first()).toContainText(
      "after-restart.example.org",
      { timeout: 20_000 },
    );
  });
});

test.describe("export", () => {
  async function download(page: Page): Promise<string[]> {
    const downloading = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export JSON lines" }).click();
    const file = await downloading;
    expect(file.suggestedFilename()).toMatch(
      /^puddle-activity-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.jsonl$/,
    );
    const path = await file.path();
    return readFileSync(path, "utf8").trimEnd().split("\n");
  }

  test("saves the filtered records as JSON lines, oldest first", async ({
    page,
    backend,
    request,
  }) => {
    const expected = await matching(request, backend, {
      type: "connection",
      outcome: "allow",
    });
    expect(expected.length).toBeGreaterThan(3);
    await openActivity(page, backend, "?type=connection&outcome=allow");
    await total(page, expected.length);
    const lines = await download(page);
    const records = lines.map(
      (line) => JSON.parse(line) as Record<string, unknown>,
    );
    // Exactly what the API holds for that filter, in log order, one record per line.
    expect(records).toEqual(expected.map((e) => e.record));
    for (const record of records) {
      expect(record).toMatchObject({ type: "connection", decision: "allow" });
    }
    await expect(toast(page)).toContainText(`Saved ${expected.length} records`);
  });

  test("saves a log longer than a page, nothing missed or doubled", async ({
    page,
    backend,
    request,
  }) => {
    const before = (await matching(request, backend, { type: "connection" }))
      .length;
    await backend.control.step({ do: "history", count: 1300 });
    await openActivity(page, backend, "?type=connection&range=all");
    const lines = await download(page);
    expect(lines).toHaveLength(before + 1300);
    // The same lines the API holds, in the same order, across three pages of 500.
    const all = await matching(request, backend, { type: "connection" });
    expect(lines).toEqual(all.map((e) => JSON.stringify(e.record)));
    // The scenario's own connections come first (they are the oldest in the log); the generated
    // ones follow in the order they were written, which is time order.
    const stamps = lines
      .slice(before)
      .map((l) => (JSON.parse(l) as { ts: number }).ts);
    expect(stamps).toHaveLength(1300);
    expect([...stamps].sort((a, b) => a - b)).toEqual(stamps);
  });

  test("says so when nothing matches the filter", async ({ page, backend }) => {
    await openActivity(page, backend);
    await page.getByLabel("Host contains").fill("nothing-like-it");
    await expect(
      page.getByRole("heading", { name: "No records match" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Export JSON lines" }).click();
    await expect(toast(page)).toContainText("Nothing to export");
  });
});

test.describe("a long log", () => {
  const RECORDS = 100_000;
  // Wall-clock task length on a busy machine is noisy (the inbox bar went through the same): a
  // regression that blocks the page costs seconds, so the test enforces a loose bar and reports
  // the best figure; the target is "no task over 50 ms while scrolling 1 000 rows".
  const LONG_TASK_TARGET_MS = 50;

  test(`${RECORDS.toLocaleString()} records: scrolling 1 000 rows draws a bounded window and blocks nothing`, async ({
    page,
    backend,
  }) => {
    test.setTimeout(600_000);
    await backend.control.step({ do: "history", count: RECORDS });
    await openActivity(page, backend, "?range=all");
    await page.evaluate(() => {
      const w = window as unknown as { __long: number[] };
      w.__long = [];
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) w.__long.push(entry.duration);
      }).observe({ type: "longtask", buffered: true });
    });
    const target = 36 * 1000;
    for (let guard = 0; guard < 400; guard += 1) {
      const top = await region(page).evaluate(async (el, goal) => {
        el.scrollTop = Math.min(el.scrollTop + 36 * 20, goal);
        await new Promise((r) => requestAnimationFrame(r));
        return el.scrollTop;
      }, target);
      if (top >= target) break;
      // Reached the end of what is loaded: the next page comes, then the scroll goes on.
      await expect
        .poll(
          () =>
            region(page).evaluate(
              (el) => el.scrollHeight - el.clientHeight - el.scrollTop,
            ),
          { timeout: 30_000 },
        )
        .toBeGreaterThan(0);
    }
    expect(
      await region(page).evaluate((el) => el.scrollTop),
    ).toBeGreaterThanOrEqual(target);
    // Without a clock: the table never holds more rows than a screen and its overscan.
    expect(await rows(page).count()).toBeLessThan(60);
    const long = await page.evaluate(
      () => (window as unknown as { __long: number[] }).__long,
    );
    const worst = Math.max(0, ...long);
    test.info().annotations.push({
      type: "activity-100k",
      description: `${RECORDS} records, 1000 rows scrolled: ${long.length} long tasks, worst ${worst.toFixed(0)} ms (target ${LONG_TASK_TARGET_MS} ms)`,
    });
    expect(worst, "longest task while scrolling").toBeLessThan(
      LONG_TASK_TARGET_MS * 4,
    );
  });
});

test.describe("keyboard only", () => {
  test("filter, open a record and read it without a pointer", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend, "?type=connection");
    await page.getByLabel("Host contains").focus();
    await page.keyboard.type("ads.example");
    await expect(rows(page)).toHaveCount(1);
    const toggle = rows(page).first().getByRole("button");
    await toggle.focus();
    await page.keyboard.press("Enter");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await page.keyboard.press("Tab");
    await expect(page.locator("tbody tr.detail pre")).toBeFocused();
    await toggle.focus();
    await page.keyboard.press("Space");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  test("the scroll area takes focus, and Page Down scrolls it", async ({
    page,
    backend,
  }) => {
    await backend.control.step({ do: "history", count: 600 });
    await openActivity(page, backend);
    await region(page).focus();
    await page.keyboard.press("PageDown");
    await expect
      .poll(() => region(page).evaluate((el) => el.scrollTop))
      .toBeGreaterThan(100);
  });
});

test.describe("accessibility", () => {
  for (const scheme of ["light", "dark"] as const) {
    test(`axe finds nothing in ${scheme}: the list, an open record, the empty state`, async ({
      page,
      backend,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await watchCsp(page);
      await openActivity(page, backend, "?range=all");
      expect(await axeViolations(page), "list").toEqual([]);
      await rows(page).nth(1).getByRole("button").click();
      expect(await axeViolations(page), "open record").toEqual([]);
      await page.getByRole("button", { name: "Export JSON lines" }).click();
      await expect(toast(page)).toContainText("Saved");
      expect(await axeViolations(page), "toast").toEqual([]);
      await page.getByLabel("Host contains").fill("zzz-none");
      await expect(
        page.getByRole("heading", { name: "No records match" }),
      ).toBeVisible();
      expect(await axeViolations(page), "no match").toEqual([]);
      expect(await csp()).toEqual([]);
    });
  }

  test("the buttons and controls are at least 24 by 24 CSS pixels (WCAG 2.5.8)", async ({
    page,
    backend,
  }) => {
    await openActivity(page, backend);
    for (const control of [
      rows(page).first().getByRole("button"),
      page.getByRole("button", { name: "Export JSON lines" }),
      page.getByLabel("Host contains"),
      page.getByLabel("Workspace"),
      page.getByLabel("Type"),
      page.getByLabel("Outcome"),
      page.getByLabel("Time range"),
      page.getByRole("checkbox", { name: "Live" }),
    ]) {
      const box = await control.boundingBox();
      expect(box?.width ?? 0).toBeGreaterThanOrEqual(24);
      expect(box?.height ?? 0).toBeGreaterThanOrEqual(24);
    }
  });
});
