// SPDX-License-Identifier: GPL-3.0-or-later
// The network-health screen and the notices against the real API on the fixture backend. Each
// test has a backend of its own. Waits are on conditions (text on the page, a response), never on
// time or key order.
import type { Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

async function open(page: Page, backend: Backend, scenario: string) {
  await backend.control.reset(scenario);
  await backend.signIn(page);
  await page.goto("/settings/network-health");
  await expect(
    page.getByRole("heading", { level: 1, name: "Network health" }),
  ).toBeVisible();
}

const notices = (page: Page) => page.getByRole("region", { name: "Notices" });

test("a corporate network: the setup, sign-in, roots and routes, no notice, no CSP violation", async ({
  page,
  backend,
}) => {
  const csp = await watchCsp(page);
  await open(page, backend, "corporate-network");
  await expect(page.getByText("Automatic proxy script (PAC)")).toBeVisible();
  await expect(
    page.getByText("http://wpad.corp.example/proxy.pac"),
  ).toBeVisible();
  await expect(page.getByText("Signed in")).toBeVisible();
  await expect(page.getByRole("cell", { name: /^Corp Root CA/ })).toBeVisible();
  await expect(page.getByText("Corp Issuing CA 01")).toBeVisible();
  await expect(page.getByText(/Old Corp Root CA/)).toBeVisible();
  await expect(page.getByText("https://github.com:443")).toBeVisible();
  // A proxy marked as not answering is a note, with what to do about it.
  await expect(
    page.getByText(/proxy-b.corp.example:8080 is marked as not answering/),
  ).toBeVisible();
  await expect(page.getByText("No problems found.")).toBeVisible();
  await expect(notices(page).getByRole("button")).toHaveCount(0);
  expect(await csp()).toEqual([]);
});

test("a network change updates the open page, and trouble raises a notice that clears again", async ({
  page,
  backend,
}) => {
  await open(page, backend, "corporate-network");
  await expect(page.getByText(/change number 3/)).toBeVisible();

  // The change script moves to epoch 4 and clears the dead proxy.
  await backend.control.script("network-change");
  await expect(page.getByText(/change number 4/)).toBeVisible();
  await expect(page.getByText(/is marked as not answering/)).toHaveCount(0);

  await backend.control.script("network-trouble");
  await expect(page.getByText("3 problems found.")).toBeVisible();
  const notice = notices(page).getByText(/^Network trouble:/);
  await expect(notice).toBeVisible();
  // Nothing moved the focus to the notice.
  await expect(notice).not.toBeFocused();
  await expect(page.getByText(/What to do:/).first()).toBeVisible();

  await backend.control.script("network-change");
  await expect(page.getByText("No problems found.")).toBeVisible();
  await expect(notices(page).getByText(/^Network trouble:/)).toHaveCount(0);
});

test("trouble on a fresh start: the notice links to the screen, which says what to do", async ({
  page,
  backend,
}) => {
  await backend.control.reset("network-trouble");
  await backend.signIn(page);
  await page.goto("/workspaces");
  const notice = notices(page).getByText(/^Network trouble:/);
  await expect(notice).toBeVisible();
  await notices(page).getByRole("link", { name: "Network health" }).click();
  await expect(page).toHaveURL(/\/settings\/network-health$/);
  await expect(
    page.locator("main").getByText(/The proxy script at .* isn't answering/),
  ).toBeVisible();
  await expect(
    page.getByText(/couldn't read a certificate store/),
  ).toBeVisible();
  await expect(
    page.getByText(/Signing in to fallback.corp.example:3128 failed/),
  ).toBeVisible();
  await page.getByRole("button", { name: "Check again" }).click();
  await expect(page.getByRole("button", { name: "Check again" })).toBeEnabled();
});

test("settings link to the details", async ({ page, backend }) => {
  await backend.signIn(page);
  await page.goto("/settings");
  await page.getByRole("link", { name: /Details/ }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Network health" }),
  ).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`axe finds nothing in ${scheme}, healthy or in trouble`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await open(page, backend, "corporate-network");
    await expect(page.getByText("No problems found.")).toBeVisible();
    expect(await axeViolations(page), "healthy").toEqual([]);
    await backend.control.script("network-trouble");
    await expect(notices(page).getByText(/^Network trouble:/)).toBeVisible();
    expect(await axeViolations(page), "trouble").toEqual([]);
  });
}
