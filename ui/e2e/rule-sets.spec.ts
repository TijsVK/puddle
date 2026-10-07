// SPDX-License-Identifier: GPL-3.0-or-later
// Rule sets and System managed against the real API on the fixture backend (rules spec §7): the
// Rules screen's sections, a set's switches, and an inbox decision into a set. Every test starts
// from the `default` scenario (one pending request, demo -> registry.example.org).
import type { APIRequestContext, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

interface RuleSetView {
  id: string;
  name: string;
  global: boolean | null;
  overrides: { sandbox: string; enabled: boolean }[];
  entries: { pattern: string; effect: string }[];
}

async function sets(
  request: APIRequestContext,
  backend: Backend,
): Promise<RuleSetView[]> {
  const response = await request.get("/api/rule-sets", {
    headers: auth(backend),
  });
  return ((await response.json()) as { sets: RuleSetView[] }).sets;
}

async function openRules(page: Page, backend: Backend): Promise<void> {
  await backend.signIn(page);
  await page.goto("/rules");
  await expect(
    page.getByRole("heading", { level: 2, name: "Rule sets" }),
  ).toBeVisible();
}

test.beforeEach(async ({ backend }) => {
  await backend.control.reset("default");
});

test("System managed lists what puddle allows for the editor, with the reason", async ({
  page,
  backend,
}) => {
  const csp = await watchCsp(page);
  await openRules(page, backend);
  const system = page.getByRole("region", { name: "System managed" });
  await expect(system).toContainText("open-vsx.org");
  await expect(system).toContainText("bundled code-server");
  await expect(system).not.toContainText("marketplace.visualstudio.com");
  await expect(system).toContainText("add a deny rule to block one");
  expect(await axeViolations(page), "rules with sets").toEqual([]);
  expect(await csp()).toEqual([]);
});

test("a built-in set ships off, and switches for one workspace", async ({
  page,
  request,
  backend,
}) => {
  await openRules(page, backend);
  const github = page.getByRole("article", { name: "GitHub" });
  await expect(
    github.getByRole("switch", { name: "On for every workspace" }),
  ).not.toBeChecked();
  await expect(github).toContainText("Off (built-in sets ship off)");
  await github.getByLabel("Workspace name").fill("demo");
  await github.getByRole("button", { name: "On there" }).click();
  await expect(github).toContainText("On in demo");
  const stored = (await sets(request, backend)).find(
    (s) => s.id === "builtin:github",
  );
  expect(stored?.overrides).toEqual([{ sandbox: "demo", enabled: true }]);
  // Every workspace asks first.
  await github.getByRole("switch", { name: "On for every workspace" }).click();
  const confirm = page.getByRole("alertdialog", {
    name: "Turn on for every workspace?",
  });
  expect(await axeViolations(page), "confirm").toEqual([]);
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(
    github.getByRole("switch", { name: "On for every workspace" }),
  ).not.toBeChecked();
});

test("a set of your own: make it, then approve a request into it from the inbox", async ({
  page,
  request,
  backend,
}) => {
  await openRules(page, backend);
  await page.getByRole("button", { name: "New rule set" }).click();
  const dialog = page.getByRole("dialog", { name: "New rule set" });
  await dialog.getByLabel("Name").fill("Client X");
  expect(await axeViolations(page), "new set").toEqual([]);
  await dialog.getByRole("button", { name: "Make rule set" }).click();
  const card = page.getByRole("article", { name: "Client X" });
  await expect(card).toContainText("0 entries");
  // On everywhere would ask; keep it to demo so the inbox decision needs no confirm.
  await card.getByRole("switch", { name: "On for every workspace" }).click();
  await expect(card).toContainText("Off for every workspace");
  await card.getByLabel("Workspace name").fill("demo");
  await card.getByRole("button", { name: "On there" }).click();
  await expect(card).toContainText("On in demo");

  await page.goto("/inbox");
  const row = page.locator("li.req", { hasText: "registry.example.org" });
  await row.getByRole("button", { name: /^More choices for/ }).click();
  const options = page.getByRole("dialog", { name: /^Choices for/ });
  await options.getByRole("radio", { name: /Into rule set Client X/ }).check();
  await options.getByRole("button", { name: "Allow", exact: true }).click();
  await expect(row).toHaveCount(0);
  await expect(
    page.getByRole("region", { name: "Notifications" }).getByRole("status"),
  ).toContainText("Allowed registry.example.org in rule set Client X");
  const client = (await sets(request, backend)).find(
    (s) => s.name === "Client X",
  );
  expect(client?.entries).toEqual([
    expect.objectContaining({
      pattern: "registry.example.org",
      effect: "allow",
    }),
  ]);
});
