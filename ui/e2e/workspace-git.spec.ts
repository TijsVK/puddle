// SPDX-License-Identifier: GPL-3.0-or-later
// A workspace's Git tab against the real API on the fixture backend, scenario `git-identities`:
// web-shop has Work and a table of two repositories (design-tokens without Push), docs-site has
// Personal and Work and the push list off, data-tools has nothing. Waits are on conditions.
import type { Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

async function open(page: Page, backend: Backend, workspace = "web-shop") {
  await backend.control.reset("git-identities");
  await backend.signIn(page);
  await page.goto(`/workspaces/${workspace}/git`);
  await expect(
    page.getByRole("heading", { level: 2, name: "Identities" }),
  ).toBeVisible();
}

const table = (page: Page, workspace = "web-shop") =>
  page.getByRole("table", { name: `Repositories of ${workspace}` });
const notices = (page: Page) => page.getByRole("region", { name: "Notices" });

/** Emits until the page shows the notice: the event stream may connect after the page loaded. */
async function raise(
  backend: Backend,
  page: Page,
  event: Record<string, unknown>,
  text: string,
) {
  await expect(async () => {
    await backend.control.emit(event);
    await expect(notices(page)).toContainText(text, { timeout: 500 });
  }).toPass();
}

const denied = (access: "push" | "pull") => ({
  type: "git_access_denied",
  workspace: "web-shop",
  host: "github.com",
  owner: "acme",
  repo: "billing",
  access,
});

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

test("is a tab of the workspace page and shows identities, switches and the table", async ({
  page,
  backend,
}) => {
  const csp = await watchCsp(page);
  await open(page, backend);
  const tabs = page.getByRole("navigation", { name: "Workspace sections" });
  await expect(tabs.getByRole("link", { name: "Git" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  const ids = page.getByRole("list", {
    name: "Identities of web-shop, in order",
  });
  await expect(ids).toContainText("Work");
  await expect(ids).toContainText("github.com: acme, acme-labs");
  await expect(
    page.getByRole("switch", { name: "Only push to listed repos" }),
  ).toBeChecked();
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).not.toBeChecked();
  await expect(
    table(page).getByRole("checkbox", {
      name: "Push github.com/acme/web-shop",
    }),
  ).toBeChecked();
  await expect(
    table(page).getByRole("checkbox", {
      name: "Push github.com/acme/design-tokens",
    }),
  ).not.toBeChecked();
  await expect(
    page.getByText("Opening the workspace in desktop VS Code is different"),
  ).toBeVisible();
  expect(await csp()).toEqual([]);
});

test("a toggle and a switch are saved at once and survive a reload", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  // The boxes are saved, then redrawn from what is stored, so each click is followed by its result.
  await table(page)
    .getByRole("checkbox", { name: "Push github.com/acme/design-tokens" })
    .click();
  await expect(
    table(page).getByRole("checkbox", {
      name: "Push github.com/acme/design-tokens",
    }),
  ).toBeChecked();
  await page
    .getByRole("switch", { name: "Only pull from listed repos" })
    .click();
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).toBeChecked();
  await page.reload();
  await expect(
    table(page).getByRole("checkbox", {
      name: "Push github.com/acme/design-tokens",
    }),
  ).toBeChecked();
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).toBeChecked();
  await expect(
    page.getByText(
      /A fetch is allowed only from a repository whose Pull box is ticked/,
    ),
  ).toBeVisible();
});

test("adds a repository by its address and removes one", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await page
    .getByLabel("Add a repository")
    .fill("https://github.com/Acme/Billing.git");
  await page.getByLabel("Push", { exact: true }).uncheck();
  await page.getByRole("button", { name: "Add repository" }).click();
  await expect(page.getByText("Listed github.com/acme/billing.")).toBeVisible();
  await expect(
    table(page).getByRole("checkbox", { name: "Pull github.com/acme/billing" }),
  ).toBeChecked();
  await expect(
    table(page).getByRole("checkbox", { name: "Push github.com/acme/billing" }),
  ).not.toBeChecked();

  await table(page)
    .getByRole("button", {
      name: "Remove github.com/acme/design-tokens from the list",
    })
    .click();
  await expect(table(page)).not.toContainText("design-tokens");
  await expect(
    page.getByRole("heading", { level: 2, name: "Repositories" }),
  ).toBeFocused();
});

test("refuses an address it cannot read, in the create form's words, and a repository already listed", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  const url = page.getByLabel("Add a repository");
  await url.fill("git@github.com:acme/x.git");
  await page.getByRole("button", { name: "Add repository" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "SSH remotes are not supported yet",
  );
  await expect(url).toBeFocused();
  await url.fill("https://github.com/acme");
  await page.getByRole("button", { name: "Add repository" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "not a repository address puddle can read",
  );
  await url.fill("https://github.com/acme/web-shop");
  await page.getByRole("button", { name: "Add repository" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "already in the repository table",
  );
});

test("adds an identity, and refuses one that covers what another already does, naming both", async ({
  page,
  backend,
  request,
}) => {
  await open(page, backend, "data-tools");
  await expect(
    page.getByText(/No identity here covers github.com\/acme/),
  ).toBeVisible();
  const select = page.getByLabel("Add an identity");
  await select.selectOption({ label: "Work" });
  await page.getByRole("button", { name: "Add identity" }).click();
  await expect(
    page.getByRole("list", { name: "Identities of data-tools, in order" }),
  ).toContainText("Work");
  await expect(
    page.getByText(/No identity here covers github.com\/acme/),
  ).toHaveCount(0);

  const made = await request.post("/api/identities", {
    headers: auth(backend),
    data: {
      label: "Clash",
      author: { name: "C", email: "c@example.com" },
      credentials: [
        {
          host: "github.com",
          source: { kind: "gh", host: "github.com", account: "clash" },
          covers: { owners: ["acme"], rest_of_host: false },
        },
      ],
    },
  });
  expect(made.status()).toBe(201);
  await page.reload();
  await page.getByLabel("Add an identity").selectOption({ label: "Clash" });
  await page.getByRole("button", { name: "Add identity" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Work and Clash both cover github.com/acme; narrow one.",
  );
});

test("reorders and removes the identities of a workspace", async ({
  page,
  backend,
}) => {
  await open(page, backend, "docs-site");
  const items = page
    .getByRole("list", { name: "Identities of docs-site, in order" })
    .getByRole("listitem");
  await expect(items.first()).toContainText("Personal");
  await page.getByRole("button", { name: "Move Personal down" }).click();
  await expect(items.first()).toContainText("Work");
  await page
    .getByRole("button", { name: "Remove Work from docs-site" })
    .click();
  await expect(items).toHaveCount(1);
});

test("a new workspace starts with the identity that covers its repository and its own repository listed", async ({
  page,
  backend,
  request,
}) => {
  await backend.control.reset("git-identities");
  const made = await request.post("/api/workspaces", {
    headers: auth(backend),
    data: { name: "fresh", repo_url: "https://github.com/acme/fresh.git" },
  });
  expect(made.status()).toBe(202);
  await backend.signIn(page);
  await page.goto("/workspaces/fresh/git");
  await expect(
    page.getByRole("list", { name: "Identities of fresh, in order" }),
  ).toContainText("Work");
  await expect(
    table(page, "fresh").getByRole("checkbox", {
      name: "Pull github.com/acme/fresh",
    }),
  ).toBeChecked();
  await expect(
    table(page, "fresh").getByRole("checkbox", {
      name: "Push github.com/acme/fresh",
    }),
  ).toBeChecked();
});

test("creating from the form for a repository nobody covers warns with the default identity, and the Git tab lists it", async ({
  page,
  backend,
}) => {
  await backend.control.reset("git-identities");
  await backend.signIn(page);
  await page.goto("/workspaces");
  await page.getByRole("button", { name: "New workspace" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New workspace" });
  await dialog
    .getByLabel("Git repository (HTTPS)")
    .fill("https://gitlab.example.com/team/tooling.git");
  await dialog.getByRole("button", { name: "Create workspace" }).click();
  await expect(dialog).toHaveCount(0);
  // Work is the default; it covers github.com/acme only, so the warning names it and the place.
  const toast = page.getByRole("region", { name: "Notifications" });
  await expect(toast).toContainText(
    "No identity covers gitlab.example.com/team, so this workspace got your default identity, Work.",
  );
  await expect(toast).toContainText(
    "requests to gitlab.example.com/team go out without a credential",
  );
  await toast.getByRole("button", { name: "Open Git tab" }).click();
  await expect(page).toHaveURL(/\/workspaces\/tooling\/git$/);
  await expect(
    page.getByRole("list", { name: "Identities of tooling, in order" }),
  ).toContainText("Work");
  for (const access of ["Pull", "Push"]) {
    await expect(
      table(page, "tooling").getByRole("checkbox", {
        name: `${access} gitlab.example.com/team/tooling`,
      }),
    ).toBeChecked();
  }
});

test("creating for a repository an identity covers says nothing and attaches that identity, not the default", async ({
  page,
  backend,
}) => {
  await backend.control.reset("git-identities");
  await backend.signIn(page);
  await page.goto("/workspaces");
  await page.getByRole("button", { name: "New workspace" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New workspace" });
  // Personal covers the rest of github.com; Work (the default) covers only acme.
  await dialog
    .getByLabel("Git repository (HTTPS)")
    .fill("https://github.com/someone-else/notes.git");
  await dialog.getByRole("button", { name: "Create workspace" }).click();
  await expect(dialog).toHaveCount(0);
  // The workspace is listed, and no warning came with it.
  await expect(page.getByRole("button", { name: "Start notes" })).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Notifications" }),
  ).not.toContainText("No identity covers");
  await expect(page.getByRole("button", { name: "Open Git tab" })).toHaveCount(
    0,
  );
  await page.goto("/workspaces/notes/git");
  const ids = page.getByRole("list", { name: "Identities of notes, in order" });
  await expect(ids).toContainText("Personal");
  await expect(ids).not.toContainText("Work");
});

test("the default for the two switches is inherited by new workspaces and overridden per workspace", async ({
  page,
  backend,
  request,
}) => {
  await backend.control.reset("git-identities");
  await backend.signIn(page);
  await page.goto("/identities");
  const pull = page.getByRole("switch", {
    name: "Only pull from listed repos",
  });
  const push = page.getByRole("switch", { name: "Only push to listed repos" });
  await expect(push).toBeChecked();
  await expect(pull).not.toBeChecked();
  await pull.click();
  await expect(pull).toBeChecked();
  await push.click();
  await expect(push).not.toBeChecked();

  // A workspace made now starts on the new defaults.
  const made = await request.post("/api/workspaces", {
    headers: auth(backend),
    data: {
      name: "inherits",
      repo_url: "https://github.com/acme/inherits.git",
    },
  });
  expect(made.status()).toBe(202);
  await page.goto("/workspaces/inherits/git");
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).toBeChecked();
  await expect(
    page.getByRole("switch", { name: "Only push to listed repos" }),
  ).not.toBeChecked();

  // It overrides one switch; a later change of the default moves only the other.
  await page
    .getByRole("switch", { name: "Only pull from listed repos" })
    .click();
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).not.toBeChecked();
  await page.goto("/identities");
  await page
    .getByRole("switch", { name: "Only pull from listed repos" })
    .click();
  await page.getByRole("switch", { name: "Only push to listed repos" }).click();
  await page.goto("/workspaces/inherits/git");
  await expect(
    page.getByRole("switch", { name: "Only pull from listed repos" }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("switch", { name: "Only push to listed repos" }),
  ).toBeChecked();
});

test("a refused push or fetch becomes a notice with one button that lists the repository", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await raise(
    backend,
    page,
    denied("push"),
    "web-shop: a push to github.com/acme/billing was refused.",
  );
  await notices(page)
    .getByRole("button", { name: "Allow push for billing" })
    .click();
  await expect(notices(page)).toContainText(
    "web-shop may now push github.com/acme/billing.",
  );
  await expect(
    table(page).getByRole("checkbox", { name: "Push github.com/acme/billing" }),
  ).toBeChecked();
  await expect(
    table(page).getByRole("checkbox", { name: "Pull github.com/acme/billing" }),
  ).not.toBeChecked();

  // A fetch refused for a repository that is listed without Pull turns Pull on and keeps Push.
  await raise(
    backend,
    page,
    denied("pull"),
    "web-shop: a fetch from github.com/acme/billing was refused.",
  );
  await notices(page)
    .getByRole("button", { name: "Allow pull for billing" })
    .click();
  await expect(
    table(page).getByRole("checkbox", { name: "Pull github.com/acme/billing" }),
  ).toBeChecked();
  await expect(
    table(page).getByRole("checkbox", { name: "Push github.com/acme/billing" }),
  ).toBeChecked();
});

test("keyboard only: toggle a box, flip a switch and add a repository", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await table(page)
    .getByRole("checkbox", { name: "Pull github.com/acme/web-shop" })
    .focus();
  await page.keyboard.press("Space");
  await expect(
    table(page).getByRole("checkbox", {
      name: "Pull github.com/acme/web-shop",
    }),
  ).not.toBeChecked();
  await page.getByRole("switch", { name: "Only push to listed repos" }).focus();
  await page.keyboard.press("Space");
  await expect(
    page.getByRole("switch", { name: "Only push to listed repos" }),
  ).not.toBeChecked();
  await page.getByLabel("Add a repository").focus();
  await page.keyboard.type("https://github.com/acme/keys");
  await page.keyboard.press("Enter");
  await expect(table(page)).toContainText("github.com/acme/keys");
});

for (const scheme of ["light", "dark"] as const) {
  test(`axe finds nothing in ${scheme}: the tab, its errors and a notice`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const csp = await watchCsp(page);
    await open(page, backend);
    await expect(table(page)).toBeVisible();
    expect(await axeViolations(page), "the tab").toEqual([]);
    await page.getByLabel("Add a repository").fill("nonsense");
    await page.getByRole("button", { name: "Add repository" }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await axeViolations(page), "with an error").toEqual([]);
    await raise(backend, page, denied("pull"), "was refused");
    expect(await axeViolations(page), "with a notice").toEqual([]);
    await open(page, backend, "data-tools");
    await expect(page.getByText(/No identity yet/)).toBeVisible();
    expect(await axeViolations(page), "no identities").toEqual([]);
    expect(await csp()).toEqual([]);
  });
}
