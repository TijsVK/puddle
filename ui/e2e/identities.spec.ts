// SPDX-License-Identifier: GPL-3.0-or-later
// The Identities screens against the real API on the fixture backend, scenario `git-identities`:
// two identities (Work: gh account tijs-work for acme and acme-labs plus a Git credential for
// dev.azure.com/contoso that is signed out; Personal: gh account tijs-demo for the rest of
// github.com), three workspaces, and what the fake credential host answers. Each test has a
// backend of its own, reset before it. Waits are on conditions, never on time.
import type { Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

async function open(page: Page, backend: Backend, path = "/identities") {
  await backend.control.reset("git-identities");
  await backend.signIn(page);
  await page.goto(path);
}

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

const SIGN_IN_NEEDED = {
  type: "credential_sign_in_needed",
  host: "dev.azure.com",
  source: "Git credential for https://dev.azure.com/contoso",
};

const row = (page: Page, label: string) =>
  page
    .locator("[data-identity-id]")
    .filter({ has: page.getByRole("heading", { name: label }) });

test("lists the identities with author, credentials, default and use; the sidebar marks the section", async ({
  page,
  backend,
}) => {
  const csp = await watchCsp(page);
  await open(page, backend);
  await expect(
    page.getByRole("heading", { level: 1, name: "Identities" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Identities", exact: true }).first(),
  ).toHaveAttribute("aria-current", "page");
  const work = row(page, "Work");
  await expect(work).toContainText("Default");
  await expect(work).toContainText("Tijs Work <tijs@acme.example>");
  await expect(work).toContainText(
    "gh · tijs-work · github.com: acme, acme-labs",
  );
  await expect(work).toContainText(
    "Git Credential Manager · dev.azure.com/contoso",
  );
  await expect(work).toContainText("Used by 2 workspaces");
  await expect(work).toContainText("Not tested");
  const personal = row(page, "Personal");
  await expect(personal).not.toContainText("Default");
  await expect(personal).toContainText("the rest of github.com");
  await expect(page).toHaveTitle("Identities - puddle");
  expect(await csp()).toEqual([]);
});

test("Settings points to the Identities section", async ({ page, backend }) => {
  await open(page, backend, "/settings");
  await page.getByRole("link", { name: "Manage identities" }).click();
  await expect(page).toHaveURL(/\/identities$/);
});

test("Test all reads each credential and shows who needs to sign in, never a value", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await page.getByRole("button", { name: "Test all" }).click();
  await expect(row(page, "Personal")).toContainText("OK");
  await expect(row(page, "Work")).toContainText("Sign in needed");
  expect(await page.content()).not.toMatch(/ghp_|token=/);
});

test("signing in happens on a click: the dialog shows the code and the credential reads afterwards", async ({
  page,
  backend,
}) => {
  await open(page, backend, "/identities/1");
  await expect(
    page.getByRole("heading", { level: 1, name: "Work" }),
  ).toBeVisible();
  const azure = page.locator(
    '[data-credential^="Git credential for https://dev.azure.com"]',
  );
  await azure.getByRole("button", { name: /^Test / }).click();
  await expect(azure).toContainText("Sign in needed");
  await expect(azure).toContainText("not signed in");
  // Nothing signed in by itself.
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await azure.getByRole("button", { name: /^Sign in to / }).click();
  const dialog = page.getByRole("dialog", { name: "Sign in" });
  await expect(dialog.getByTestId("sign-in-code")).toHaveText("ABCD-1234");
  await expect(
    dialog.getByRole("link", { name: "https://github.com/login/device" }),
  ).toHaveAttribute("rel", /noopener/);
  // The fake finishes the sign-in at once; the dialog sees it on its next check.
  await expect(dialog).toContainText("Signed in.", { timeout: 15_000 });
  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(azure).toContainText("OK");
});

test("adds an identity from an account found on this computer", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await page.getByRole("button", { name: "Add identity" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add identity" });
  await dialog.getByLabel("Identity name").fill("Side project");
  await dialog.getByLabel("Author name").fill("Tijs S");
  await dialog.getByLabel("Author email").fill("tijs@side.example");
  await dialog.getByRole("button", { name: "Add a credential" }).click();
  await dialog.getByLabel(/tijs-demo on github.com \(GitHub CLI\)/).check();
  await expect(dialog.getByLabel("The rest of github.com")).toBeChecked();
  await dialog
    .getByLabel(/Owners or organisations it covers on github.com/)
    .fill("side-org");
  await dialog.getByRole("button", { name: "Add credential" }).click();
  await expect(dialog).toContainText(
    "gh · tijs-demo · github.com: side-org and the rest of github.com",
  );
  await dialog.getByRole("button", { name: "Add identity" }).click();
  await expect(dialog).toBeHidden();
  const made = row(page, "Side project");
  await expect(made).toContainText("Tijs S <tijs@side.example>");
  await expect(made).not.toContainText("Default");
  await expect(page.getByText("Added Side project.")).toBeVisible();
});

test("a pasted token is write-only: it is kept by id and never appears in any answer", async ({
  page,
  backend,
  request,
}) => {
  const secret = "ghp_e2eSecretValue0123456789";
  await open(page, backend);
  await page.getByRole("button", { name: "Add identity" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add identity" });
  await dialog.getByLabel("Identity name").fill("Token user");
  await dialog.getByLabel("Author name").fill("T");
  await dialog.getByLabel("Author email").fill("t@example.com");
  await dialog.getByRole("button", { name: "Add a credential" }).click();
  await dialog.getByLabel("Paste a token").check();
  await expect(dialog.getByLabel("Token", { exact: true })).toHaveAttribute(
    "type",
    "password",
  );
  await dialog.getByLabel("Git host").fill("dev.azure.com");
  await dialog.getByLabel("Azure DevOps organisation").fill("fabrikam");
  await dialog.getByLabel("Token", { exact: true }).fill(secret);
  await dialog.getByLabel(/Owners or organisations/).fill("fabrikam");
  await dialog.getByLabel(/The rest of dev.azure.com/).uncheck();
  await dialog.getByRole("button", { name: "Add credential" }).click();
  await expect(dialog).toContainText(
    "Pasted token · fabrikam · dev.azure.com: fabrikam",
  );
  await dialog.getByRole("button", { name: "Add identity" }).click();
  await expect(dialog).toBeHidden();
  await expect(row(page, "Token user")).toContainText("Pasted token");
  const answer = await request.get("/api/identities", {
    headers: { Authorization: `Bearer ${backend.token}` },
  });
  const text = await answer.text();
  expect(text).toContain('"kind":"stored"');
  expect(text).not.toContain(secret);
  expect(await page.content()).not.toContain(secret);
});

test("checks a form before it asks and keeps focus on the first problem", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await page.getByRole("button", { name: "Add identity" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add identity" });
  await dialog.getByRole("button", { name: "Add identity" }).click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Give the identity a name",
  );
  await expect(dialog.getByLabel("Identity name")).toBeFocused();
  await dialog.getByLabel("Identity name").fill("work");
  await dialog.getByRole("button", { name: "Add identity" }).click();
  await expect(dialog.getByRole("alert")).toContainText("already called work");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("sets the default, moves an identity and deletes one, naming the workspaces that lose it", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await row(page, "Personal")
    .getByRole("button", { name: "Set Personal as default" })
    .click();
  await expect(row(page, "Personal")).toContainText("Default");
  await expect(row(page, "Work")).not.toContainText("Default");
  await row(page, "Personal")
    .getByRole("button", { name: "Move Personal up" })
    .click();
  await expect(page.locator("[data-identity-id]").first()).toContainText(
    "Personal",
  );

  await row(page, "Work").getByRole("button", { name: "Delete Work" }).click();
  const confirm = page.getByRole("alertdialog");
  await expect(confirm).toContainText(
    /(docs-site, web-shop|web-shop, docs-site) will lose it/,
  );
  await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
  await confirm.getByRole("button", { name: "Delete Work" }).click();
  await expect(
    page.getByText(
      /^Deleted Work; it was taken off (docs-site, web-shop|web-shop, docs-site)\.$/,
    ),
  ).toBeVisible();
  await expect(row(page, "Work")).toHaveCount(0);
});

test("the sign-in notice leads to the credential's page and goes when the credential reads", async ({
  page,
  backend,
}) => {
  await open(page, backend, "/workspaces");
  const notice = notices(page);
  await raise(backend, page, SIGN_IN_NEEDED, "Sign-in needed");
  await expect(notice).toContainText(
    "Git credential for https://dev.azure.com/contoso",
  );
  await notice.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/identities\/1$/);
  const azure = page.locator(
    '[data-credential^="Git credential for https://dev.azure.com"]',
  );
  await expect(azure).toContainText("Sign in needed");
  // The user signs in (the fake host makes the credential readable), and a check says so.
  await backend.control.step({
    do: "credential_readable",
    readable: true,
    source: {
      kind: "git_credential",
      host: "dev.azure.com",
      path: "contoso",
      username: null,
    },
  });
  await azure.getByRole("button", { name: /^Test / }).click();
  await expect(azure).toContainText("OK");
  await expect(notice).not.toContainText("Sign-in needed");
});

test("keyboard only: add, move and delete without a pointer", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  await page.getByRole("button", { name: "Add identity" }).first().focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Add identity" });
  await expect(dialog.getByLabel("Identity name")).toBeFocused();
  await page.keyboard.type("Keys");
  await page.keyboard.press("Tab");
  await page.keyboard.type("K");
  await page.keyboard.press("Tab");
  await page.keyboard.type("k@example.com");
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden();
  await expect(row(page, "Keys")).toBeVisible();

  await row(page, "Keys").getByRole("button", { name: "Move Keys up" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("[data-identity-id]").nth(1)).toContainText("Keys");
  await expect(
    page.getByRole("button", { name: "Move Keys up" }),
  ).toBeFocused();

  await row(page, "Keys").getByRole("button", { name: "Delete Keys" }).focus();
  await page.keyboard.press("Enter");
  const confirm = page.getByRole("alertdialog");
  await expect(confirm.getByRole("button", { name: "Cancel" })).toBeFocused();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await expect(row(page, "Keys")).toHaveCount(0);
  await expect(
    page.getByRole("heading", { level: 1, name: "Identities" }),
  ).toBeFocused();
});

for (const scheme of ["light", "dark"] as const) {
  test(`axe finds nothing in ${scheme}: the list, an identity, the dialogs and a notice`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const csp = await watchCsp(page);
    await open(page, backend);
    await expect(row(page, "Work")).toBeVisible();
    expect(await axeViolations(page), "list").toEqual([]);

    await page.getByRole("button", { name: "Test all" }).click();
    await expect(row(page, "Work")).toContainText("Sign in needed");
    expect(await axeViolations(page), "list with statuses").toEqual([]);

    await page.getByRole("button", { name: "Add identity" }).first().click();
    const dialog = page.getByRole("dialog", { name: "Add identity" });
    await dialog.getByRole("button", { name: "Add a credential" }).click();
    await expect(dialog.getByLabel(/tijs-demo/)).toBeVisible();
    expect(await axeViolations(page), "add identity with the editor").toEqual(
      [],
    );
    await dialog.getByLabel("Paste a token").check();
    await dialog.getByRole("button", { name: "Add credential" }).click();
    await expect(dialog.getByRole("alert")).toBeVisible();
    expect(await axeViolations(page), "add identity with an error").toEqual([]);
    await page.keyboard.press("Escape");

    await page.goto("/identities/1");
    await expect(
      page.getByRole("heading", { level: 1, name: "Work" }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: /^Test / })
      .first()
      .click();
    expect(await axeViolations(page), "identity").toEqual([]);
    const azure = page.locator(
      '[data-credential^="Git credential for https://dev.azure.com"]',
    );
    await azure.getByRole("button", { name: /^Test / }).click();
    await azure.getByRole("button", { name: /^Sign in to / }).click();
    await expect(page.getByTestId("sign-in-code")).toBeVisible();
    expect(await axeViolations(page), "sign-in dialog").toEqual([]);
    await page.keyboard.press("Escape");

    await raise(backend, page, SIGN_IN_NEEDED, "Sign-in needed");
    expect(await axeViolations(page), "with the sign-in notice").toEqual([]);
    expect(await csp()).toEqual([]);
  });
}
