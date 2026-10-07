// SPDX-License-Identifier: GPL-3.0-or-later
// App-level notices driven by events, on the fixture backend (scenario `lived-in`): they show on
// any screen, never take focus, and can be dismissed. Waits are on conditions, never on time.
import type { Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations } from "./support";

async function open(page: Page, backend: Backend, path = "/inbox") {
  await backend.control.reset("lived-in");
  await backend.signIn(page);
  await page.goto(path);
  await expect(
    page.getByRole("link", { name: "Skip to content" }),
  ).toBeAttached();
  // The stream is up once a harmless event goes through: wait for the shell's live state.
  await expect(page.getByRole("region", { name: "Notices" })).toBeAttached();
}

const notices = (page: Page) => page.getByRole("region", { name: "Notices" });

/** Emits until the page shows the notice: the stream may connect after the page loaded. */
async function emitUntilShown(
  backend: Backend,
  page: Page,
  event: Record<string, unknown>,
  text: RegExp,
) {
  await expect(async () => {
    await backend.control.emit(event);
    await expect(notices(page).getByText(text).first()).toBeVisible({
      timeout: 500,
    });
  }).toPass();
}

test("an out-of-memory kill shows a notice on any screen, without taking focus", async ({
  page,
  backend,
}) => {
  await open(page, backend, "/rules");
  await emitUntilShown(
    backend,
    page,
    { type: "oom_kill", sandbox: "web-shop", pid: 4242, process: "node" },
    /web-shop ran out of memory/,
  );
  await expect(notices(page).getByText(/node \(process 4242\)/)).toBeVisible();
  expect(await page.evaluate(() => document.activeElement?.tagName)).toBe(
    "BODY",
  );
  expect(await axeViolations(page)).toEqual([]);
  await notices(page).getByRole("link", { name: "Workspace settings" }).click();
  await expect(page).toHaveURL(/\/workspaces\/web-shop\/settings$/);
});

test("a workspace that stops on its own is reported, and one that is stopped on purpose is not", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  // The stream is up once a first notice has come through; events before that would be lost.
  await emitUntilShown(
    backend,
    page,
    { type: "oom_kill", sandbox: "data-tools", pid: 1, process: "ld" },
    /data-tools ran out of memory/,
  );
  // Asked for: stopping, then stopped.
  await backend.control.emit({
    type: "workspace_progress",
    sandbox: "web-shop",
    step: "stopping",
    detail: null,
  });
  await backend.control.emit({
    type: "status_changed",
    sandbox: "web-shop",
    status: "stopped",
  });
  await backend.control.emit({
    type: "status_changed",
    sandbox: "web-shop",
    status: "running",
  });
  // Events arrive in order: once this one is shown, the three above were handled.
  await backend.control.emit({
    type: "oom_kill",
    sandbox: "docs-site",
    pid: 2,
    process: "ld",
  });
  await expect(
    notices(page).getByText(/docs-site ran out of memory/),
  ).toBeVisible();
  await expect(
    notices(page).getByText(/stopped without being asked/),
  ).toHaveCount(0);
  // Not asked for: the scenario's own script.
  await expect(async () => {
    await backend.control.script("workspace-stopped");
    await expect(
      notices(page).getByText("web-shop stopped without being asked to."),
    ).toBeVisible({ timeout: 500 });
    await backend.control.emit({
      type: "status_changed",
      sandbox: "web-shop",
      status: "running",
    });
  }).toPass();
  await backend.control.emit({
    type: "status_changed",
    sandbox: "web-shop",
    status: "crashed",
  });
  await expect(notices(page).getByText("web-shop crashed.")).toBeVisible();
  // Running again withdraws the notice.
  await backend.control.emit({
    type: "status_changed",
    sandbox: "web-shop",
    status: "running",
  });
  await expect(notices(page).getByText("web-shop crashed.")).toHaveCount(0);
});

test("notices can be dismissed by keyboard, and a repeat replaces the old notice", async ({
  page,
  backend,
}) => {
  await open(page, backend);
  const oom = {
    type: "oom_kill",
    sandbox: "docs-site",
    pid: 7,
    process: "cc1plus",
  };
  await emitUntilShown(backend, page, oom, /docs-site ran out of memory/);
  await backend.control.emit(oom);
  await backend.control.emit({ ...oom, sandbox: "data-tools" });
  await expect(
    notices(page).getByText(/data-tools ran out of memory/),
  ).toBeVisible();
  await expect(
    notices(page).getByText(/docs-site ran out of memory/),
  ).toHaveCount(1);

  const dismiss = notices(page).getByRole("button", {
    name: /^Dismiss notice: docs-site/,
  });
  await dismiss.focus();
  await page.keyboard.press("Enter");
  await expect(
    notices(page).getByText(/docs-site ran out of memory/),
  ).toHaveCount(0);
  await expect(
    notices(page).getByRole("button", { name: /^Dismiss notice: data-tools/ }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(notices(page).getByRole("button")).toHaveCount(0);
  await expect(page.locator("#main")).toBeFocused();
});

for (const scheme of ["light", "dark"] as const) {
  test(`axe finds nothing with several notices in ${scheme}`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await open(page, backend);
    for (const sandbox of ["web-shop", "docs-site", "data-tools"]) {
      await backend.control.emit({
        type: "oom_kill",
        sandbox,
        pid: 1,
        process: "node",
      });
    }
    await backend.control.emit({
      type: "status_changed",
      sandbox: "web-shop",
      status: "crashed",
    });
    await expect(notices(page).getByText("web-shop crashed.")).toBeVisible();
    await notices(page)
      .getByRole("button", { name: /^Show all/ })
      .click();
    expect(await axeViolations(page)).toEqual([]);
  });
}
