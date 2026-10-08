// SPDX-License-Identifier: GPL-3.0-or-later
// The first-run flow against the real API on the fixture backend: the whole way through, a
// blocking finding, skipping, the certificates step with company roots, and the system check
// run again from Settings. Each test has a backend of its own, reset before it.
import type { APIRequestContext, Page } from "@playwright/test";
import { type Backend, expect, test } from "./fixture";
import { axeViolations, watchCsp } from "./support";

const auth = (backend: Backend) => ({
  Authorization: `Bearer ${backend.token}`,
});

interface FirstRun {
  completed: boolean;
  completed_at: number | null;
}

async function firstRun(
  request: APIRequestContext,
  backend: Backend,
): Promise<FirstRun> {
  const r = await request.get("/api/first-run", { headers: auth(backend) });
  return (await r.json()) as FirstRun;
}

/** An install nobody has been through yet, signed in as the shell would. */
async function freshInstall(page: Page, backend: Backend) {
  await backend.control.reset("first-run");
  await backend.signIn(page);
}

const heading = (page: Page, name: string) =>
  page.getByRole("heading", { level: 1, name });

const STEPS = [
  ["/welcome", "Welcome to puddle"],
  ["/welcome/check", "System check"],
  ["/welcome/certificates", "Certificates"],
  ["/welcome/connect", "How do you want to connect?"],
  ["/welcome/look", "Look"],
  ["/welcome/workspace", "Your first workspace"],
] as const;

test("a fresh install is led through every step and then opens on the workspaces", async ({
  page,
  backend,
  request,
}) => {
  const csp = await watchCsp(page);
  await freshInstall(page, backend);

  await page.goto("/");
  await expect(page).toHaveURL(/\/welcome$/);
  await expect(heading(page, "Welcome to puddle")).toBeFocused();
  await expect(page).toHaveTitle("Welcome - puddle");
  // The app's own navigation stays out of the flow.
  await expect(page.getByRole("navigation", { name: "Main" })).toHaveCount(0);
  await expect(
    page.getByRole("listitem").filter({ hasText: "Welcome" }),
  ).toHaveAttribute("aria-current", "step");
  await page.getByRole("link", { name: "Get started" }).click();

  // System check: a healthy machine goes on.
  await expect(heading(page, "System check")).toBeVisible();
  await expect(page.getByText("No problems found.")).toBeVisible();
  await expect(
    page.getByRole("list", { name: "Checks" }).getByRole("listitem"),
  ).toHaveCount(5);
  await page.getByRole("link", { name: "Continue" }).click();

  // Certificates: nothing about a development certificate is known yet, and this machine has no
  // company roots.
  await expect(heading(page, "Certificates")).toBeVisible();
  await expect(
    page.getByText("Development certificate: not checked yet"),
  ).toBeVisible();
  await expect(
    page.getByText("Company certificates: not read yet"),
  ).toBeVisible();
  await page.getByRole("link", { name: "Continue" }).click();

  // Connect: code-server is preselected, direct SSH is off until the trust text is accepted.
  await expect(heading(page, "How do you want to connect?")).toBeVisible();
  await expect(
    page.getByRole("radio", { name: /code-server \(bundled\)/ }),
  ).toBeChecked();
  const directSsh = page.getByRole("checkbox", {
    name: /Allow direct SSH for new workspaces/,
  });
  await expect(directSsh).not.toBeChecked();
  await directSsh.click();
  const trust = page.getByRole("alertdialog", {
    name: "Allow direct SSH for new workspaces?",
  });
  await expect(trust).toBeVisible();
  await expect(directSsh).not.toBeChecked();
  const saved = page.waitForResponse(
    (r) => r.request().method() === "PUT" && r.url().endsWith("/api/settings"),
  );
  await trust.getByRole("button", { name: "Allow for new workspaces" }).click();
  await saved;
  await expect(directSsh).toBeChecked();
  const settings = (await (
    await request.get("/api/settings", { headers: auth(backend) })
  ).json()) as { effective: { direct_ssh: { value: boolean } } };
  expect(settings.effective.direct_ssh.value).toBe(true);
  await page.getByRole("link", { name: "Continue" }).click();

  // Look: a dark theme and compact spacing apply at once.
  await expect(heading(page, "Look")).toBeVisible();
  await page.getByRole("radio", { name: /^Dark/ }).check();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("radio", { name: /^Compact/ }).check();
  await expect(page.locator("html")).toHaveAttribute("data-density", "compact");
  await expect(page.getByText("Density saved.")).toBeVisible();
  await page.getByRole("link", { name: "Continue" }).click();

  // First workspace: the usual form, then the workspace list with the workspace on it.
  await expect(heading(page, "Your first workspace")).toBeVisible();
  await page.getByRole("button", { name: "Create a workspace" }).click();
  const form = page.getByRole("dialog", { name: "New workspace" });
  await form
    .getByLabel(/Git repository/)
    .fill("https://github.com/example/shop-api.git");
  await expect(form.getByLabel("Name")).toHaveValue("shop-api");
  await form.getByRole("button", { name: "Create workspace" }).click();
  await expect(page).toHaveURL(/\/workspaces$/);
  await expect(page.getByText("shop-api").first()).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();

  // It was shown once: the start page now leads to the workspaces, and the choices stuck.
  expect((await firstRun(request, backend)).completed).toBe(true);
  await page.goto("/");
  await expect(page).toHaveURL(/\/workspaces$/);
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  expect(await csp()).toEqual([]);
});

test("a blocking finding stops the flow until it is fixed, and the report can be copied", async ({
  page,
  backend,
  request,
}) => {
  await freshInstall(page, backend);
  await page.addInitScript(() => {
    const w = window as unknown as { __copied: string[] };
    w.__copied = [];
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (text: string) => void w.__copied.push(text) },
    });
  });
  const healthy = (await (
    await request.get("/api/doctor", { headers: auth(backend) })
  ).json()) as { ok: boolean; checks: Record<string, unknown>[] };
  const broken = structuredClone(healthy);
  broken.ok = false;
  broken.checks[1] = {
    ...broken.checks[1],
    status: "fail",
    summary: "/dev/kvm doesn't exist",
    finding: "kvm_missing",
    fix: "Turn on virtualization in your UEFI setup.",
    detail: "No such file or directory (os error 2)",
  };
  await backend.control.step({ do: "doctor", ...broken });

  await page.goto("/welcome/check");
  await expect(
    page.getByText("1 problem to fix before puddle can run workspaces."),
  ).toBeVisible();
  await expect(
    page.getByText("Turn on virtualization in your UEFI setup."),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Continue" })).toHaveCount(0);

  await page.getByRole("button", { name: "Copy report" }).click();
  await expect(page.getByText("Report copied.")).toBeVisible();
  const copied = await page.evaluate(
    () => (window as unknown as { __copied: string[] }).__copied,
  );
  const report = JSON.parse(copied[0] ?? "{}") as {
    schema_version: number;
    checks: { finding: string | null }[];
  };
  expect(report.schema_version).toBe(1);
  expect(report.checks[1]?.finding).toBe("kvm_missing");

  // Fixed: check again and go on.
  await backend.control.step({ do: "doctor", ...healthy });
  await page.getByRole("button", { name: "Check again" }).click();
  await expect(page.getByText("No problems found.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Continue" })).toBeVisible();
  await expect(page.getByText("Report copied.")).toHaveCount(0);

  // Broken again: leaving does not count as having been through the flow.
  await backend.control.step({ do: "doctor", ...broken });
  await page.getByRole("button", { name: "Check again" }).click();
  await page.getByRole("link", { name: "Leave setup for now" }).click();
  await expect(page).toHaveURL(/\/workspaces$/);
  expect((await firstRun(request, backend)).completed).toBe(false);
  await page.goto("/");
  await expect(page).toHaveURL(/\/welcome$/);
});

test("skipping the setup ends it for good", async ({
  page,
  backend,
  request,
}) => {
  await freshInstall(page, backend);
  await page.goto("/");
  await page.getByRole("button", { name: "Skip setup" }).click();
  await expect(page).toHaveURL(/\/workspaces$/);
  expect((await firstRun(request, backend)).completed).toBe(true);
  await page.goto("/");
  await expect(page).toHaveURL(/\/workspaces$/);
});

test("the first workspace can be skipped", async ({
  page,
  backend,
  request,
}) => {
  await freshInstall(page, backend);
  await page.goto("/welcome/workspace");
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page).toHaveURL(/\/workspaces$/);
  expect((await firstRun(request, backend)).completed).toBe(true);
  await expect(page.getByText("shop-api")).toHaveCount(0);
});

test("the certificates step counts the company roots puddle will add", async ({
  page,
  backend,
  request,
}) => {
  await backend.control.reset("corporate-network");
  await request.put("/api/first-run", {
    headers: auth(backend),
    data: { completed: false },
  });
  await backend.signIn(page);
  await page.goto("/welcome/certificates");
  await expect(
    page.getByText("2 company root certificates found"),
  ).toBeVisible();
  await expect(page.getByText(/Added to every workspace/)).toBeVisible();
});

test("Settings runs the system check again on its own page and leads back", async ({
  page,
  backend,
}) => {
  await backend.signIn(page);
  await page.goto("/settings");
  await page.getByRole("link", { name: "Run the system check again" }).click();
  await expect(page).toHaveURL(/\/welcome\/check\?from=settings$/);
  await expect(page.getByText("No problems found.")).toBeVisible();
  await expect(page.getByRole("list", { name: "Setup steps" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Continue" })).toHaveCount(0);
  await page.getByRole("link", { name: "Back to Settings" }).click();
  await expect(page).toHaveURL(/\/settings$/);
});

for (const scheme of ["light", "dark"] as const) {
  test(`every step passes the accessibility scan in the ${scheme} theme`, async ({
    page,
    backend,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await freshInstall(page, backend);
    for (const [path, title] of STEPS) {
      await page.goto(path);
      await expect(heading(page, title)).toBeVisible();
      if (path === "/welcome/check") {
        await expect(page.getByText("No problems found.")).toBeVisible();
      }
      if (path === "/welcome/connect") {
        await expect(
          page.getByRole("radio", { name: /code-server/ }),
        ).toBeVisible();
      }
      expect(await axeViolations(page), path).toEqual([]);
    }
  });
}

test("the blocked system check and the form dialog pass the accessibility scan", async ({
  page,
  backend,
  request,
}) => {
  await freshInstall(page, backend);
  const healthy = (await (
    await request.get("/api/doctor", { headers: auth(backend) })
  ).json()) as { ok: boolean; checks: Record<string, unknown>[] };
  healthy.ok = false;
  healthy.checks[1] = {
    ...healthy.checks[1],
    status: "fail",
    summary: "/dev/kvm doesn't exist",
    finding: "kvm_missing",
    fix: "Turn on virtualization in your UEFI setup.",
    detail: "No such file or directory (os error 2)",
  };
  await backend.control.step({ do: "doctor", ...healthy });
  await page.goto("/welcome/check");
  await expect(page.getByText(/1 problem to fix/)).toBeVisible();
  await page.getByText("Technical details").click();
  expect(await axeViolations(page)).toEqual([]);

  await page.goto("/welcome/workspace");
  await page.getByRole("button", { name: "Create a workspace" }).click();
  await expect(
    page.getByRole("dialog", { name: "New workspace" }),
  ).toBeVisible();
  expect(await axeViolations(page)).toEqual([]);
});
