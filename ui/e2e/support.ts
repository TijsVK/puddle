// SPDX-License-Identifier: GPL-3.0-or-later
import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";

function connection(): { url: string; token: string } {
  const file = process.env["PUDDLE_E2E_CONNECTION"];
  if (!file)
    throw new Error(
      "PUDDLE_E2E_CONNECTION is not set (see playwright.config.ts)",
    );
  return JSON.parse(readFileSync(file, "utf8")) as {
    url: string;
    token: string;
  };
}

/** What the desktop shell's init script does: hand the page the token before the app starts. */
export async function signIn(page: Page): Promise<void> {
  const { token } = connection();
  await page.addInitScript((t) => {
    (window as unknown as { __PUDDLE__: { token: string } }).__PUDDLE__ = {
      token: t,
    };
  }, token);
}

/** Records Content-Security-Policy violations (there must be none). */
export async function watchCsp(page: Page): Promise<() => Promise<string[]>> {
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (e) => {
      seen.push(`${e.violatedDirective}: ${e.blockedURI}`);
    });
  });
  return () =>
    page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
}

/** axe with the tags the project's bar names (WCAG 2.0 to 2.2, A and AA). */
export async function axeViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  return results.violations.map(
    (v) =>
      `${v.id}: ${v.nodes
        .map(
          (n) =>
            `${n.target.join(" ")} (${(n.any[0]?.message ?? n.failureSummary ?? "").replace(/\s+/g, " ")})`,
        )
        .join(", ")}`,
  );
}

export const test = base;
export { expect };
