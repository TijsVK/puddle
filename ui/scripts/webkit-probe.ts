// SPDX-License-Identifier: GPL-3.0-or-later
// Exit 0 if Playwright's WebKit can start on this machine, 1 if not (check.sh uses it to decide
// whether the local ui-e2e gate can include WebKit).
import { webkit } from "@playwright/test";

try {
  const browser = await webkit.launch();
  await browser.close();
} catch {
  process.exitCode = 1;
}
