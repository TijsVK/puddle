// SPDX-License-Identifier: GPL-3.0-or-later
// End-to-end tests against the UI fixture backend (T-171): the real puddle-api serving the built
// app on 127.0.0.1 (the same origin the desktop shell loads), on fake services with seeded data.
// This config starts one shared, read-only server (scenario `default`: one pending request).
// A test that changes state uses e2e/fixture.ts instead, which gives each worker its own.
//   Linux: Chromium and WebKit (WebKit stands in for WebKitGTK and, later, WKWebView).
//   Windows: the installed Edge (WebView2's engine), so no browser download.
import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

const PORT = 4173;
const CONNECTION_FILE = resolve(
  import.meta.dirname,
  ".svelte-kit",
  "e2e",
  "connection.json",
);
process.env["PUDDLE_E2E_CONNECTION"] = CONNECTION_FILE;

// `check.sh` passes its cargo wrapper (mbx) here; plain cargo otherwise.
const cargo = process.env["PUDDLE_CARGO"] ?? "cargo";
const windows = process.platform === "win32";
// Narrow the browsers, e.g. PUDDLE_E2E_PROJECTS=chromium (check.sh does this where WebKit can't start).
const only = (process.env["PUDDLE_E2E_PROJECTS"] ?? "")
  .split(",")
  .filter(Boolean);

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: process.env["CI"]
    ? [["list"], ["html", { open: "never" }]]
    : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
  },
  projects: (windows
    ? [
        {
          name: "msedge",
          use: { ...devices["Desktop Edge"], channel: "msedge" },
        },
      ]
    : [
        { name: "chromium", use: { ...devices["Desktop Chrome"] } },
        { name: "webkit", use: { ...devices["Desktop Safari"] } },
      ]
  ).filter((project) => only.length === 0 || only.includes(project.name)),
  webServer: {
    command: `${cargo} run --quiet --locked -p puddle-e2e --features embedded-ui --bin puddle-ui-fixture -- ${PORT} "${CONNECTION_FILE}"`,
    cwd: resolve(import.meta.dirname, ".."),
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 600_000,
    stdout: "pipe",
  },
});
