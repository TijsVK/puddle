// SPDX-License-Identifier: GPL-3.0-or-later
// Smoke test of the real shell: starts `puddle-app` with WebView2's remote-debugging port
// open and checks, over the Chrome DevTools Protocol, that the main window shows the SPA served
// by the in-process backend, that the page holds the API token, and that it can call no Tauri
// command. WebView2 (Windows) only: WebKitGTK has no DevTools Protocol (Linux needs WebKitWebDriver,
// see the brief's follow-ups). Plain Node 24, no npm packages.
//
// Environment: PUDDLE_APP_EXE (the built shell), CDP_PORT (default 9333).
// tauri-driver + msedgedriver was tried first and failed with "DevToolsActivePort file doesn't
// exist" on windows-2025 ; driving WebView2 over the DevTools Protocol works without either driver.
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const exe = process.env.PUDDLE_APP_EXE;
if (!exe) throw new Error("set PUDDLE_APP_EXE to the built puddle-app");
const port = Number(process.env.CDP_PORT ?? 9333);

const app = spawn(exe, [], {
  stdio: ["ignore", "inherit", "inherit"],
  env: {
    ...process.env,
    PUDDLE_APP_DEBUG_PORT: String(port),
  },
});
let appExited = false;
app.on("exit", (code) => {
  appExited = true;
  console.log(`puddle-app exited (${code})`);
});

const failures = [];
function check(name, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures.push(name);
}

let lastSeen = "nothing yet";

function describeWebView() {
  const ps = spawnSync(
    "powershell",
    ["-NoProfile", "-Command", "Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | Select-Object -First 3 | ForEach-Object { $_.CommandLine }"],
    { encoding: "utf8" },
  );
  return (ps.stdout ?? "").slice(0, 1500);
}

async function pageTarget() {
  for (let i = 0; i < 300; i++) {
    if (appExited) throw new Error("puddle-app exited before its window was up");
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      lastSeen = JSON.stringify(list.map((t) => ({ type: t.type, url: t.url })));
      const page = list.find((t) => t.type === "page" && /^http:\/\/127\.0\.0\.1:\d+\//.test(t.url));
      if (page) return page;
    } catch (err) {
      lastSeen = `fetch failed: ${err}`;
    }
    await sleep(400);
  }
  throw new Error(`no page on 127.0.0.1 showed up in WebView2's targets; last seen: ${lastSeen}\nwebview2 processes:\n${describeWebView()}`);
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let next = 1;
    const pending = new Map();
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      const p = pending.get(m.id);
      if (p) {
        pending.delete(m.id);
        m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result);
      }
    };
    ws.onerror = () => reject(new Error("DevTools websocket failed"));
    ws.onopen = () =>
      resolve({
        evaluate: async (expression) => {
          const id = next++;
          const done = new Promise((res, rej) => pending.set(id, { resolve: res, reject: rej }));
          ws.send(JSON.stringify({ id, method: "Runtime.evaluate", params: { expression, returnByValue: true, awaitPromise: true } }));
          const r = await done;
          if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
          return r.result.value;
        },
        close: () => ws.close(),
      });
  });
}

let page;
try {
  const target = await pageTarget();
  page = await connect(target.webSocketDebuggerUrl);
  const run = (body) => page.evaluate(`(async () => { ${body} })()`);

  // A fresh install opens the first-run flow, which has the whole window (no sidebar). Go through it
  // the way a user does: press "Skip setup".
  let welcome;
  for (let i = 0; i < 100; i++) {
    welcome = await run(`return { origin: location.origin, path: location.pathname, title: document.title,
      heading: document.querySelector('h1')?.textContent ?? "",
      skip: [...document.querySelectorAll('button')].some((b) => b.textContent.trim() === "Skip setup"),
      links: document.querySelectorAll('nav[aria-label="Main"] a').length };`).catch(() => undefined);
    if (welcome?.skip) break;
    await sleep(400);
  }
  check(
    "a fresh install opens the first-run welcome screen, without the sidebar",
    welcome?.path === "/welcome" && welcome.title === "Welcome - puddle" && welcome.heading === "Welcome to puddle" && welcome.skip && welcome.links === 0,
    JSON.stringify(welcome),
  );
  await run(`[...document.querySelectorAll('button')].find((b) => b.textContent.trim() === "Skip setup")?.click(); return true;`);

  // The sections the sidebar has today (ui/src/lib/nav.ts). A new section must not turn this test
  // red; losing one must. The Playwright shell tests count the sections, on the same engine.
  const KNOWN_SECTIONS = ["/workspaces", "/inbox", "/rules", "/activity", "/identities", "/settings"];
  const hasKnownSections = (hrefs) => KNOWN_SECTIONS.every((href) => hrefs?.includes(href));
  let shell;
  for (let i = 0; i < 100; i++) {
    shell = await run(`return { origin: location.origin, title: document.title,
      hrefs: [...document.querySelectorAll('nav[aria-label="Main"] a')].map((a) => a.getAttribute("href")) };`).catch(() => undefined);
    if (hasKnownSections(shell?.hrefs)) break;
    await sleep(400);
  }
  check("skipping the setup shows the app from the in-process API, with its sections", hasKnownSections(shell?.hrefs), JSON.stringify(shell));
  const recorded = await run(`const r = await fetch("/api/first-run", { headers: { Authorization: "Bearer " + window.__PUDDLE__.token } });
    return { status: r.status, body: await r.json() };`).catch((err) => ({ error: String(err) }));
  check("the API records that the setup is done", recorded?.status === 200 && recorded.body?.completed === true, JSON.stringify(recorded));
  check("served from 127.0.0.1", /^http:\/\/127\.0\.0\.1:\d+$/.test(shell?.origin ?? ""), shell?.origin);
  check("title carries the app name", /puddle/.test(shell?.title ?? ""), shell?.title);

  const token = await run(`const t = window.__PUDDLE__ && window.__PUDDLE__.token;
    return { type: typeof t, length: t ? t.length : 0, frozen: Object.isFrozen(window.__PUDDLE__) };`);
  check("the page holds a 64-character token, frozen", token.type === "string" && token.length === 64 && token.frozen);

  let badge = "";
  for (let i = 0; i < 100 && !badge.includes("1 pending"); i++) {
    badge = await run(`const b = document.querySelector('[data-testid="pending-badge"]'); return b ? b.textContent : "";`);
    if (!badge.includes("1 pending")) await sleep(300);
  }
  check("the fixture's pending request shows in the sidebar badge", badge.includes("1 pending"), badge.trim());
  const banner = await run(`const s = document.querySelector('[role="status"]'); return s ? s.textContent : "";`);
  check("no 'can't sign in' banner", !banner.includes("can't sign in"), banner.trim());

  // The main window has no Tauri permissions: every command is refused (or there is no bridge).
  const refused = await run(`
    const internals = window.__TAURI_INTERNALS__;
    if (!internals || typeof internals.invoke !== "function") return { bridge: false, results: [] };
    const commands = ["ping", "plugin:app|version", "plugin:opener|open_url", "plugin:path|resolve_directory", "plugin:event|listen"];
    const results = await Promise.all(commands.map((cmd) =>
      internals.invoke(cmd, cmd === "plugin:opener|open_url" ? { url: "https://example.org/" } : {})
        .then(() => ({ cmd, refused: false, message: "succeeded" }),
              (e) => ({ cmd, refused: true, message: String(e) }))));
    return { bridge: true, results };`);
  console.log(`     IPC bridge present: ${refused.bridge}`);
  for (const r of refused.results) {
    check(`invoke ${r.cmd} is refused`, r.refused && /not allowed/i.test(r.message), r.message.split("\n")[0]);
  }
} catch (err) {
  check("the smoke test ran to the end", false, String(err?.stack ?? err));
} finally {
  page?.close();
  if (!appExited) {
    // The whole tree: WebView2's processes are children of the app.
    spawnSync("taskkill", ["/PID", String(app.pid), "/T", "/F"], { stdio: "ignore" });
  }
}

if (failures.length > 0) {
  console.error(`\n${failures.length} check(s) failed: ${failures.join("; ")}`);
  process.exit(1);
}
console.log("\nsmoke test passed");
process.exit(0);
