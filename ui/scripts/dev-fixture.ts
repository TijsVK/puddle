// SPDX-License-Identifier: GPL-3.0-or-later
// `npm run dev:fixture [-- <scenario> [<port>]]`: the real API on fake services (the UI fixture
// backend) and Vite's dev server in front of it, with hot reload. The browser never holds the
// token: the dev proxy adds it. Scripted events: see the printed `curl` lines.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { buildFixture } from "./fixture-binary.ts";

const scenario = process.argv[2] ?? "lived-in";
const port = process.argv[3] ?? "4180";
const dir = resolve(import.meta.dirname, "..", ".svelte-kit", "fixture");
const connection = resolve(dir, "connection.json");
mkdirSync(dir, { recursive: true });
rmSync(connection, { force: true });

const executable = buildFixture();
const fixture = spawn(
  executable,
  ["--scenario", scenario, "--port", port, "--connection-file", connection],
  { stdio: ["ignore", "inherit", "inherit"] },
);
fixture.on("exit", (code) => {
  if (code !== null && code !== 0) {
    console.error(`fixture backend exited with ${code}`);
    process.exit(code);
  }
});

for (let i = 0; i < 200 && !existsSync(`${connection}.control`); i += 1) {
  await new Promise((r) => setTimeout(r, 50));
}
if (!existsSync(`${connection}.control`)) {
  fixture.kill();
  throw new Error("the fixture backend did not start");
}
const control = (
  JSON.parse(readFileSync(`${connection}.control`, "utf8")) as { url: string }
).url;
const token = (
  JSON.parse(readFileSync(connection, "utf8")) as { token: string }
).token;
console.log(`
fixture "${scenario}": API http://127.0.0.1:${port}, control ${control}
  state:   curl -s -H 'Authorization: Bearer ${token}' ${control}/control/state
  script:  curl -s -XPOST -H 'Authorization: Bearer ${token}' ${control}/control/script/arrivals
  reset:   curl -s -XPOST -H 'Authorization: Bearer ${token}' ${control}/control/reset
`);

const vite = spawn(
  process.execPath,
  [
    resolve(
      import.meta.dirname,
      "..",
      "node_modules",
      "vite",
      "bin",
      "vite.js",
    ),
    "dev",
  ],
  {
    stdio: "inherit",
    env: { ...process.env, PUDDLE_CONNECTION_FILE: connection },
  },
);
const stop = () => {
  fixture.kill();
  vite.kill();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
vite.on("exit", (code) => {
  fixture.kill();
  process.exit(code ?? 0);
});
