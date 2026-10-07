// SPDX-License-Identifier: GPL-3.0-or-later
// Builds the UI fixture backend (`puddle-ui-fixture`, crate puddle-e2e) and returns the path of
// the executable, so callers can start and stop it directly (not through `cargo run`, whose
// parent process would be the one a signal reaches).
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export const REPO_ROOT = resolve(import.meta.dirname, "..", "..");

/** `check.sh` passes its cargo wrapper (mbx) here; plain cargo otherwise. */
export function cargoCommand(): string {
  return process.env["PUDDLE_CARGO"] ?? "cargo";
}

/** The `cargo build` arguments for the fixture, with the built UI embedded. */
export function buildArgs(): string[] {
  return [
    "build",
    "--quiet",
    "--locked",
    "-p",
    "puddle-e2e",
    "--features",
    "embedded-ui",
    "--bin",
    "puddle-ui-fixture",
    "--message-format=json",
  ];
}

/** The executable named by cargo's JSON messages. */
export function executableFrom(messages: string): string {
  let found: string | undefined;
  for (const line of messages.split("\n")) {
    if (!line.startsWith("{")) continue;
    const message = JSON.parse(line) as {
      reason?: string;
      executable?: string | null;
      target?: { name?: string };
    };
    if (
      message.reason === "compiler-artifact" &&
      message.target?.name === "puddle-ui-fixture" &&
      message.executable
    ) {
      found = message.executable;
    }
  }
  if (!found)
    throw new Error("cargo did not report the puddle-ui-fixture binary");
  return found;
}

export function buildFixture(): string {
  const output = execFileSync(cargoCommand(), buildArgs(), {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
  });
  return executableFrom(output);
}
