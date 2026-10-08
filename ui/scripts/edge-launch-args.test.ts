// SPDX-License-Identifier: GPL-3.0-or-later
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  COPIED_FROM_PLAYWRIGHT,
  EDGE_DISABLED_FEATURES,
  edgeLaunchArgs,
} from "./edge-launch-args.ts";

const installed = (
  JSON.parse(
    readFileSync(
      resolve(
        import.meta.dirname,
        "..",
        "node_modules",
        "@playwright",
        "test",
        "package.json",
      ),
      "utf8",
    ),
  ) as { version: string }
).version;

describe("the Edge launch switches", () => {
  it("are one --disable-features switch (Chromium reads only the last) with the port randomization off", () => {
    const args = edgeLaunchArgs();
    expect(args).toHaveLength(1);
    expect(args[0]).toMatch(/^--disable-features=[A-Za-z,]+$/);
    const features = args[0]?.slice("--disable-features=".length).split(",");
    expect(features).toEqual(EDGE_DISABLED_FEATURES);
    expect(features).toContain("TcpPortRandomizationWin");
    expect(new Set(features).size).toBe(features?.length);
  });

  it("repeat the list of the Playwright that is installed, or say what to refresh", () => {
    expect(
      installed,
      `Playwright is ${installed}, the list in edge-launch-args.ts was copied from ${COPIED_FROM_PLAYWRIGHT}: ` +
        "compare `disabledFeatures` in node_modules/playwright-core/lib/coreBundle.js (chromiumSwitches) with " +
        "PLAYWRIGHT_DISABLED_FEATURES, then update both",
    ).toBe(COPIED_FROM_PLAYWRIGHT);
  });
});
