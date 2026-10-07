// SPDX-License-Identifier: GPL-3.0-or-later
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { packageDirOf, shippedPackages } from "./shipped-packages.ts";

describe("packageDirOf", () => {
  it("finds the package of a module, scoped or not, nested or not", () => {
    expect(packageDirOf("/w/ui/node_modules/svelte/src/index.js")).toBe(
      "/w/ui/node_modules/svelte",
    );
    expect(
      packageDirOf("/w/ui/node_modules/@lucide/svelte/dist/a.svelte"),
    ).toBe("/w/ui/node_modules/@lucide/svelte");
    expect(
      packageDirOf("/w/ui/node_modules/bits-ui/node_modules/runed/dist/x.js"),
    ).toBe("/w/ui/node_modules/bits-ui/node_modules/runed");
    expect(packageDirOf("C:\\w\\ui\\node_modules\\esm-env\\index.js?v=1")).toBe(
      "C:/w/ui/node_modules/esm-env",
    );
  });

  it("ignores our own sources and virtual modules", () => {
    expect(packageDirOf("/w/ui/src/lib/nav.ts")).toBeUndefined();
    expect(packageDirOf("\0virtual:thing")).toBeUndefined();
    expect(packageDirOf("/w/ui/node_modules/")).toBeUndefined();
  });
});

describe("shippedPackages plugin", () => {
  const run = (environment: string, file: string) => {
    const plugin = shippedPackages(file);
    const hook = plugin.generateBundle as (
      this: unknown,
      o: unknown,
      b: unknown,
    ) => void;
    hook.call(
      { environment: { name: environment } },
      {},
      {
        "a.js": {
          type: "chunk",
          modules: {
            "/w/node_modules/b/i.js": {},
            "/w/node_modules/a/i.js": {},
            "/w/src/x.ts": {},
          },
        },
        "a.css": { type: "asset" },
      },
    );
  };

  it("writes the sorted package list for the client build only", () => {
    const dir = mkdtempSync(join(tmpdir(), "shipped-"));
    try {
      const file = join(dir, "nested", "shipped.json");
      run("ssr", file);
      expect(existsSync(file)).toBe(false);
      run("client", file);
      expect(JSON.parse(readFileSync(file, "utf8"))).toEqual([
        "/w/node_modules/a",
        "/w/node_modules/b",
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
