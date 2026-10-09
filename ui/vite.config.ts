// SPDX-License-Identifier: GPL-3.0-or-later
import adapter from "@sveltejs/adapter-static";
import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vitest/config";
import { devProxy } from "./tools/dev-proxy.ts";
import { shippedPackages } from "./tools/shipped-packages.ts";

export default defineConfig({
  plugins: [
    sveltekit({
      // A single-page app: every route is answered by index.html and rendered in the browser
      // (src/routes/+layout.ts turns SSR off), so puddle-api can serve it as plain files.
      adapter: adapter({ fallback: "index.html" }),
    }),
    shippedPackages(),
  ],
  server: { proxy: devProxy() },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "tools/**/*.test.ts", "scripts/**/*.test.ts"],
    setupFiles: ["./vitest.setup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,svelte}", "tools/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "tools/**/*.test.ts",
        "scripts/**/*.test.ts",
        "src/lib/api/schema.d.ts",
        "src/lib/testing/**",
        "src/app.d.ts",
      ],
      reporter: ["text-summary", "text", "lcov"],
      thresholds: {
        lines: 85,
        branches: 80,
        functions: 85,
        statements: 85,
        "src/lib/api/**": { lines: 95, branches: 90 },
        "src/lib/decision/**": { lines: 95, branches: 90 },
        "src/lib/rules/**": { lines: 95, branches: 90 },
        "src/lib/audit/**": { lines: 95, branches: 90 },
        "src/lib/workspaces/**": { lines: 95, branches: 90 },
        "src/lib/settings/**": { lines: 95, branches: 90 },
        "src/lib/network/**": { lines: 95, branches: 90 },
        "src/lib/notify/**": { lines: 95, branches: 90 },
        "src/lib/identities/**": { lines: 95, branches: 90 },
        "src/lib/repos/**": { lines: 95, branches: 90 },
      },
    },
  },
  resolve: process.env["VITEST"] ? { conditions: ["browser"] } : {},
});
