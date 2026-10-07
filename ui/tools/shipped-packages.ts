// SPDX-License-Identifier: GPL-3.0-or-later
// Records which npm packages end up in the browser bundle, for the licence gate
// (scripts/licences.ts): what ships is what must be licence-checked, not the whole install tree
// (build tools are never shipped). Written by `vite build` to .svelte-kit/shipped-packages.json.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Plugin } from "vite";

export const SHIPPED_FILE = ".svelte-kit/shipped-packages.json";

/** The package directory (relative, `node_modules/@scope/name`) a module id belongs to. */
export function packageDirOf(id: string): string | undefined {
  const path = id.split("?")[0]?.replaceAll("\\", "/") ?? "";
  const marker = "node_modules/";
  const at = path.lastIndexOf(marker);
  if (at < 0) return undefined;
  const rest = path.slice(at + marker.length).split("/");
  const name = rest[0]?.startsWith("@") ? rest.slice(0, 2).join("/") : rest[0];
  if (!name) return undefined;
  const prefix = path.slice(0, at + marker.length);
  return `${prefix}${name}`;
}

/** Vite plugin: lists the packages of the client bundle after the build. */
export function shippedPackages(file = SHIPPED_FILE): Plugin {
  return {
    name: "puddle-shipped-packages",
    apply: "build",
    generateBundle(_options, bundle) {
      if (this.environment?.name !== "client") return;
      const dirs = new Set<string>();
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== "chunk") continue;
        for (const id of Object.keys(chunk.modules)) {
          const dir = packageDirOf(id);
          if (dir) dirs.add(dir);
        }
      }
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, `${JSON.stringify([...dirs].sort(), null, 2)}\n`);
    },
  };
}
