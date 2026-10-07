// SPDX-License-Identifier: GPL-3.0-or-later
// `npm run dev` proxy: /api goes to the running API from its connection file, and the bearer
// token is added here, server side, so the browser tab never holds it. Point
// PUDDLE_CONNECTION_FILE at the file `ConnectionInfo::write` made (or the UI fixture backend's).
import { readFileSync } from "node:fs";
import type { ProxyOptions } from "vite";

export interface Connection {
  url: string;
  token: string;
}

/** Parses the connection file's JSON (`{version, url, token}`); throws a readable error. */
export function parseConnection(text: string): Connection {
  const value: unknown = JSON.parse(text);
  if (typeof value === "object" && value !== null) {
    const { version, url, token } = value as Record<string, unknown>;
    if (version === 1 && typeof url === "string" && typeof token === "string") {
      return { url, token };
    }
  }
  throw new Error("not a puddle connection file (version 1)");
}

export interface DevProxyDeps {
  env?: Record<string, string | undefined>;
  read?: (path: string) => string;
}

/** The Vite `server.proxy` entry, or none when no connection file is named. */
export function devProxy(
  deps: DevProxyDeps = {},
): Record<string, ProxyOptions> {
  const env = deps.env ?? process.env;
  const read = deps.read ?? ((path: string) => readFileSync(path, "utf8"));
  const path = env["PUDDLE_CONNECTION_FILE"];
  if (!path) return {};
  const connection = parseConnection(read(path));
  return {
    "/api": {
      target: connection.url,
      // The API checks Host against its own address, so the proxy presents it.
      changeOrigin: true,
      configure(proxy) {
        proxy.on("proxyReq", (request) => {
          request.setHeader("Authorization", `Bearer ${connection.token}`);
          // The API refuses unknown origins; a proxied request is same-origin from its view.
          request.removeHeader("origin");
        });
      },
    },
  };
}
