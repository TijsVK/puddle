// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import { devProxy, parseConnection } from "./dev-proxy.ts";

const file = JSON.stringify({
  version: 1,
  url: "http://127.0.0.1:4000",
  token: "secret",
});

describe("parseConnection", () => {
  it("reads a version 1 connection file", () => {
    expect(parseConnection(file)).toEqual({
      url: "http://127.0.0.1:4000",
      token: "secret",
    });
  });

  it("refuses anything else without echoing it", () => {
    for (const bad of [
      '{"version":2,"url":"u","token":"t"}',
      '{"version":1}',
      "[]",
      "null",
      '"x"',
    ]) {
      expect(() => parseConnection(bad)).toThrow(
        "not a puddle connection file",
      );
    }
    expect(() => parseConnection("{")).toThrow();
  });
});

describe("devProxy", () => {
  it("is empty when no connection file is named", () => {
    expect(devProxy({ env: {} })).toEqual({});
  });

  it("proxies /api to the API and adds the token and drops Origin server side", () => {
    const read = vi.fn(() => file);
    const proxies = devProxy({
      env: { PUDDLE_CONNECTION_FILE: "/run/puddle/api.json" },
      read,
    });
    expect(read).toHaveBeenCalledWith("/run/puddle/api.json");
    const entry = proxies["/api"];
    expect(entry).toMatchObject({
      target: "http://127.0.0.1:4000",
      changeOrigin: true,
    });

    const handlers: Record<string, (request: unknown) => void> = {};
    entry?.configure?.(
      {
        on: (name: string, fn: (r: unknown) => void) => (handlers[name] = fn),
      } as never,
      entry,
    );
    const headers = new Map<string, string>([
      ["origin", "http://localhost:5173"],
    ]);
    handlers["proxyReq"]?.({
      setHeader: (k: string, v: string) => headers.set(k.toLowerCase(), v),
      removeHeader: (k: string) => headers.delete(k),
    });
    expect(headers.get("authorization")).toBe("Bearer secret");
    expect(headers.has("origin")).toBe(false);
  });

  it("reads the real file system by default", () => {
    expect(() =>
      devProxy({ env: { PUDDLE_CONNECTION_FILE: "/nonexistent/puddle.json" } }),
    ).toThrow();
  });
});
