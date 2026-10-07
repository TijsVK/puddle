// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "./client.ts";

function fakeFetch(status = 200, body: unknown = { requests: [] }) {
  return vi.fn(
    async (_request: RequestInfo | URL) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
}

describe("createApiClient", () => {
  it("adds the bearer token to every request", async () => {
    const fetch = fakeFetch();
    const client = createApiClient({
      baseUrl: "http://127.0.0.1:1",
      getToken: () => "tok",
      fetch,
    });
    const { data } = await client.GET("/api/pending");
    expect(data).toEqual({ requests: [] });
    const request = fetch.mock.calls[0]?.[0] as Request;
    expect(request.headers.get("authorization")).toBe("Bearer tok");
    expect(request.url).toBe("http://127.0.0.1:1/api/pending");
  });

  it("sends no Authorization header without a token (the dev proxy adds one)", async () => {
    const fetch = fakeFetch();
    const client = createApiClient({
      baseUrl: "http://x",
      getToken: () => undefined,
      fetch,
    });
    await client.GET("/api/pending");
    expect(
      (fetch.mock.calls[0]?.[0] as Request).headers.has("authorization"),
    ).toBe(false);
  });

  it("looks the token up per request, so a late one is used", async () => {
    const fetch = fakeFetch();
    const state: { token?: string } = {};
    const client = createApiClient({
      baseUrl: "http://x",
      getToken: () => state.token,
      fetch,
    });
    await client.GET("/api/pending");
    state.token = "late";
    await client.GET("/api/pending");
    expect(
      (fetch.mock.calls[1]?.[0] as Request).headers.get("authorization"),
    ).toBe("Bearer late");
  });

  it("returns the error body of a refusal instead of throwing", async () => {
    const fetch = fakeFetch(401, {
      error: "unauthorized",
      message: "missing or wrong bearer token",
    });
    const client = createApiClient({
      baseUrl: "http://x",
      getToken: () => undefined,
      fetch,
    });
    const { data, error, response } = await client.GET("/api/pending");
    expect(data).toBeUndefined();
    expect(error?.error).toBe("unauthorized");
    expect(response.status).toBe(401);
  });

  it("sends typed bodies and path parameters", async () => {
    const fetch = fakeFetch(200, {});
    const client = createApiClient({
      baseUrl: "http://x",
      getToken: () => "t",
      fetch,
    });
    await client.DELETE("/api/rules/{id}", { params: { path: { id: 7 } } });
    const request = fetch.mock.calls[0]?.[0] as Request;
    expect(request.method).toBe("DELETE");
    expect(new URL(request.url).pathname).toBe("/api/rules/7");
  });

  it("uses the page's origin and the global fetch by default", async () => {
    // A browser resolves "/api/..." against the page; node's Request needs an absolute URL.
    const NativeRequest = globalThis.Request;
    class PageRequest extends NativeRequest {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        super(
          typeof input === "string" && input.startsWith("/")
            ? `http://127.0.0.1${input}`
            : input,
          init,
        );
      }
    }
    const fetch = vi.fn(
      async () =>
        new Response("{}", { headers: { "content-type": "application/json" } }),
    );
    vi.stubGlobal("Request", PageRequest);
    vi.stubGlobal("fetch", fetch);
    try {
      vi.resetModules();
      const { api } = await import("./client.ts");
      const { response } = await api.GET("/api/health");
      expect(response.status).toBe(200);
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
