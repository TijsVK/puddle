// SPDX-License-Identifier: GPL-3.0-or-later
// The typed API client: openapi-fetch over the generated schema.d.ts (ADR 0004). A wrong path or
// body is a compile error (client.types.test.ts). One middleware adds the bearer token.
import createClient, { type Middleware } from "openapi-fetch";
import { authHeaders, bootstrapToken } from "./connection.ts";
import type { paths } from "./schema.d.ts";

export interface ApiClientOptions {
  /** Origin of the API; empty means the page's own origin, which is how the app is served. */
  baseUrl?: string;
  /** Looked up per request, so a token that arrives late is still used. */
  getToken?: () => string | undefined;
  /** For tests. */
  fetch?: typeof fetch;
}

export function createApiClient(options: ApiClientOptions = {}) {
  const getToken = options.getToken ?? (() => bootstrapToken());
  const client = createClient<paths>({
    baseUrl: options.baseUrl ?? "",
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });
  const auth: Middleware = {
    onRequest({ request }) {
      for (const [name, value] of Object.entries(authHeaders(getToken()))) {
        request.headers.set(name, value);
      }
      return request;
    },
  };
  client.use(auth);
  return client;
}

export type ApiClient = ReturnType<typeof createApiClient>;

/** The app's client, on the page's own origin. */
export const api: ApiClient = createApiClient({
  // The global fetch is looked up per call so tests can replace it.
  fetch: (input) => globalThis.fetch(input),
});
