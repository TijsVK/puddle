// SPDX-License-Identifier: GPL-3.0-or-later
// How the page learns the API token. The desktop shell sets `window.__PUDDLE__` with an init
// script before the app starts; in `npm run dev` the Vite proxy adds the token to /api requests
// itself, so the page never holds one. The token is never read from a URL, a cookie or storage,
// and never written to any of them.

/** What the shell hands the page. */
export interface PuddleBootstrap {
  /** The API bearer token. */
  token?: string;
}

/** The token, if the shell provided one. */
export function bootstrapToken(
  scope: { __PUDDLE__?: PuddleBootstrap } = globalThis as {
    __PUDDLE__?: PuddleBootstrap;
  },
): string | undefined {
  const token = scope.__PUDDLE__?.token;
  return typeof token === "string" && token !== "" ? token : undefined;
}

/** The request header carrying the token, or none without one. */
export function authHeaders(token: string | undefined): Record<string, string> {
  return token === undefined ? {} : { Authorization: `Bearer ${token}` };
}
