// SPDX-License-Identifier: GPL-3.0-or-later
// What the repository lists mean on screen, as pure functions: how a list's freshness, notes and
// problem are worded, which identities reach a repository, and which clone addresses the
// workspace's repository table cannot hold. The lists come from `GET /api/repos`; every string
// the host sends (a note, a problem's message) is untrusted text and is only ever rendered as text.
import type { components } from "#lib/api/schema.d.ts";
import { relativeTime } from "#lib/format/relative-time.ts";
import {
  sourceLabel,
  type Credential,
  type Identity,
} from "#lib/identities/model.ts";
import { parseRepoUrl } from "#lib/identities/repo.ts";

export type RepoListing = components["schemas"]["RepoListing"];
export type RepoView = components["schemas"]["RepoView"];
export type RepoSource = components["schemas"]["RepoSource"];
export type RepoNote = components["schemas"]["RepoNote"];
export type RepoProblem = components["schemas"]["RepoProblem"];

/** The repositories a screen asks for. */
export interface RepoQuery {
  /** Only this identity's repositories. */
  identity?: number;
  /** Words that must all appear in the full name. */
  query?: string;
  limit?: number;
}

/** A list read this long ago is shown as it is; the host reads again after ten minutes. */
export const POLL_FLOOR_MS = 1000;
/** Longest wait before asking again, so a far-off `retry_at` still gets looked at. */
export const POLL_CEILING_MS = 10 * 60_000;

/** Which credential of `identity` a list was read with, when the identity still has it. */
export function credentialOf(
  source: RepoSource,
  identity: Identity | undefined,
): Credential | undefined {
  return identity?.credentials[source.credential];
}

/** Names a list: the sign-in it was read with and where (the organisation on Azure DevOps). */
export function sourceTitle(
  source: RepoSource,
  identity: Identity | undefined,
): string {
  const where =
    source.organisation === null
      ? source.host
      : `${source.host}/${source.organisation}`;
  const credential = credentialOf(source, identity);
  return credential
    ? `${sourceLabel(credential.source)} on ${where}`
    : `Credential ${source.credential + 1} on ${where}`;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** How current a list is, in a sentence. */
export function freshness(source: RepoSource, now: number): string {
  const count = plural(source.repo_count, "repository", "repositories");
  const read =
    source.refreshed_at === null
      ? null
      : relativeTime(source.refreshed_at, now);
  switch (source.state) {
    case "ok":
      return `${count}, read ${read ?? "just now"}.`;
    case "stale":
      return `${count} from the last good read${read === null ? "" : `, ${read}`}. The newest read did not work.`;
    case "failed":
      return "Nothing read yet. Refresh tries again.";
    case "unavailable":
      return "puddle cannot list this one. Edit the identity to change its sign-in.";
  }
}

/** When puddle may ask again, when the host said to wait. */
export function retryText(source: RepoSource, now: number): string | null {
  if (source.retry_at === null || source.retry_at <= now) return null;
  return `puddle asks again ${relativeTime(source.retry_at, now)}.`;
}

/** The milliseconds until the soonest time a list may be read again, or `null` when none waits. */
export function nextRetryDelay(
  sources: readonly RepoSource[],
  now: number,
): number | null {
  const waits = sources
    .map((s) => s.retry_at)
    .filter((at): at is number => at !== null && at > now)
    .map((at) => at - now);
  if (waits.length === 0) return null;
  return Math.min(
    Math.max(Math.min(...waits) + POLL_FLOOR_MS, POLL_FLOOR_MS),
    POLL_CEILING_MS,
  );
}

/** What a repository's role says, in a word. */
export function roleWord(role: RepoView["role"]): string {
  return role === "unknown" ? "" : role;
}

/** The traits of a repository worth a chip, in words. */
export function traits(repo: RepoView): string[] {
  const out: string[] = [];
  if (repo.visibility !== "unknown") out.push(repo.visibility);
  if (repo.archived) out.push("archived");
  if (repo.fork) out.push("fork");
  return out;
}

/**
 * The identities that can use a repository, as the workspace will see them: those with a credential
 * on its host that names its owner or covers the rest of the host. `first` (the identity that
 * listed it) leads; the rest keep your order.
 */
export function matching(
  identities: readonly Identity[],
  host: string,
  owner: string,
  first?: number | null,
): Identity[] {
  const h = host.toLowerCase();
  const o = owner.toLowerCase();
  const covers = identities.filter((i) =>
    i.credentials.some(
      (c) =>
        c.host.toLowerCase() === h &&
        (c.covers.rest_of_host ||
          c.covers.owners.some((name) => name.toLowerCase() === o)),
    ),
  );
  return [
    ...covers.filter((i) => i.id === first),
    ...covers.filter((i) => i.id !== first),
  ];
}

/** The identities that can use the repository at `url`; none when the address is not readable. */
export function matchingUrl(
  identities: readonly Identity[],
  url: string,
  first?: number | null,
): Identity[] {
  const parsed = parseRepoUrl(url);
  return parsed.ok
    ? matching(identities, parsed.host, parsed.owner, first)
    : [];
}

/**
 * Whether the clone address names an Azure DevOps project with a space in it. The repository table
 * and the proxy cannot spell such a name, so the workspace still clones but its push and pull lists
 * cannot hold the repository.
 */
export function tableCannotHold(url: string): boolean {
  const rest = url.trim().replace(/^https:\/\//i, "");
  const slash = rest.indexOf("/");
  if (slash < 0) return false;
  const host = rest.slice(0, slash).toLowerCase();
  if (host !== "dev.azure.com" && !host.endsWith(".visualstudio.com")) {
    return false;
  }
  const path = rest.slice(slash + 1).split(/[?#]/)[0] ?? "";
  return path.split("/").some((segment) => {
    try {
      return /\s/.test(decodeURIComponent(segment));
    } catch {
      return false;
    }
  });
}

/** The warning for such an address, with the way out. */
export const TABLE_CANNOT_HOLD =
  "This project's name has a space in it, which a workspace's repository table can't hold. The workspace is made, but while “Only push to listed repos” is on, pushes from it are refused: turn that off on the workspace's Git tab, or use a project without a space.";
