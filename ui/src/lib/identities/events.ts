// SPDX-License-Identifier: GPL-3.0-or-later
// The stream events the identity screens and their notices act on, narrowed from the generated
// `Event`. Read defensively: an event that is not an object of exactly that type is ignored.
import type { components } from "#lib/api/schema.d.ts";

type Event = components["schemas"]["Event"];

export type IdentitiesChanged = Extract<Event, { type: "identities_changed" }>;
export type WorkspaceGitChanged = Extract<
  Event,
  { type: "workspace_git_changed" }
>;
export type CredentialSignInNeeded = Extract<
  Event,
  { type: "credential_sign_in_needed" }
>;
export type GitAccessDenied = Extract<Event, { type: "git_access_denied" }>;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null;

export function isIdentitiesChanged(v: unknown): v is IdentitiesChanged {
  return isObject(v) && v["type"] === "identities_changed";
}

/** A change to a workspace's Git settings; `name` narrows it to one workspace. */
export function isWorkspaceGitChanged(
  v: unknown,
  name?: string,
): v is WorkspaceGitChanged {
  return (
    isObject(v) &&
    v["type"] === "workspace_git_changed" &&
    typeof v["workspace"] === "string" &&
    (name === undefined || v["workspace"] === name)
  );
}

const str = (v: unknown) => typeof v === "string";

/** The two events that become notices, when their fields have the right types. */
export function asCredentialEvent(
  raw: unknown,
): CredentialSignInNeeded | GitAccessDenied | null {
  if (!isObject(raw)) return null;
  if (raw["type"] === "credential_sign_in_needed") {
    return str(raw["host"]) && str(raw["source"])
      ? (raw as CredentialSignInNeeded)
      : null;
  }
  if (raw["type"] === "git_access_denied") {
    const access = raw["access"];
    return str(raw["workspace"]) &&
      str(raw["host"]) &&
      str(raw["owner"]) &&
      str(raw["repo"]) &&
      (access === "push" || access === "pull")
      ? (raw as GitAccessDenied)
      : null;
  }
  return null;
}
