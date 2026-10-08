// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  asCredentialEvent,
  isIdentitiesChanged,
  isWorkspaceGitChanged,
} from "./events.ts";

describe("identity events", () => {
  it("recognises the two change events and only them", () => {
    expect(isIdentitiesChanged({ type: "identities_changed" })).toBe(true);
    expect(isIdentitiesChanged({ type: "rules_changed" })).toBe(false);
    expect(isIdentitiesChanged(null)).toBe(false);
    expect(isIdentitiesChanged("identities_changed")).toBe(false);
    const git = { type: "workspace_git_changed", workspace: "web" };
    expect(isWorkspaceGitChanged(git)).toBe(true);
    expect(isWorkspaceGitChanged(git, "web")).toBe(true);
    expect(isWorkspaceGitChanged(git, "other")).toBe(false);
    expect(isWorkspaceGitChanged({ type: "workspace_git_changed" })).toBe(
      false,
    );
    expect(isWorkspaceGitChanged(undefined)).toBe(false);
  });

  it("reads a sign-in notice event when its fields are text", () => {
    const ok = {
      type: "credential_sign_in_needed",
      host: "github.com",
      source: "gh account me on github.com",
    };
    expect(asCredentialEvent(ok)).toEqual(ok);
    expect(asCredentialEvent({ ...ok, host: 3 })).toBeNull();
    expect(asCredentialEvent({ ...ok, source: undefined })).toBeNull();
  });

  it("reads a refused-access event when its fields are right", () => {
    const ok = {
      type: "git_access_denied",
      workspace: "web",
      host: "github.com",
      owner: "acme",
      repo: "billing",
      access: "push",
    };
    expect(asCredentialEvent(ok)).toEqual(ok);
    expect(asCredentialEvent({ ...ok, access: "pull" })).toMatchObject({
      access: "pull",
    });
    expect(asCredentialEvent({ ...ok, access: "delete" })).toBeNull();
    expect(asCredentialEvent({ ...ok, owner: 1 })).toBeNull();
    expect(asCredentialEvent({ type: "oom_kill" })).toBeNull();
    expect(asCredentialEvent(7)).toBeNull();
  });
});
