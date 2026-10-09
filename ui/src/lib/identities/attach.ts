// SPDX-License-Identifier: GPL-3.0-or-later
// Gives a workspace that was just made the identities the create form chose. The host attaches the
// identity that covers the repository (else the default) when it makes the workspace; this puts
// the chosen ones in its place through the same calls the workspace's Git tab uses, in the order
// of the form (the identity that listed the repository first).
import {
  WorkspaceGitStore,
  type WorkspaceGit,
} from "#lib/stores/workspace-git.svelte.ts";
import type { Result } from "#lib/stores/identities.svelte.ts";

type GitCalls = Pick<
  WorkspaceGitStore,
  "load" | "attach" | "detach" | "setIdentities" | "git" | "status"
>;

/** The ids already on a workspace's Git view, in order. */
function idsOf(git: WorkspaceGit | null): number[] {
  return git?.identities.map((i) => i.id) ?? [];
}

/**
 * Makes `wanted` (in this order) the workspace's identities. Stops at the first refusal and says
 * which identity it was, in the host's words.
 */
export async function useIdentities(
  workspace: string,
  wanted: readonly number[],
  labels: (id: number) => string,
  git: GitCalls = new WorkspaceGitStore(),
): Promise<Result> {
  await git.load(workspace, true);
  if (git.git === null) {
    return {
      ok: false,
      message: "puddle couldn't read which identities the workspace has.",
    };
  }
  const have = idsOf(git.git);
  for (const id of have.filter((id) => !wanted.includes(id))) {
    const result = await git.detach(id);
    if (!result.ok) {
      return { ok: false, message: `${labels(id)}: ${result.message}` };
    }
  }
  for (const id of wanted.filter((id) => !have.includes(id))) {
    const result = await git.attach(id);
    if (!result.ok) {
      return { ok: false, message: `${labels(id)}: ${result.message}` };
    }
  }
  const now = idsOf(git.git);
  const inOrder =
    now.length === wanted.length && now.every((id, at) => id === wanted[at]);
  if (!inOrder) {
    const result = await git.setIdentities([...wanted]);
    if (!result.ok) return { ok: false, message: result.message };
  }
  return { ok: true };
}
