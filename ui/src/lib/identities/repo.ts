// SPDX-License-Identifier: GPL-3.0-or-later
// The repository a clone address names, in the one spelling a workspace's repository table keeps
// (host and names lower-case, no `.git`, Azure DevOps `project/repo`). The host reads addresses
// the same way (`RepoRef::from_https_url`); both are tested against one list of cases.
import { repoUrlProblem } from "#lib/workspaces/model.ts";

export interface RepoRef {
  host: string;
  owner: string;
  repo: string;
}

export type ParsedRepo =
  ({ ok: true } & RepoRef) | { ok: false; message: string };

const SHAPE =
  "That is not a repository address puddle can read. Use https://github.com/owner/repo or https://dev.azure.com/organisation/project/_git/repo.";

const NAME = /^[a-z0-9._-]{1,100}$/;

function refuse(): ParsedRepo {
  return { ok: false, message: SHAPE };
}

/** The repository `raw` names, or why it can't be listed. */
export function parseRepoUrl(raw: string): ParsedRepo {
  const problem = repoUrlProblem(raw);
  if (problem !== null) return { ok: false, message: problem };
  const rest = raw.trim().slice("https://".length).split(/[?#]/)[0] ?? "";
  const slash = rest.indexOf("/");
  if (slash < 0) return refuse();
  const host = rest.slice(0, slash).toLowerCase();
  if (host.includes(":") || host.includes("@")) return refuse();
  const segments = rest
    .slice(slash + 1)
    .split("/")
    .filter((s) => s !== "");
  const isGit = (s: string | undefined) => s?.toLowerCase() === "_git";
  let owner: string;
  let repo: string;
  const [a, b, c, d] = segments;
  if (host === "dev.azure.com") {
    if (segments.length === 3 && a && isGit(b) && c) {
      owner = a;
      repo = `${c}/${c}`;
    } else if (segments.length === 4 && a && b && isGit(c) && d) {
      owner = a;
      repo = `${b}/${d}`;
    } else return refuse();
  } else if (host.endsWith(".visualstudio.com")) {
    owner = host.slice(0, -".visualstudio.com".length);
    if (segments.length === 3 && a && isGit(b) && c) repo = `${a}/${c}`;
    else if (segments.length === 4 && b && isGit(c) && d) repo = `${b}/${d}`;
    else return refuse();
  } else if (segments.length === 2 && a && b) {
    owner = a;
    repo = b;
  } else return refuse();
  owner = owner.toLowerCase();
  repo = repo.toLowerCase().replace(/\.git$/, "");
  const parts = repo.split("/");
  const valid =
    NAME.test(owner) &&
    parts.length >= 1 &&
    parts.length <= 2 &&
    parts.every((p) => NAME.test(p) && p !== "." && p !== "..");
  return valid ? { ok: true, host, owner, repo } : refuse();
}

/** `github.com/acme/web-shop`, as a row of the table reads. */
export function repoName(repo: RepoRef): string {
  return `${repo.host}/${repo.owner}/${repo.repo}`;
}
