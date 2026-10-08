// SPDX-License-Identifier: GPL-3.0-or-later
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseRepoUrl, repoName } from "./repo.ts";

interface Case {
  url: string;
  repo: [string, string, string] | null;
}

// The same file drives the host's parser (`RepoRef::from_https_url`).
const cases = (
  JSON.parse(
    readFileSync(
      // Vitest runs in `ui/`.
      resolve(
        process.cwd(),
        "../crates/puddle-store/tests/data/repo-urls.json",
      ),
      "utf8",
    ),
  ) as { cases: Case[] }
).cases;

describe("parseRepoUrl", () => {
  it.each(cases)("reads $url like the host does", ({ url, repo }) => {
    const got = parseRepoUrl(url);
    if (repo === null) {
      expect(got.ok).toBe(false);
    } else {
      expect(got).toEqual({
        ok: true,
        host: repo[0],
        owner: repo[1],
        repo: repo[2],
      });
    }
  });

  it("says why an address is refused, in the create form's words", () => {
    const message = (url: string) => {
      const got = parseRepoUrl(url);
      return got.ok ? "" : got.message;
    };
    expect(message("")).toMatch(/Enter the repository/);
    expect(message("git@github.com:a/b.git")).toMatch(
      /SSH remotes are not supported/,
    );
    expect(message("https://me@github.com/a/b")).toMatch(
      /Remove the user name/,
    );
    expect(message("https://github.com/a")).toMatch(
      /not a repository address puddle can read/,
    );
  });

  it("names a repository the way the table does", () => {
    expect(repoName({ host: "github.com", owner: "acme", repo: "web" })).toBe(
      "github.com/acme/web",
    );
  });
});
