// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  credential,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { repoSource, repoView } from "#lib/testing/fake-repos.ts";
import {
  credentialOf,
  freshness,
  matching,
  matchingUrl,
  nextRetryDelay,
  POLL_CEILING_MS,
  POLL_FLOOR_MS,
  retryText,
  roleWord,
  sourceTitle,
  tableCannotHold,
  traits,
} from "./model.ts";

const NOW = 10_000_000;
const work = identity(1, {
  label: "Work",
  credentials: [
    credential({
      source: ghSource("tijs-work"),
      owners: ["acme"],
      rest: false,
    }),
  ],
});
const personal = identity(2, {
  label: "Personal",
  credentials: [credential({ source: ghSource("tijs-demo"), rest: true })],
});
const other = identity(3, {
  label: "Other host",
  credentials: [
    credential({ host: "dev.azure.com", owners: ["contoso"], rest: false }),
  ],
});

describe("sourceTitle", () => {
  it("names the sign-in and the host, with the organisation on Azure DevOps", () => {
    expect(sourceTitle(repoSource(), work)).toBe(
      "gh · tijs-work on github.com",
    );
    const ado = identity(4, {
      credentials: [
        credential({
          host: "dev.azure.com",
          source: {
            kind: "git_credential",
            host: "dev.azure.com",
            path: "contoso",
            username: null,
          },
        }),
      ],
    });
    expect(
      sourceTitle(
        repoSource({ host: "dev.azure.com", organisation: "contoso" }),
        ado,
      ),
    ).toBe(
      "Git Credential Manager · dev.azure.com/contoso on dev.azure.com/contoso",
    );
  });

  it("still names a list whose credential is gone", () => {
    expect(sourceTitle(repoSource({ credential: 2 }), undefined)).toBe(
      "Credential 3 on github.com",
    );
    expect(credentialOf(repoSource({ credential: 2 }), work)).toBeUndefined();
  });
});

describe("freshness", () => {
  it("says when a good list was read and how many it holds", () => {
    const source = repoSource({ repo_count: 3, refreshed_at: NOW - 180_000 });
    expect(freshness(source, NOW)).toBe("3 repositories, read 3 minutes ago.");
    expect(
      freshness({ ...source, repo_count: 1, refreshed_at: null }, NOW),
    ).toBe("1 repository, read just now.");
  });

  it("says an old list is old and why it is shown", () => {
    const source = repoSource({
      state: "stale",
      repo_count: 2,
      refreshed_at: NOW - 900_000,
    });
    expect(freshness(source, NOW)).toBe(
      "2 repositories from the last good read, 15 minutes ago. The newest read did not work.",
    );
    expect(freshness({ ...source, refreshed_at: null }, NOW)).toContain(
      "from the last good read. The newest",
    );
  });

  it("says a failed or impossible list holds nothing", () => {
    expect(freshness(repoSource({ state: "failed" }), NOW)).toBe(
      "Nothing read yet.",
    );
    expect(freshness(repoSource({ state: "unavailable" }), NOW)).toBe(
      "puddle cannot list this one.",
    );
  });
});

describe("waiting for a host", () => {
  it("words when puddle asks again, only while it is in the future", () => {
    expect(retryText(repoSource({ retry_at: NOW + 600_000 }), NOW)).toBe(
      "puddle asks again in 10 minutes.",
    );
    expect(retryText(repoSource({ retry_at: NOW - 1 }), NOW)).toBeNull();
    expect(retryText(repoSource(), NOW)).toBeNull();
  });

  it("asks again a second after the soonest wait ends, within bounds", () => {
    const wait = (ms: number | null) =>
      repoSource({ retry_at: ms === null ? null : NOW + ms });
    expect(nextRetryDelay([wait(null)], NOW)).toBeNull();
    expect(nextRetryDelay([wait(-5)], NOW)).toBeNull();
    expect(nextRetryDelay([wait(30_000), wait(5_000)], NOW)).toBe(
      5_000 + POLL_FLOOR_MS,
    );
    expect(nextRetryDelay([wait(3 * 3_600_000)], NOW)).toBe(POLL_CEILING_MS);
  });
});

describe("a repository's words", () => {
  it("shows the role, but not an unknown one", () => {
    expect(roleWord("admin")).toBe("admin");
    expect(roleWord("unknown")).toBe("");
  });

  it("lists visibility, archived and fork as traits", () => {
    expect(traits(repoView("a", "b"))).toEqual(["private"]);
    expect(
      traits(
        repoView("a", "b", {
          visibility: "unknown",
          archived: true,
          fork: true,
        }),
      ),
    ).toEqual(["archived", "fork"]);
  });
});

describe("matching identities", () => {
  const all = [work, personal, other];

  it("takes an exact owner and the rest of the host, on the right host, in your order", () => {
    expect(matching(all, "github.com", "ACME").map((i) => i.id)).toEqual([
      1, 2,
    ]);
    expect(matching(all, "GitHub.com", "someone").map((i) => i.id)).toEqual([
      2,
    ]);
    expect(matching(all, "dev.azure.com", "contoso").map((i) => i.id)).toEqual([
      3,
    ]);
    expect(matching(all, "gitlab.com", "acme")).toEqual([]);
  });

  it("puts the identity that listed it first", () => {
    expect(matching(all, "github.com", "acme", 2).map((i) => i.id)).toEqual([
      2, 1,
    ]);
  });

  it("reads an address, or finds none when it cannot", () => {
    expect(
      matchingUrl(all, "https://github.com/acme/web.git").map((i) => i.id),
    ).toEqual([1, 2]);
    expect(matchingUrl(all, "not a url")).toEqual([]);
  });
});

describe("tableCannotHold", () => {
  it("is true for an Azure DevOps project with a space, spelled either way", () => {
    expect(
      tableCannotHold(
        "https://dev.azure.com/contoso/Shop%20Floor/_git/scanner",
      ),
    ).toBe(true);
    expect(
      tableCannotHold("https://dev.azure.com/contoso/Shop Floor/_git/scanner"),
    ).toBe(true);
    expect(
      tableCannotHold("https://contoso.visualstudio.com/Shop%20Floor/_git/x"),
    ).toBe(true);
  });

  it("is false for names without a space and for other hosts", () => {
    expect(
      tableCannotHold("https://dev.azure.com/contoso/Platform/_git/api"),
    ).toBe(false);
    expect(tableCannotHold("https://github.com/acme/web%20x")).toBe(false);
    expect(tableCannotHold("https://dev.azure.com")).toBe(false);
    expect(tableCannotHold("")).toBe(false);
    expect(
      tableCannotHold("https://dev.azure.com/contoso/%E0%A4%A/_git/x"),
    ).toBe(false);
  });
});
