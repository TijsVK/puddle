// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { credential, identity } from "#lib/testing/fake-identities.ts";
import {
  authorProblem,
  checkOf,
  coverageOf,
  coverageProblem,
  coverageText,
  covering,
  credentialChip,
  credentialKey,
  describeSource,
  foundLabel,
  hostProblem,
  identityProblem,
  identityStatus,
  labelProblem,
  moved,
  needsOrg,
  orgProblem,
  parseOwners,
  requestOf,
  sourceLabel,
  sourceOf,
  statusWord,
  tokenProblem,
  UNTESTED,
  usedBy,
  type Check,
  type FoundAccount,
  type Source,
} from "./model.ts";

const gh: Source = { kind: "gh", host: "github.com", account: "tijs-work" };
const gcm: Source = {
  kind: "git_credential",
  host: "dev.azure.com",
  path: "contoso",
  username: null,
};
const gcmUser: Source = {
  kind: "git_credential",
  host: "github.com",
  path: "me",
  username: "me",
};
const stored: Source = {
  kind: "stored",
  id: "tok-1",
  host: "dev.azure.com",
  org: "contoso",
};
const storedPlain: Source = { ...stored, host: "github.com", org: null };

describe("describing a source", () => {
  // The host words the same sources the same way (`SourceSpec::describe`, tested in puddle-api's
  // credentials HTTP tests and in puddle-secrets); a notice finds its credential by this text.
  it("matches the host's wording", () => {
    expect(describeSource(gh)).toBe("gh account tijs-work on github.com");
    expect(describeSource(gcm)).toBe(
      "Git credential for https://dev.azure.com/contoso",
    );
    expect(describeSource(gcmUser)).toBe(
      "Git credential for https://github.com/me (account me)",
    );
    expect(describeSource(stored)).toBe("stored token tok-1 for dev.azure.com");
  });

  it("labels a source for a chip", () => {
    expect(sourceLabel(gh)).toBe("gh · tijs-work");
    expect(sourceLabel(gcm)).toBe(
      "Git Credential Manager · dev.azure.com/contoso",
    );
    expect(sourceLabel(stored)).toBe("Pasted token · contoso");
    expect(sourceLabel(storedPlain)).toBe("Pasted token");
  });
});

describe("coverage", () => {
  it("says what a credential covers", () => {
    expect(coverageText({ owners: [], rest_of_host: true }, "github.com")).toBe(
      "the rest of github.com",
    );
    expect(coverageText({ owners: ["a", "b"], rest_of_host: false }, "h")).toBe(
      "a, b",
    );
    expect(coverageText({ owners: ["a"], rest_of_host: true }, "h")).toBe(
      "a and the rest of h",
    );
    expect(coverageText({ owners: [], rest_of_host: false }, "h")).toBe(
      "nothing",
    );
    expect(
      credentialChip(credential({ source: gh, owners: ["acme"], rest: false })),
    ).toBe("gh · tijs-work · github.com: acme");
  });

  it("parses owners as typed", () => {
    expect(parseOwners("Acme, acme-labs  acme")).toEqual({
      ok: true,
      owners: ["acme", "acme-labs"],
    });
    expect(parseOwners("")).toEqual({ ok: true, owners: [] });
    const bad = parseOwners("acme, bad/owner");
    expect(bad.ok).toBe(false);
    expect(!bad.ok && bad.message).toContain("bad/owner");
  });

  it("wants an owner or the rest of the host", () => {
    expect(coverageProblem({ owners: [], rest_of_host: false })).toMatch(
      /Name an owner/,
    );
    expect(coverageProblem({ owners: [], rest_of_host: true })).toBeNull();
    expect(coverageProblem({ owners: ["a"], rest_of_host: false })).toBeNull();
  });

  it("finds the identity that covers an owner, the exact owner first", () => {
    const work = identity(1, {
      credentials: [credential({ owners: ["acme"], rest: false })],
    });
    const personal = identity(2, { credentials: [credential({ rest: true })] });
    const azure = identity(3, {
      credentials: [
        credential({ host: "dev.azure.com", owners: ["contoso"], rest: false }),
      ],
    });
    expect(covering([personal, work], "github.com", "Acme")).toBe(work);
    expect(covering([personal, work], "GitHub.com", "other")).toBe(personal);
    expect(covering([work], "github.com", "other")).toBeNull();
    expect(covering([azure], "dev.azure.com", "contoso")).toBe(azure);
    expect(covering([], "github.com", "x")).toBeNull();
  });
});

describe("what a found account becomes", () => {
  const found = (over: Partial<FoundAccount>): FoundAccount => ({
    via: "gh",
    host: "github.com",
    account: "me",
    org: null,
    signed_in: true,
    ...over,
  });

  it("turns each listing into its source and its first coverage", () => {
    expect(sourceOf(found({}))).toEqual({
      kind: "gh",
      host: "github.com",
      account: "me",
    });
    expect(coverageOf(found({}))).toEqual({ owners: [], rest_of_host: true });
    expect(sourceOf(found({ via: "gcm_github" }))).toEqual(gcmUser);
    expect(coverageOf(found({ via: "gcm_github" }))).toEqual({
      owners: [],
      rest_of_host: true,
    });
    const azure = found({
      via: "gcm_azure_repos",
      host: "dev.azure.com",
      org: "Contoso",
    });
    // The path is the organisation as the helper lists it; what it covers is kept lower-case.
    expect(sourceOf(azure)).toEqual({ ...gcm, path: "Contoso" });
    expect(coverageOf(azure)).toEqual({
      owners: ["contoso"],
      rest_of_host: false,
    });
  });

  it("cannot use an Azure DevOps entry with no organisation", () => {
    const orphan = found({ via: "gcm_azure_repos", host: "dev.azure.com" });
    expect(sourceOf(orphan)).toBeNull();
    expect(coverageOf(orphan)).toEqual({ owners: [], rest_of_host: true });
  });

  it("words an account for a list", () => {
    expect(foundLabel(found({}))).toBe("me on github.com (GitHub CLI)");
    expect(
      foundLabel(
        found({
          via: "gcm_azure_repos",
          host: "dev.azure.com",
          org: "contoso",
        }),
      ),
    ).toBe("me on dev.azure.com/contoso (Git Credential Manager)");
  });
});

describe("checks", () => {
  it("reads a check result and words each state", () => {
    expect(
      checkOf({ readable: true, problem: null, needs_sign_in: false }),
    ).toEqual({
      state: "ok",
    });
    expect(
      checkOf({ readable: false, problem: "gone", needs_sign_in: true }),
    ).toEqual({
      state: "problem",
      message: "gone",
      needsSignIn: true,
    });
    expect(
      checkOf({ readable: false, problem: null, needs_sign_in: false }),
    ).toMatchObject({ message: "puddle can't read it" });
    const words = (c: Check) => statusWord(c);
    expect(words(UNTESTED)).toBe("Not tested");
    expect(words({ state: "checking" })).toBe("Checking…");
    expect(words({ state: "ok" })).toBe("OK");
    expect(words({ state: "problem", message: "", needsSignIn: true })).toBe(
      "Sign in needed",
    );
    expect(words({ state: "problem", message: "", needsSignIn: false })).toBe(
      "Problem",
    );
  });

  it("keys a check by host and source", () => {
    expect(credentialKey(credential({ source: gh }))).toBe(
      "github.com|gh account tijs-work on github.com",
    );
  });

  it("takes the worst of an identity's checks", () => {
    const ok: Check = { state: "ok" };
    const signIn: Check = { state: "problem", message: "", needsSignIn: true };
    const broken: Check = { state: "problem", message: "", needsSignIn: false };
    expect(identityStatus([])).toEqual(UNTESTED);
    expect(identityStatus([ok, ok])).toEqual(ok);
    expect(identityStatus([ok, UNTESTED])).toEqual(UNTESTED);
    expect(identityStatus([ok, { state: "checking" }, UNTESTED])).toEqual({
      state: "checking",
    });
    expect(identityStatus([ok, signIn, UNTESTED])).toEqual(signIn);
    expect(identityStatus([signIn, broken])).toEqual(broken);
  });
});

describe("what a form checks", () => {
  it("checks a name against the others", () => {
    expect(labelProblem("", [])).toMatch(/Give the identity a name/);
    expect(labelProblem("x".repeat(65), [])).toMatch(/at most 64/);
    expect(labelProblem(" work ", ["Work"])).toMatch(/already called work/);
    expect(labelProblem("Work", ["Personal"])).toBeNull();
  });

  it("checks the author", () => {
    expect(authorProblem("", "a@b")).toMatch(/name/);
    expect(authorProblem("A", "")).toMatch(/email/);
    expect(authorProblem("A", "a b@c")).toMatch(/@/);
    expect(authorProblem("A", "no-at-sign")).toMatch(/@/);
    expect(authorProblem("A", "a@b.example")).toBeNull();
  });

  it("reports the first problem of an identity, with its field", () => {
    const ok = { label: "Work", name: "A", email: "a@b.example" };
    expect(identityProblem(ok, [])).toBeNull();
    expect(identityProblem({ ...ok, label: "" }, [])?.field).toBe("label");
    expect(identityProblem({ ...ok, name: " " }, [])?.field).toBe("name");
    expect(identityProblem({ ...ok, email: "x" }, [])?.field).toBe("email");
    expect(identityProblem({ ...ok, email: "" }, [])?.field).toBe("email");
  });

  it("checks a pasted token's host, organisation and value", () => {
    expect(hostProblem("")).toMatch(/Enter the Git host/);
    expect(hostProblem("nodots")).toMatch(/not a host/);
    expect(hostProblem("bad host.com")).toMatch(/not a host/);
    expect(hostProblem("github.com")).toBeNull();
    expect(orgProblem("")).toMatch(/organisation/);
    expect(orgProblem("contoso")).toBeNull();
    expect(tokenProblem("")).toMatch(/Paste/);
    expect(tokenProblem("a b")).toMatch(/no spaces/);
    expect(tokenProblem(" ghp_x ")).toBeNull();
    expect(needsOrg(" Dev.Azure.com ")).toBe(true);
    expect(needsOrg("github.com")).toBe(false);
  });
});

describe("small helpers", () => {
  it("moves an item one place", () => {
    expect(moved([1, 2, 3], 2, -1)).toEqual([2, 1, 3]);
    expect(moved([1, 2, 3], 2, 1)).toEqual([1, 3, 2]);
    expect(moved([1, 2, 3], 1, -1)).toEqual([1, 2, 3]);
    expect(moved([1, 2, 3], 3, 1)).toEqual([1, 2, 3]);
    expect(moved([1, 2, 3], 9, 1)).toEqual([1, 2, 3]);
  });

  it("says how many workspaces use an identity", () => {
    expect(usedBy(identity(1))).toBe("Not used yet");
    expect(usedBy(identity(1, { workspaces: ["a"] }))).toBe(
      "Used by 1 workspace",
    );
    expect(usedBy(identity(1, { workspaces: ["a", "b"] }))).toBe(
      "Used by 2 workspaces",
    );
  });

  it("makes the request that saves an identity as it is", () => {
    const one = identity(1);
    expect(requestOf(one)).toEqual({
      label: one.label,
      author: one.author,
      credentials: one.credentials,
    });
    expect(requestOf(one, []).credentials).toEqual([]);
  });
});
