// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  credential,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { repoSource } from "#lib/testing/fake-repos.ts";
import RepoSourceStatus from "./RepoSourceStatus.svelte";

afterEach(cleanup);

const NOW = 10_000_000;
const me = identity(1, {
  label: "Work",
  credentials: [credential({ source: ghSource("tijs-work") })],
});

function show(
  source = repoSource(),
  over: Record<string, unknown> = {},
  who = me,
) {
  const onSignIn = vi.fn();
  render(RepoSourceStatus, {
    props: { source, identity: who, now: NOW, onSignIn, ...over },
  } as never);
  return { onSignIn };
}

describe("RepoSourceStatus", () => {
  it("names the sign-in, says the list is up to date and how many it holds", () => {
    show(repoSource({ repo_count: 4, refreshed_at: NOW - 120_000 }));
    expect(screen.getByText("gh · tijs-work on github.com")).toBeVisible();
    expect(screen.getByText("Up to date")).toBeVisible();
    expect(
      screen.getByText(/4 repositories, read 2 minutes ago/),
    ).toBeVisible();
  });

  it("shows every note the host sent, as text", () => {
    show(
      repoSource({
        notes: [
          { code: "sso_partial", message: "Some organisations are missing." },
          {
            code: "truncated",
            message: "<img src=x onerror=alert(1)> more exist",
          },
        ],
      }),
    );
    expect(screen.getByText("Some organisations are missing.")).toBeVisible();
    expect(
      screen.getByText("<img src=x onerror=alert(1)> more exist"),
    ).toBeVisible();
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows why a list failed, with the way out, and signs in on a click", async () => {
    const { onSignIn } = show(
      repoSource({
        state: "failed",
        problem: {
          code: "not_signed_in",
          message: "Not signed in. Sign in again.",
          needs_sign_in: true,
        },
      }),
    );
    expect(screen.getByText("Not read")).toBeVisible();
    expect(screen.getByText(/Not signed in\. Sign in again\./)).toBeVisible();
    await fireEvent.click(
      screen.getByRole("button", {
        name: "Sign in to gh · tijs-work on github.com",
      }),
    );
    expect(onSignIn).toHaveBeenCalledWith(0);
  });

  it("offers no sign-in for a pasted token, where there is none to run", () => {
    show(
      repoSource({
        state: "failed",
        problem: {
          code: "token_rejected",
          message: "GitHub rejected the token.",
          needs_sign_in: true,
        },
      }),
      {},
      identity(1, {
        credentials: [
          credential({
            source: { kind: "stored", id: "t", host: "github.com", org: null },
          }),
        ],
      }),
    );
    expect(screen.getByText(/GitHub rejected the token/)).toBeVisible();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("offers no sign-in where the screen has none, or when signing in is not the way out", () => {
    show(
      repoSource({
        state: "unavailable",
        problem: {
          code: "organisation_needed",
          message: "Name the organisation.",
          needs_sign_in: false,
        },
      }),
    );
    expect(screen.getByText("Can't be listed")).toBeVisible();
    expect(screen.queryByRole("button")).toBeNull();
    cleanup();
    show(
      repoSource({
        state: "failed",
        problem: {
          code: "not_signed_in",
          message: "Sign in.",
          needs_sign_in: true,
        },
      }),
      { onSignIn: undefined },
    );
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("says when puddle asks again after a limit, and that the list shown is old", () => {
    show(
      repoSource({
        state: "stale",
        refreshed_at: NOW - 900_000,
        retry_at: NOW + 600_000,
        repo_count: 2,
        problem: {
          code: "rate_limited",
          message: "GitHub asked puddle to wait.",
          needs_sign_in: false,
        },
      }),
    );
    expect(screen.getByText("Old list")).toBeVisible();
    expect(screen.getByText(/puddle asks again in 10 minutes/)).toBeVisible();
    expect(screen.getByText(/GitHub asked puddle to wait/)).toBeVisible();
  });
});
