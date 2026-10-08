// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, render, screen } from "@testing-library/svelte";
import { fireEvent } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { describeSource } from "#lib/identities/model.ts";
import { IdentitiesStore } from "#lib/stores/identities.svelte.ts";
import {
  credential,
  FakeIdentities,
  ghSource,
} from "#lib/testing/fake-identities.ts";
import SignInDialog from "./SignInDialog.svelte";

let api: FakeIdentities;
let store: IdentitiesStore;
const cred = credential({ source: ghSource("tijs") });
const CODE = { code: "ABCD-1234", url: "https://github.com/login/device" };

beforeEach(() => {
  vi.useFakeTimers();
  api = new FakeIdentities();
  api.unreadable.add(describeSource(cred.source));
  store = new IdentitiesStore({ api: api as never });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function mount(over: Record<string, unknown> = {}) {
  const onSignedIn = vi.fn();
  render(SignInDialog, {
    open: true,
    credential: cred,
    start: CODE,
    error: null,
    store,
    onSignedIn,
    pollMs: 1000,
    windowMs: 5000,
    ...over,
  } as never);
  return onSignedIn;
}

describe("the sign-in dialog", () => {
  it("shows the one-time code and a safe link to the address", () => {
    mount();
    expect(screen.getByTestId("sign-in-code")).toHaveTextContent("ABCD-1234");
    const link = screen.getByRole("link", { name: CODE.url });
    expect(link).toHaveAttribute("href", CODE.url);
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "gh account tijs on github.com",
    );
  });

  it("asks the credential until it reads, then says so", async () => {
    const done = mount();
    await vi.advanceTimersByTimeAsync(1100);
    expect(done).not.toHaveBeenCalled();
    api.unreadable.clear();
    await vi.advanceTimersByTimeAsync(1100);
    expect(done).toHaveBeenCalledOnce();
    expect(screen.getByText("Signed in.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Done" })).toBeInTheDocument();
    const calls = api.calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.calls.length).toBe(calls);
  });

  it("gives up after its window and says so", async () => {
    mount();
    await vi.advanceTimersByTimeAsync(6500);
    expect(screen.getByText(/wasn't finished in time/)).toBeInTheDocument();
  });

  it("stops asking when it is closed", async () => {
    mount();
    await fireEvent.click(screen.getByRole("button", { name: "Close" }));
    const calls = api.calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.calls.length).toBe(calls);
  });

  it("tells a helper-window sign-in from a code sign-in", () => {
    mount({ start: { code: null, url: null } });
    expect(
      screen.getByText(/Finish signing in in the window that opened/),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("sign-in-code")).toBeNull();
  });

  it("says it is starting, and why it could not", () => {
    mount({ start: null });
    expect(screen.getByRole("status")).toHaveTextContent(
      "Starting the sign-in",
    );
    cleanup();
    mount({ start: null, error: "gh is not installed or not on PATH." });
    expect(screen.getByRole("alert")).toHaveTextContent("gh is not installed");
    expect(api.calls).toEqual([]);
  });

  it("asks nothing before it has a credential", () => {
    mount({ credential: null });
    expect(api.calls).toEqual([]);
  });
});
