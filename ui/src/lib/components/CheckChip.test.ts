// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import type { Check } from "#lib/identities/model.ts";
import CheckChip from "./CheckChip.svelte";

afterEach(cleanup);

describe("CheckChip", () => {
  it.each<[Check, string]>([
    [{ state: "untested" }, "Not tested"],
    [{ state: "checking" }, "Checking…"],
    [{ state: "ok" }, "OK"],
    [{ state: "problem", message: "x", needsSignIn: true }, "Sign in needed"],
    [{ state: "problem", message: "x", needsSignIn: false }, "Problem"],
  ])("says %j in words", (check, word) => {
    render(CheckChip, { check });
    expect(screen.getByText(word)).toHaveAttribute("data-check", check.state);
  });
});
