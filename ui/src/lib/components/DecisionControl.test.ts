// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Choice, Target } from "#lib/decision/model.ts";
import DecisionControl from "./DecisionControl.svelte";

afterEach(cleanup);

const target: Target = {
  host: "api.example.com",
  registrableDomain: "example.com",
};

function mount(props: Record<string, unknown> = {}) {
  const onDecide = vi.fn<(choice: Choice) => void>();
  const onMore = vi.fn<(anchor: HTMLElement) => void>();
  render(DecisionControl, {
    props: { target, workspace: "demo", onDecide, onMore, ...props },
  } as never);
  return { onDecide, onMore };
}

describe("the one-click buttons", () => {
  it("Allow and Deny decide for this workspace, the exact host, permanently", async () => {
    const { onDecide } = mount();
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow api.example.com for demo" }),
    );
    await fireEvent.click(
      screen.getByRole("button", { name: "Deny api.example.com for demo" }),
    );
    const narrow = {
      scope: "workspace",
      ruleSet: null,
      match: "exact",
      durationSecs: null,
    };
    expect(onDecide).toHaveBeenNthCalledWith(1, { effect: "allow", ...narrow });
    expect(onDecide).toHaveBeenNthCalledWith(2, { effect: "deny", ...narrow });
  });

  it("the chevron hands its own element to the parent and shows whether the options are open", async () => {
    const { onMore } = mount();
    const chevron = screen.getByRole("button", {
      name: "More choices for api.example.com",
    });
    expect(chevron).toHaveAttribute("aria-haspopup", "dialog");
    expect(chevron).toHaveAttribute("aria-expanded", "false");
    await fireEvent.click(chevron);
    expect(onMore).toHaveBeenCalledWith(chevron);
    cleanup();
    mount({ optionsOpen: true });
    expect(
      screen.getByRole("button", { name: /^More choices/ }),
    ).toHaveAttribute("aria-expanded", "true");
  });

  it("offers only Deny when the request can't be approved yet", () => {
    mount({ denyOnly: true });
    expect(screen.queryByRole("button", { name: /^Allow/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /More choices/ })).toBeNull();
    expect(screen.getByRole("button", { name: /^Deny/ })).toBeInTheDocument();
  });

  it("keeps the word workspace in the labels, never sandbox", () => {
    mount();
    expect(document.body.textContent).not.toMatch(/sandbox/i);
    for (const button of screen.getAllByRole("button")) {
      expect(button.getAttribute("aria-label") ?? "").not.toMatch(/sandbox/i);
      expect(button.getAttribute("title") ?? "").not.toMatch(/sandbox/i);
    }
  });
});
