// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Choice, Target } from "#lib/decision/model.ts";
import OptionsPopover from "./OptionsPopover.svelte";

afterEach(cleanup);

const target: Target = {
  host: "api.example.com",
  registrableDomain: "example.com",
};

/** jsdom has no layout, so floating-ui never marks the popover positioned; show it by hand. */
async function show(): Promise<HTMLElement> {
  const dialog = await screen.findByRole("dialog", { hidden: true });
  const wrapper = dialog.parentElement;
  if (wrapper) wrapper.style.visibility = "visible";
  return dialog;
}

function mount(props: Record<string, unknown> = {}) {
  const onDecide = vi.fn<(choice: Choice) => void>();
  const onClose = vi.fn();
  const anchor = document.createElement("button");
  document.body.append(anchor);
  render(OptionsPopover, {
    props: {
      open: true,
      target,
      workspace: "demo",
      anchor,
      onDecide,
      onClose,
      ...props,
    },
  } as never);
  return { onDecide, onClose, anchor };
}

describe("OptionsPopover", () => {
  it("is a named dialog that starts at the narrowest choice and lists the durations", async () => {
    mount();
    const dialog = await show();
    expect(dialog).toHaveAccessibleName("Choices for api.example.com");
    expect(
      within(dialog).getByRole("radio", { name: /^Only demo/ }),
    ).toBeChecked();
    expect(
      within(dialog).getByRole("radio", { name: /^Only api\.example\.com/ }),
    ).toBeChecked();
    const select = within(dialog).getByRole("combobox", { name: "How long" });
    expect(select).toHaveValue("0");
    expect(
      within(select)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Permanently", "1 hour", "8 hours", "1 day", "7 days"]);
  });

  it("sends every workspace, the registrable domain as a suffix and a duration", async () => {
    const { onDecide } = mount();
    const dialog = await show();
    await fireEvent.click(
      within(dialog).getByRole("radio", { name: /^Every workspace/ }),
    );
    await fireEvent.click(
      within(dialog).getByRole("radio", {
        name: /^Everything under example\.com/,
      }),
    );
    await fireEvent.change(within(dialog).getByRole("combobox"), {
      target: { value: "28800" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: /Deny/ }));
    expect(onDecide).toHaveBeenCalledWith({
      effect: "deny",
      scope: "global",
      match: "suffix",
      durationSecs: 28_800,
    });
  });

  it("starts from the narrowest choice every time it opens", async () => {
    mount();
    let dialog = await show();
    await fireEvent.click(
      within(dialog).getByRole("radio", { name: /^Every workspace/ }),
    );
    cleanup();
    mount();
    dialog = await show();
    expect(
      within(dialog).getByRole("radio", { name: /^Only demo/ }),
    ).toBeChecked();
  });

  it("closes with Cancel and Escape without deciding, and focuses the anchor again", async () => {
    const { onDecide, onClose, anchor } = mount();
    const dialog = await show();
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    await vi.waitFor(() => expect(anchor).toHaveFocus());
    onClose.mockClear();
    await fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onDecide).not.toHaveBeenCalled();
  });

  it("offers no subdomain choice for the registrable domain itself or an exact-only request", async () => {
    mount({
      target: { host: "example.com", registrableDomain: "example.com" },
    });
    expect(
      within(await show()).queryByRole("radio", { name: /Everything under/ }),
    ).toBeNull();
    cleanup();
    mount({ exactOnly: true });
    expect(
      within(await show()).queryByRole("radio", { name: /Everything under/ }),
    ).toBeNull();
  });

  it("renders nothing while closed", () => {
    mount({ open: false });
    expect(screen.queryByRole("dialog", { hidden: true })).toBeNull();
  });
});
