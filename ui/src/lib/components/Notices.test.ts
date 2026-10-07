// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import { NoticeCenter } from "#lib/notify/notices.svelte.ts";
import Notices from "./Notices.svelte";

afterEach(cleanup);

function setup(count = 0) {
  const center = new NoticeCenter();
  for (let i = 1; i <= count; i += 1) {
    center.add({
      key: `k${i}`,
      tone: i % 2 ? "warning" : "info",
      title: `Title ${i}`,
      ...(i === 1
        ? { detail: "More words", link: { href: "/x", label: "Go there" } }
        : {}),
    });
  }
  render(Notices, { center });
  return center;
}

describe("Notices", () => {
  it("keeps an empty polite live region, so a notice that arrives is announced", async () => {
    const center = setup();
    const region = screen.getByRole("region", { name: "Notices" });
    expect(region.querySelector("[aria-live=polite]")).not.toBeNull();
    center.add({ key: "a", tone: "info", title: "Hello" });
    expect(await screen.findByText("Hello")).toBeInTheDocument();
    expect(document.activeElement).toBe(document.body);
  });

  it("shows title, detail and link as text, newest first", () => {
    setup(2);
    expect(screen.getByText("More words")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go there" })).toHaveAttribute(
      "href",
      "/x",
    );
    const titles = screen.getAllByText(/^Title/).map((e) => e.textContent);
    expect(titles).toEqual(["Title 2", "Title 1"]);
  });

  it("never draws a title as markup", () => {
    const center = setup();
    center.add({
      key: "a",
      tone: "info",
      title: "<img src=x onerror=alert(1)>",
    });
    expect(document.querySelector("img")).toBeNull();
  });

  it("dismisses one notice and moves focus to a neighbour, or to the page when none is left", async () => {
    document.body.insertAdjacentHTML(
      "beforeend",
      '<main id="main" tabindex="-1"></main>',
    );
    const center = setup(2);
    const buttons = screen.getAllByRole("button", { name: /^Dismiss notice/ });
    expect(buttons[0]).toHaveAccessibleName("Dismiss notice: Title 2");
    await fireEvent.click(buttons[0]!);
    expect(center.items.map((n) => n.key)).toEqual(["k1"]);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Dismiss notice: Title 1" }),
    );
    await fireEvent.click(document.activeElement!);
    expect(center.items).toEqual([]);
    expect(document.activeElement).toBe(document.getElementById("main"));
    document.getElementById("main")?.remove();
  });

  it("folds a long list and offers to show all or dismiss all", async () => {
    const center = setup(5);
    expect(screen.getAllByText(/^Title/)).toHaveLength(3);
    const toggle = screen.getByRole("button", { name: "Show all 5 notices" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await fireEvent.click(toggle);
    expect(screen.getAllByText(/^Title/)).toHaveLength(5);
    await fireEvent.click(screen.getByRole("button", { name: "Show fewer" }));
    expect(screen.getAllByText(/^Title/)).toHaveLength(3);
    await fireEvent.click(screen.getByRole("button", { name: "Dismiss all" }));
    expect(center.items).toEqual([]);
  });
});
