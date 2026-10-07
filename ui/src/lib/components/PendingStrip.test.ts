// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import PendingStrip from "./PendingStrip.svelte";

afterEach(cleanup);

describe("PendingStrip", () => {
  it("is not there when nothing waits", () => {
    const { container } = render(PendingStrip, { props: { count: 0 } });
    expect(container.textContent?.trim()).toBe("");
  });

  it("counts, says what is asking and links to the inbox", () => {
    render(PendingStrip, {
      props: {
        count: 3,
        latest: { workspace: "web-shop", host: "cdn.example.org", port: 443 },
      },
    });
    const strip = screen.getByRole("status");
    expect(strip).toHaveTextContent("3 requests waiting.");
    expect(strip).toHaveTextContent("web-shop wants cdn.example.org:443");
    expect(screen.getByRole("link", { name: "Review" })).toHaveAttribute(
      "href",
      "/inbox",
    );
  });

  it("says one request in the singular, and manages without a latest one", () => {
    render(PendingStrip, { props: { count: 1 } });
    expect(screen.getByRole("status")).toHaveTextContent("1 request waiting.");
    expect(screen.getByRole("status")).not.toHaveTextContent("Latest");
  });
});
