// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import StatusChip from "./StatusChip.svelte";

afterEach(cleanup);

describe("StatusChip", () => {
  it.each([
    ["created", "Not started"],
    ["running", "Running"],
    ["draining", "Stopping"],
    ["crashed", "Crashed"],
    ["volume_missing", "Volume missing"],
  ] as const)("says %s in words", (status, label) => {
    render(StatusChip, { props: { status } });
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("says what is being done while an operation runs, not the state", () => {
    render(StatusChip, { props: { status: "stopped", busy: "deleting" } });
    expect(screen.getByText("Deleting")).toHaveClass("busy");
    expect(screen.queryByText("Stopped")).toBeNull();
  });

  it("keeps the colour out of the accessible name: the dot is hidden from readers", () => {
    const { container } = render(StatusChip, { props: { status: "running" } });
    expect(container.querySelector(".dot")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    expect(screen.getByText("Running")).toHaveClass("ok");
  });
});
