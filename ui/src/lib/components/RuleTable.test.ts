// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { rule } from "#lib/testing/fake-rules.ts";
import { DEFAULT_SORT } from "#lib/rules/model.ts";
import RuleTable from "./RuleTable.svelte";

afterEach(cleanup);

const rules = [
  rule(1, { pattern: "a.example.com" }),
  rule(2, { pattern: "b.example.com" }),
];

describe("RuleTable", () => {
  it("is read-only without handlers: plain headers and no action buttons", () => {
    render(RuleTable, { props: { rules, sort: DEFAULT_SORT, now: 5_000_000 } });
    expect(screen.getAllByRole("columnheader")).toHaveLength(5);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(screen.getByText("a.example.com")).toBeInTheDocument();
  });

  it("sorts, changes expiry and deletes through its handlers when it has them", async () => {
    const onSort = vi.fn();
    const onExpiry = vi.fn();
    const onDelete = vi.fn();
    render(RuleTable, {
      props: {
        rules,
        sort: DEFAULT_SORT,
        now: 5_000_000,
        onSort,
        onExpiry,
        onDelete,
      },
    });
    expect(screen.getAllByRole("columnheader")).toHaveLength(6);
    await fireEvent.click(screen.getByRole("button", { name: "Sort by host" }));
    expect(onSort).toHaveBeenCalledWith("pattern");
    await fireEvent.click(
      screen.getAllByRole("button", { name: /^Change expiry/ })[0]!,
    );
    expect(onExpiry).toHaveBeenCalledWith(rules[0], expect.any(HTMLElement));
    await fireEvent.click(
      screen.getAllByRole("button", { name: /^Delete rule/ })[0]!,
    );
    expect(onDelete).toHaveBeenCalledWith(rules[0], expect.any(HTMLElement));
  });
});
