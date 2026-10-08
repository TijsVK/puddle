// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const nav = vi.hoisted(() => ({ search: "" }));
vi.mock("$app/state", () => ({
  page: {
    get url() {
      return new URL(`http://127.0.0.1/welcome/check${nav.search}`);
    },
  },
}));

const api = await vi.hoisted(async () => {
  const mod = await import("#lib/testing/fake-first-run.ts");
  return new mod.FakeFirstRun();
});
vi.mock("#lib/api/client.ts", () => ({ api }));

import { brokenReport, healthyReport } from "#lib/testing/fake-first-run.ts";
import { doctor } from "#lib/stores/doctor.svelte.ts";
import Page from "./+page.svelte";

const writeText = vi.fn(async (_text: string) => undefined);

beforeEach(() => {
  nav.search = "";
  api.calls = [];
  api.report = healthyReport();
  api.doctorStatus = 200;
  api.down = false;
  api.hold = null;
  doctor.status = "idle";
  doctor.report = null;
  writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
});
afterEach(cleanup);

const runs = () => api.calls.filter((c) => c === "GET /api/doctor").length;
const link = (name: string) => screen.queryByRole("link", { name });

describe("system check step", () => {
  it("runs the checks when it opens, says so meanwhile, and focuses its heading", async () => {
    let release = () => {};
    api.hold = new Promise<void>((resolve) => (release = resolve));
    render(Page);
    const heading = screen.getByRole("heading", {
      level: 1,
      name: "System check",
    });
    expect(document.activeElement).toBe(heading);
    expect(screen.getByText(/Checking this computer/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Copy report" })).toBeNull();
    release();
    await screen.findByText("No problems found.");
    expect(runs()).toBe(1);
  });

  it("lists each check with its state in words, and goes on when nothing failed", async () => {
    api.report = healthyReport({ elapsed_ms: 2300 });
    render(Page);
    const list = await screen.findByRole("list", { name: "Checks" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent("OK: CPU virtualization");
    expect(items[2]).toHaveTextContent("booted in 1.4 s");
    expect(screen.getByRole("status")).toHaveTextContent(
      "No problems found. Checked in 2.3 s.",
    );
    expect(link("Continue")).toHaveAttribute("href", "/welcome/certificates");
    expect(link("Back")).toHaveAttribute("href", "/welcome");
    expect(link("Leave setup for now")).toBeNull();
  });

  it("shows a warning's note without blocking", async () => {
    const report = healthyReport();
    report.checks[0] = {
      ...report.checks[0]!,
      status: "warn",
      summary: "a client is installed",
      fix: "Nothing to do.",
    };
    api.report = report;
    render(Page);
    await screen.findByText(/No problems found; 1 warning to know about/);
    expect(screen.getByText("Note:")).toBeInTheDocument();
    expect(screen.getByText("Nothing to do.")).toBeInTheDocument();
    expect(screen.getByText("Warning:")).toBeInTheDocument();
    expect(link("Continue")).toBeInTheDocument();
  });

  it("blocks on a failed check: shows the fix and the evidence, offers no Continue", async () => {
    api.report = brokenReport();
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "1 problem to fix before puddle can run workspaces.",
    );
    expect(screen.getByText("Fix:")).toBeInTheDocument();
    expect(
      screen.getByText("Turn on virtualization in your UEFI setup."),
    ).toBeInTheDocument();
    expect(screen.getByText("Problem:")).toBeInTheDocument();
    expect(screen.getByText("Not checked:")).toBeInTheDocument();
    const details = screen.getByLabelText("Technical details of Hypervisor");
    expect(details).toHaveTextContent("No such file or directory");
    expect(details).toHaveAttribute("tabindex", "0");
    expect(link("Continue")).toBeNull();
    expect(screen.queryByRole("button", { name: "Continue" })).toBeNull();
    // Leaving does not mark the flow done: it comes back at the next start.
    expect(link("Leave setup for now")).toHaveAttribute("href", "/workspaces");
    expect(
      screen.getByText(/comes back the next time you open puddle/),
    ).toBeVisible();
  });

  it("checks again and lets the user on once the problem is fixed", async () => {
    api.report = brokenReport();
    render(Page);
    await screen.findByText(/1 problem to fix/);
    api.report = healthyReport();
    await fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    await screen.findByText("No problems found.");
    expect(runs()).toBe(2);
    expect(link("Continue")).toBeInTheDocument();
  });

  it("copies the report as JSON with its schema version, and says when copying is refused", async () => {
    api.report = brokenReport();
    render(Page);
    await screen.findByText(/1 problem to fix/);
    await fireEvent.click(screen.getByRole("button", { name: "Copy report" }));
    expect(await screen.findByText("Report copied.")).toBeInTheDocument();
    const copied = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      schema_version: number;
      checks: { finding: string | null }[];
    };
    expect(copied.schema_version).toBe(1);
    expect(copied.checks[1]?.finding).toBe("kvm_missing");

    writeText.mockRejectedValueOnce(new Error("denied"));
    await fireEvent.click(screen.getByRole("button", { name: "Copy report" }));
    expect(await screen.findByText(/didn't let puddle copy/)).toHaveAttribute(
      "role",
      "alert",
    );
    expect(screen.queryByText("Report copied.")).toBeNull();
    // A new run forgets the old copy message.
    await fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() =>
      expect(screen.queryByText(/didn't let puddle copy/)).toBeNull(),
    );
  });

  it("says plainly when this puddle has no system check, and lets the user go on", async () => {
    api.doctorStatus = 503;
    render(Page);
    expect(await screen.findByText(/can't run the system check/)).toBeVisible();
    expect(link("Continue")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy report" })).toBeNull();
  });

  it("says when the service doesn't answer, and lets the user go on and try again", async () => {
    api.down = true;
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /couldn't run the system check: puddle's service isn't answering/,
    );
    expect(link("Continue")).toBeInTheDocument();
    api.down = false;
    await fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    await screen.findByText("No problems found.");
  });

  it("gives puddle's own reason when the check itself fails", async () => {
    api.doctorStatus = 500;
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "puddle couldn't run the system check: not here",
    );
    expect(link("Continue")).toBeInTheDocument();
  });

  it("keeps the result when the user comes back from a later step", async () => {
    render(Page);
    await screen.findByText("No problems found.");
    cleanup();
    render(Page);
    expect(screen.getByText("No problems found.")).toBeInTheDocument();
    expect(runs()).toBe(1);
  });

  it("opened from Settings it runs afresh and leads back to Settings, with no step Back", async () => {
    render(Page);
    await screen.findByText("No problems found.");
    cleanup();
    nav.search = "?from=settings";
    render(Page);
    await waitFor(() => expect(runs()).toBe(2));
    await screen.findByText("No problems found.");
    expect(link("Back to Settings")).toHaveAttribute("href", "/settings");
    expect(link("Back")).toBeNull();
    expect(link("Continue")).toBeNull();
  });

  it("opened from Settings with a problem, offers no setup text", async () => {
    nav.search = "?from=settings";
    api.report = brokenReport();
    render(Page);
    await screen.findByText(/1 problem to fix/);
    expect(link("Back to Settings")).toBeInTheDocument();
    expect(link("Leave setup for now")).toBeNull();
    expect(screen.queryByText(/comes back the next time/)).toBeNull();
  });
});
