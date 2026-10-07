// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = await vi.hoisted(async () => {
  const fakes = await import("#lib/testing/fake-audit.ts");
  const inbox = await import("#lib/testing/fake-inbox.ts");
  return {
    api: new fakes.FakeAudit(),
    source: new inbox.FakeSource(),
    connection: fakes.connection,
    replaceState: vi.fn(),
  };
});

vi.mock("$app/navigation", () => ({ replaceState: h.replaceState }));
vi.mock("#lib/stores/audit.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/audit.svelte.ts")>();
  return {
    ...mod,
    auditStore: new mod.AuditStore({ api: h.api as never, source: h.source }),
  };
});

import { auditStore } from "#lib/stores/audit.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import ActivityPage from "./+page.svelte";

const { api, source, connection, replaceState } = h;

function seed() {
  const now = Date.now();
  api.workspaces = ["shop", "api"];
  api.entries = [
    connection(1, {
      sandbox_id: "shop",
      host: "github.com",
      ts: now - 1000,
    }),
    connection(2, {
      sandbox_id: "api",
      host: "evil.test",
      decision: "deny",
      ts: now - 900,
    }),
    connection(3, {
      sandbox_id: "shop",
      host: "crates.io",
      ts: now - 800,
    }),
  ];
}

beforeEach(() => {
  seed();
  api.queries = [];
  api.down = false;
  api.failNext = null;
  replaceState.mockClear();
  window.history.replaceState({}, "", "/activity");
  auditStore.status = "loading";
  auditStore.entries = [];
  auditStore.held = [];
  auditStore.live = true;
  auditStore.following = true;
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

const rows = () => document.querySelectorAll("tbody tr.row");
const hosts = () =>
  [...rows()].map((r) => r.querySelectorAll("td")[3]?.textContent?.trim());

async function open() {
  render(ActivityPage);
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
}

describe("the activity page", () => {
  it("reads the newest records for the default range and shows them", async () => {
    await open();
    expect(
      screen.getByRole("heading", { level: 1, name: "Activity" }),
    ).toBeInTheDocument();
    expect(hosts()).toEqual([
      "crates.io:443",
      "evil.test:443",
      "github.com:443",
    ]);
    expect(api.queries[0]?.from).toBeGreaterThan(0);
    expect(screen.getByText(/3\s+records/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
  });
  it("says it is loading first", () => {
    render(ActivityPage);
    expect(screen.getByText(/Loading activity/)).toBeInTheDocument();
  });
  it("starts from the filters in the address", async () => {
    window.history.replaceState(
      {},
      "",
      "/activity?workspace=shop&type=connection&outcome=allow&host=git&range=all",
    );
    await open();
    expect(api.queries[0]).toMatchObject({
      sandbox: "shop",
      type: "connection",
      outcome: "allow",
      host_contains: "git",
      limit: 200,
    });
    expect(api.queries[0]?.from).toBeUndefined();
    expect(hosts()).toEqual(["github.com:443"]);
    expect(screen.getByLabelText("Host contains")).toHaveValue("git");
    expect(screen.getByLabelText("Workspace")).toHaveValue("shop");
    expect(screen.getByLabelText("Time range")).toHaveValue("all");
  });
  it("offers the workspaces, and one the address names that no longer exists", async () => {
    window.history.replaceState({}, "", "/activity?workspace=gone");
    render(ActivityPage);
    await waitFor(() =>
      expect(
        [...screen.getByLabelText("Workspace").querySelectorAll("option")].map(
          (o) => o.textContent,
        ),
      ).toEqual(["All workspaces", "api", "gone", "shop"]),
    );
  });
  it("reads again on a select change and keeps the address in step", async () => {
    await open();
    await fireEvent.change(screen.getByLabelText("Outcome"), {
      target: { value: "deny" },
    });
    await waitFor(() => expect(hosts()).toEqual(["evil.test:443"]));
    expect(api.queries.at(-1)).toMatchObject({ outcome: "deny" });
    expect(replaceState).toHaveBeenLastCalledWith("/activity?outcome=deny", {});
    await fireEvent.change(screen.getByLabelText("Time range"), {
      target: { value: "7d" },
    });
    await fireEvent.change(screen.getByLabelText("Type"), {
      target: { value: "connection" },
    });
    await waitFor(() =>
      expect(replaceState).toHaveBeenLastCalledWith(
        "/activity?type=connection&outcome=deny&range=7d",
        {},
      ),
    );
  });
  it("waits for a pause in typing before it reads the host filter", async () => {
    await open();
    const asked = api.queries.length;
    const host = screen.getByLabelText("Host contains");
    await fireEvent.input(host, { target: { value: "c" } });
    await fireEvent.input(host, { target: { value: "crates" } });
    expect(api.queries).toHaveLength(asked);
    await waitFor(() => expect(hosts()).toEqual(["crates.io:443"]));
    expect(api.queries).toHaveLength(asked + 1);
    expect(replaceState).toHaveBeenLastCalledWith("/activity?host=crates", {});
  });
  it("reads at once on Enter in the host field", async () => {
    await open();
    const host = screen.getByLabelText("Host contains");
    await fireEvent.input(host, { target: { value: "evil" } });
    await fireEvent.submit(screen.getByRole("search"));
    await waitFor(() => expect(hosts()).toEqual(["evil.test:443"]));
  });
  it("clears the filters back to the default view", async () => {
    window.history.replaceState({}, "", "/activity?workspace=api&range=all");
    await open();
    await fireEvent.click(
      screen.getByRole("button", { name: "Clear filters" }),
    );
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(replaceState).toHaveBeenLastCalledWith("/activity", {});
    expect(screen.getByLabelText("Workspace")).toHaveValue("");
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
  });
  it("still works when the address cannot be updated yet", async () => {
    replaceState.mockImplementationOnce(() => {
      throw new Error("router not ready");
    });
    await open();
    await fireEvent.change(screen.getByLabelText("Outcome"), {
      target: { value: "allow" },
    });
    await waitFor(() => expect(hosts()).toHaveLength(2));
  });

  describe("when there is nothing to show", () => {
    it("says what a filter found", async () => {
      window.history.replaceState({}, "", "/activity?host=nothing-like-it");
      render(ActivityPage);
      await screen.findByText("No records match");
      expect(screen.getByText(/in last 24 hours matches/)).toBeInTheDocument();
    });
    it("says nothing has been recorded when no filter is set", async () => {
      api.entries = [];
      window.history.replaceState({}, "", "/activity?range=all");
      render(ActivityPage);
      await screen.findByText("Nothing recorded yet");
      expect(screen.getByText(/0\s+records/)).toBeInTheDocument();
    });
    it("offers to try again when the log can't be read", async () => {
      api.down = true;
      render(ActivityPage);
      await screen.findByText(/Couldn't read the activity log/);
      api.down = false;
      await fireEvent.click(screen.getByRole("button", { name: "Try again" }));
      await waitFor(() => expect(rows()).toHaveLength(3));
    });
  });

  describe("live", () => {
    it("adds a record that arrives while the page is at the top", async () => {
      await open();
      api.entries.push(connection(4, { host: "new.test", ts: Date.now() }));
      source.emit({ type: "audit_appended", id: 4 });
      await waitFor(() => expect(hosts()[0]).toBe("new.test:443"));
    });
    it("holds records back once the user scrolls away, and shows them on request", async () => {
      await open();
      const region = screen.getByRole("region", { name: "Activity records" });
      region.scrollTop = 200;
      await fireEvent.scroll(region);
      await waitFor(() => expect(auditStore.following).toBe(false));
      api.entries.push(connection(4, { host: "new.test", ts: Date.now() }));
      source.emit({ type: "audit_appended", id: 4 });
      const button = await screen.findByRole("button", {
        name: /1 new\s+record: show/,
      });
      expect(hosts()[0]).toBe("crates.io:443");
      await fireEvent.click(button);
      await waitFor(() => expect(hosts()[0]).toBe("new.test:443"));
      expect(screen.queryByRole("button", { name: /new\s+record/ })).toBeNull();
    });
    it("says how many are waiting", async () => {
      await open();
      auditStore.setFollowing(false);
      api.entries.push(
        connection(4, { ts: Date.now() }),
        connection(5, { ts: Date.now() }),
      );
      source.emit({ type: "audit_appended", id: 5 });
      await screen.findByRole("button", { name: /2 new\s+records: show/ });
    });
    it("stops reading with Live off, and reads again with it on", async () => {
      await open();
      const live = screen.getByRole("checkbox", { name: "Live" });
      expect(live).toBeChecked();
      await fireEvent.click(live);
      expect(auditStore.live).toBe(false);
      api.entries.push(connection(4, { host: "new.test", ts: Date.now() }));
      source.emit({ type: "audit_appended", id: 4 });
      await Promise.resolve();
      expect(hosts()).toHaveLength(3);
      await fireEvent.click(live);
      await waitFor(() => expect(hosts()[0]).toBe("new.test:443"));
    });
  });

  describe("export", () => {
    let blobs: Blob[];
    let clicked: { download: string; href: string }[];
    beforeEach(() => {
      blobs = [];
      clicked = [];
      URL.createObjectURL = (blob: Blob | MediaSource) => {
        blobs.push(blob as Blob);
        return `blob:test/${blobs.length}`;
      };
      URL.revokeObjectURL = () => {};
      vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
        function (this: HTMLAnchorElement) {
          clicked.push({ download: this.download, href: this.href });
        },
      );
    });
    afterEach(() => {
      vi.restoreAllMocks();
      api.gate = null;
    });

    it("saves the filtered records as JSON lines, oldest first", async () => {
      await open();
      await fireEvent.change(screen.getByLabelText("Workspace"), {
        target: { value: "shop" },
      });
      await waitFor(() => expect(rows()).toHaveLength(2));
      await fireEvent.click(
        screen.getByRole("button", { name: "Export JSON lines" }),
      );
      await screen.findByText(/Saved 2 records as puddle-activity-/);
      expect(clicked).toHaveLength(1);
      expect(clicked[0]?.download).toMatch(/^puddle-activity-.*\.jsonl$/);
      expect(blobs[0]?.type).toBe("application/x-ndjson");
      const lines = (await blobs[0]?.text())?.trimEnd().split("\n") ?? [];
      expect(
        lines.map((l) => (JSON.parse(l) as { host: string }).host),
      ).toEqual(["github.com", "crates.io"]);
      expect(api.queries.at(-1)).toMatchObject({ sandbox: "shop", after: 0 });
    });
    it("says so when nothing matches, and saves no file", async () => {
      api.entries = [];
      window.history.replaceState({}, "", "/activity?range=all");
      render(ActivityPage);
      await screen.findByText("Nothing recorded yet");
      await fireEvent.click(
        screen.getByRole("button", { name: "Export JSON lines" }),
      );
      await screen.findByText(/Nothing to export/);
      expect(clicked).toHaveLength(0);
    });
    it("says so when the log can't be read", async () => {
      await open();
      api.failNext = 500;
      await fireEvent.click(
        screen.getByRole("button", { name: "Export JSON lines" }),
      );
      await screen.findByText(/couldn't read the log/);
      expect(clicked).toHaveLength(0);
    });
    it("shows progress, can be cancelled, and is one at a time", async () => {
      api.entries = Array.from({ length: 1500 }, (_, i) =>
        connection(i + 1, { ts: Date.now() }),
      );
      render(ActivityPage);
      await waitFor(() => expect(rows().length).toBeGreaterThan(0));
      const button = screen.getByRole("button", { name: "Export JSON lines" });
      let release = () => {};
      api.gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      await fireEvent.click(button);
      expect(button).toBeDisabled();
      await fireEvent.click(button);
      const cancel = await screen.findByRole("button", { name: "Cancel" });
      await fireEvent.click(cancel);
      release();
      await screen.findByText("Export cancelled.");
      expect(clicked).toHaveLength(0);
      expect(button).not.toBeDisabled();
    });
  });
});
