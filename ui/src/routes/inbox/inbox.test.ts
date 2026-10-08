// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = await vi.hoisted(async () => {
  const m = await import("#lib/testing/fake-inbox.ts");
  const sets = await import("#lib/testing/fake-rule-sets.ts");
  return {
    inbox: new m.FakeInbox(),
    setsApi: new sets.FakeRuleSets(),
    source: new m.FakeSource(),
    request: m.request,
    mine: sets.mine,
  };
});

vi.mock("#lib/stores/rule-sets.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/rule-sets.svelte.ts")>();
  return {
    ...mod,
    ruleSets: new mod.RuleSetsStore({
      api: h.setsApi as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});

vi.mock("#lib/stores/pending.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/pending.svelte.ts")>();
  return {
    ...mod,
    pending: new mod.PendingStore({
      api: h.inbox as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});

import { pending } from "#lib/stores/pending.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import InboxPage from "./+page.svelte";

const { inbox, setsApi, source, request, mine } = h;

function reset() {
  inbox.open = [];
  inbox.rules = [];
  inbox.suppression = {};
  inbox.toggles = {};
  inbox.calls = [];
  inbox.down = false;
  pending.rows = [];
  pending.decided = [];
  pending.suppression = {};
  pending.toggles = {};
  pending.status = "loading";
  setsApi.sets = [];
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
}

beforeEach(reset);
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function seed() {
  inbox.add(
    request(1, { host: "a.example.com", first_seen: 3_000 }),
    "example.com",
  );
  inbox.add(
    request(2, { host: "b.example.com", first_seen: 2_000 }),
    "example.com",
  );
  inbox.add(
    request(3, { host: "registry.other.org", first_seen: 1_000 }),
    "other.org",
  );
}

async function ready() {
  const view = render(InboxPage);
  await screen.findByRole("heading", { name: "example.com" });
  return view;
}

const rowOf = (host: string) =>
  screen.getByText(host, { selector: ".host" }).closest("li") as HTMLElement;
const press = (key: string, target: Element = document.body) =>
  fireEvent.keyDown(target, { key });

describe("the inbox page", () => {
  it("shows a loading line, then the groups with their rows", async () => {
    seed();
    render(InboxPage);
    expect(screen.getByText(/Loading requests/)).toBeInTheDocument();
    await screen.findByRole("heading", { level: 2, name: "example.com" });
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", { level: 2, name: "other.org" }),
    ).toBeInTheDocument();
    expect(screen.getByText("2 waiting")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(rowOf("a.example.com")).toHaveAttribute("aria-current", "true");
  });

  it("says so when the service didn't answer, and shows an empty state when nothing waits", async () => {
    inbox.down = true;
    const view = render(InboxPage);
    await screen.findByText(/Couldn't read the requests/);
    view.unmount();
    reset();
    render(InboxPage);
    await screen.findByRole("heading", { name: "All quiet" });
  });

  it("lists the shortcuts in words", async () => {
    seed();
    await ready();
    expect(screen.getByText(/allow ·/)).toHaveTextContent(
      "A allow · D deny · J/K move · Enter more choices",
    );
  });

  it("shows the held-back line only while a workspace's requests are suppressed (R-13)", async () => {
    const held = () => document.querySelector(".held");
    seed();
    inbox.suppression["demo"] = { active: true, count: 14 };
    await ready();
    await vi.waitFor(() =>
      expect(held()).toHaveTextContent(
        /14 more requests from demo were held back/,
      ),
    );
    cleanup();
    reset();
    seed();
    inbox.suppression["demo"] = { active: true, count: 1 };
    await ready();
    await vi.waitFor(() =>
      expect(held()).toHaveTextContent(
        /1 more request from demo was held back/,
      ),
    );
    cleanup();
    reset();
    seed();
    inbox.suppression["demo"] = { active: false, count: 14 };
    await ready();
    await vi.waitFor(() => expect(pending.suppression["demo"]).toBeDefined());
    expect(held()).toBeNull();
  });

  it("updates live: a new row, an updated count, a closed row, without a refetch", async () => {
    seed();
    await ready();
    const fetched = inbox.calls.length;
    source.emit({
      type: "pending_opened",
      request: request(9, { host: "new.example.com", first_seen: 9_000 }),
      registrable_domain: "example.com",
    });
    expect(
      await screen.findByText("new.example.com", { selector: ".host" }),
    ).toBeInTheDocument();
    source.emit({
      type: "pending_updated",
      id: 9,
      attempts: 4,
      last_seen: 9_500,
    });
    await vi.waitFor(() =>
      expect(rowOf("new.example.com")).toHaveTextContent("4 attempts"),
    );
    source.emit({
      type: "pending_closed",
      id: 9,
      state: "allowed",
      rule_id: 1,
    });
    await vi.waitFor(() =>
      expect(screen.queryByText("new.example.com")).toBeNull(),
    );
    expect(
      inbox.calls.slice(fetched).filter((c) => c === "GET /api/inbox"),
    ).toEqual([]);
  });

  it("refreshes relative times every 30 seconds", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(1_000_000 + 60_000);
    inbox.add(
      request(1, { first_seen: 1_000_000, last_seen: 1_000_000 }),
      "example.com",
    );
    render(InboxPage);
    await vi.waitFor(() =>
      expect(screen.getByRole("listitem")).toHaveTextContent("1 minute ago"),
    );
    await vi.advanceTimersByTimeAsync(30_000);
    expect(screen.getByRole("listitem")).toHaveTextContent("1 minute ago");
    await vi.advanceTimersByTimeAsync(120_000);
    expect(screen.getByRole("listitem")).toHaveTextContent("3 minutes ago");
  });
});

describe("deciding with the buttons", () => {
  it("allows one host for one workspace with one click, announces it, and closes the row", async () => {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow a.example.com for demo" }),
    );
    await vi.waitFor(() =>
      expect(
        screen.queryByText("a.example.com", { selector: ".host" }),
      ).toBeNull(),
    );
    expect(inbox.rules[0]).toMatchObject({
      effect: "allow",
      pattern: "a.example.com",
      scope: { type: "workspace" },
    });
    expect(screen.getByRole("status")).toHaveTextContent(
      "Allowed a.example.com for workspace demo, permanently.",
    );
    expect(
      within(
        screen.getByRole("region", { name: "Decided just now" }),
      ).getByText("allowed"),
    ).toBeInTheDocument();
    expect(pending.count).toBe(2);
  });

  it("denies with one click", async () => {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: "Deny b.example.com for demo" }),
    );
    await vi.waitFor(() => expect(inbox.rules).toHaveLength(1));
    expect(inbox.rules[0]).toMatchObject({
      effect: "deny",
      pattern: "b.example.com",
    });
  });

  it("undoes from the toast: the rule is deleted and the page says so", async () => {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow a.example.com for demo" }),
    );
    await fireEvent.click(await screen.findByRole("button", { name: "Undo" }));
    await vi.waitFor(() => expect(inbox.rules).toHaveLength(0));
    expect(
      await screen.findByText(/Undone: Allowed a\.example\.com/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Decided just now" }),
    ).toBeNull();
  });

  it("undoes from the Decided just now list", async () => {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: "Deny a.example.com for demo" }),
    );
    const undo = await screen.findByRole("button", {
      name: /^Undo: Denied a\.example\.com/,
    });
    await fireEvent.click(undo);
    await vi.waitFor(() => expect(inbox.rules).toHaveLength(0));
  });

  it("says when an undo fails", async () => {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow a.example.com for demo" }),
    );
    inbox.DELETE = (async () => ({
      response: { status: 500, ok: false },
    })) as never;
    await fireEvent.click(
      await screen.findByRole("button", { name: /^Undo: / }),
    );
    expect(
      await screen.findByText("puddle couldn't undo that."),
    ).toBeInTheDocument();
    reset();
  });

  it("puts the rule into one of your sets that is on for the workspace", async () => {
    setsApi.sets = [
      mine(4, { name: "Client X" }),
      mine(5, {
        name: "Elsewhere",
        overrides: [{ workspace: "demo" as never, enabled: false }],
      }),
    ];
    inbox.add(request(1, { host: "a.example.com" }), "example.com");
    await ready();
    await vi.waitFor(() =>
      expect(setsApi.calls).toContain("GET /api/rule-sets"),
    );
    await fireEvent.click(
      screen.getByRole("button", { name: /^More choices for a\.example\.com/ }),
    );
    const dialog = await showOptions();
    expect(
      within(dialog).queryByRole("radio", { name: /Elsewhere/ }),
    ).toBeNull();
    await fireEvent.click(
      within(dialog).getByRole("radio", { name: /Into rule set Client X/ }),
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: /Allow/ }),
    );
    // On for every workspace, so it asks first.
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent(
      "Allow a.example.com in rule set Client X (which is on for every workspace), permanently",
    );
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Allow in every workspace" }),
    );
    await vi.waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent(
        "Allowed a.example.com in rule set Client X",
      ),
    );
  });

  it("mentions the other requests the rule closed", async () => {
    inbox.add(request(1, { host: "a.example.com" }), "example.com");
    inbox.add(request(2, { host: "b.example.com" }), "example.com");
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: /^More choices for a\.example\.com/ }),
    );
    const dialog = await showOptions();
    await fireEvent.click(
      within(dialog).getByRole("radio", { name: /^Everything under/ }),
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: /Allow/ }),
    );
    await vi.waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent(
        "also closed 1 other request",
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "All quiet" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/· also closed 1 other/)).toBeInTheDocument();
  });

  it("shows a refusal and refetches when the request was already decided elsewhere", async () => {
    seed();
    await ready();
    inbox.nextDecisionStatus = 409;
    inbox.open = inbox.open.filter((o) => o.request.id !== 1);
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow a.example.com for demo" }),
    );
    expect(
      await screen.findByText(/already decided or has gone away/),
    ).toBeInTheDocument();
    await vi.waitFor(() =>
      expect(
        screen.queryByText("a.example.com", { selector: ".host" }),
      ).toBeNull(),
    );
  });

  it("shows a refusal from the service as an error toast", async () => {
    seed();
    await ready();
    inbox.nextDecisionStatus = 500;
    await fireEvent.click(
      screen.getByRole("button", { name: "Allow a.example.com for demo" }),
    );
    expect(await screen.findByText("refused")).toBeInTheDocument();
    expect(rowOf("a.example.com")).toBeInTheDocument();
  });
});

async function showOptions(): Promise<HTMLElement> {
  const dialog = await screen.findByRole("dialog", { hidden: true });
  if (dialog.parentElement) dialog.parentElement.style.visibility = "visible";
  return dialog;
}

describe("every workspace needs a confirm", () => {
  async function chooseGlobal(effect: "Allow" | "Deny") {
    seed();
    await ready();
    await fireEvent.click(
      screen.getByRole("button", { name: /^More choices for a\.example\.com/ }),
    );
    const dialog = await showOptions();
    await fireEvent.click(
      within(dialog).getByRole("radio", { name: /^Every workspace/ }),
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: new RegExp(effect) }),
    );
  }

  it("asks first, names the pattern, and does nothing on Cancel", async () => {
    await chooseGlobal("Allow");
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveAccessibleName("Allow for every workspace?");
    expect(confirm).toHaveTextContent(
      "Allow a.example.com for every workspace, permanently",
    );
    expect(inbox.calls.filter((c) => c.startsWith("POST"))).toEqual([]);
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Cancel" }),
    );
    await vi.waitFor(() =>
      expect(screen.queryByRole("alertdialog")).toBeNull(),
    );
    expect(inbox.calls.filter((c) => c.startsWith("POST"))).toEqual([]);
  });

  it("decides for every workspace only after Confirm", async () => {
    await chooseGlobal("Allow");
    await fireEvent.click(
      await screen.findByRole("button", { name: "Allow in every workspace" }),
    );
    await vi.waitFor(() => expect(inbox.rules).toHaveLength(1));
    expect(inbox.rules[0]?.scope).toEqual({ type: "global" });
  });

  it("words a global deny as a deny", async () => {
    await chooseGlobal("Deny");
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveAccessibleName("Deny for every workspace?");
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Deny in every workspace" }),
    );
    await vi.waitFor(() =>
      expect(inbox.rules[0]).toMatchObject({
        effect: "deny",
        scope: { type: "global" },
      }),
    );
  });
});

describe("keyboard", () => {
  it("J and K move the current row and its focus, and stop at the ends", async () => {
    seed();
    await ready();
    await press("j");
    expect(rowOf("b.example.com")).toHaveAttribute("aria-current", "true");
    expect(rowOf("b.example.com")).toHaveFocus();
    await press("J");
    await press("j");
    expect(rowOf("registry.other.org")).toHaveFocus();
    await press("k");
    await press("K");
    await press("k");
    expect(rowOf("a.example.com")).toHaveFocus();
  });

  it("A allows and D denies the current row, and focus lands on the next row", async () => {
    seed();
    await ready();
    await press("a");
    await vi.waitFor(() =>
      expect(
        screen.queryByText("a.example.com", { selector: ".host" }),
      ).toBeNull(),
    );
    expect(inbox.rules[0]).toMatchObject({
      effect: "allow",
      pattern: "a.example.com",
    });
    await vi.waitFor(() => expect(rowOf("b.example.com")).toHaveFocus());
    await press("D");
    await vi.waitFor(() =>
      expect(inbox.rules[1]).toMatchObject({
        effect: "deny",
        pattern: "b.example.com",
      }),
    );
    await vi.waitFor(() => expect(rowOf("registry.other.org")).toHaveFocus());
  });

  it("the last decision moves focus to the heading", async () => {
    inbox.add(request(1), "example.com");
    await ready();
    await press("d");
    await vi.waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveFocus(),
    );
  });

  it("Enter on a row opens its options; Escape closes them and returns focus to the trigger", async () => {
    seed();
    await ready();
    rowOf("a.example.com").focus();
    await press("Enter", rowOf("a.example.com"));
    const dialog = await showOptions();
    expect(dialog).toHaveAccessibleName("Choices for a.example.com");
    await fireEvent.keyDown(dialog, { key: "Escape" });
    await vi.waitFor(() =>
      expect(screen.queryByRole("dialog", { hidden: true })).toBeNull(),
    );
  });

  it("Enter opens the options again after they were closed", async () => {
    seed();
    await ready();
    await press("Enter");
    let dialog = await showOptions();
    await fireEvent.keyDown(dialog, { key: "Escape" });
    await vi.waitFor(() =>
      expect(screen.queryByRole("dialog", { hidden: true })).toBeNull(),
    );
    await press("Enter");
    dialog = await showOptions();
    expect(dialog).toHaveAccessibleName("Choices for a.example.com");
  });

  it("Enter on a button keeps its own meaning", async () => {
    seed();
    await ready();
    const allow = screen.getByRole("button", {
      name: "Allow a.example.com for demo",
    });
    allow.focus();
    await press("Enter", allow);
    expect(screen.queryByRole("dialog", { hidden: true })).toBeNull();
  });

  it("ignores keys with a modifier, in form fields, and while a dialog is open", async () => {
    seed();
    await ready();
    await fireEvent.keyDown(document.body, { key: "a", ctrlKey: true });
    await fireEvent.keyDown(document.body, { key: "a", metaKey: true });
    await fireEvent.keyDown(document.body, { key: "a", altKey: true });
    const field = document.createElement("input");
    document.body.append(field);
    await press("a", field);
    field.remove();
    await press("x");
    await press("Enter", document.body); // opens the options of the current row
    await showOptions();
    await press("d");
    await press("j");
    expect(inbox.calls.filter((c) => c.startsWith("POST"))).toEqual([]);
  });

  it("does nothing without rows", async () => {
    render(InboxPage);
    await screen.findByRole("heading", { name: "All quiet" });
    await press("a");
    await press("j");
    await press("Enter");
    expect(inbox.calls.filter((c) => c.startsWith("POST"))).toEqual([]);
  });

  it("A decides for this workspace only, never for every workspace", async () => {
    seed();
    await ready();
    await press("a");
    await vi.waitFor(() =>
      expect(inbox.rules[0]?.scope).toEqual({
        type: "workspace",
        workspace: "demo",
      }),
    );
  });
});

describe("local destinations", () => {
  async function local(toggleOn: boolean) {
    inbox.add(request(1, { host: "192.168.1.10" }), "192.168.1.10");
    inbox.toggles["demo"] = { private: toggleOn };
    render(InboxPage);
    await screen.findByRole("heading", { name: "192.168.1.10" });
  }

  it("names the switched-off toggle, links to it, and offers only Deny", async () => {
    await local(false);
    await vi.waitFor(() =>
      expect(screen.getByText(/can't be approved yet/)).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("link", { name: "Private networks" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Allow/ })).toBeNull();
    expect(screen.getByRole("button", { name: /^Deny/ })).toBeInTheDocument();
  });

  it("A explains instead of allowing, and Enter opens nothing", async () => {
    await local(false);
    await vi.waitFor(() =>
      expect(screen.getByText(/can't be approved yet/)).toBeInTheDocument(),
    );
    await press("a");
    expect(
      await screen.findByText(/Can't allow 192\.168\.1\.10 yet/),
    ).toBeInTheDocument();
    await press("Enter");
    expect(screen.queryByRole("dialog", { hidden: true })).toBeNull();
    expect(inbox.calls.filter((c) => c.startsWith("POST"))).toEqual([]);
  });

  it("D still denies it", async () => {
    await local(false);
    await vi.waitFor(() =>
      expect(screen.getByText(/can't be approved yet/)).toBeInTheDocument(),
    );
    await press("d");
    await vi.waitFor(() =>
      expect(inbox.rules[0]).toMatchObject({
        effect: "deny",
        pattern: "192.168.1.10",
      }),
    );
  });

  it("approves normally once its toggle is on", async () => {
    await local(true);
    await fireEvent.click(
      await screen.findByRole("button", { name: /^Allow/ }),
    );
    await vi.waitFor(() =>
      expect(inbox.rules[0]).toMatchObject({ effect: "allow" }),
    );
  });
});

describe("the page measures itself", () => {
  it("marks when data arrived and, after the rows were rendered, when they were painted", async () => {
    performance.clearMarks();
    seed();
    await ready();
    const painted = () => performance.getEntriesByName("puddle:inbox-painted");
    await vi.waitFor(() => expect(painted().length).toBeGreaterThan(0));
    const data = performance.getEntriesByName("puddle:inbox-data");
    expect(data).toHaveLength(1);
    await vi.waitFor(() =>
      expect(
        performance.getEntriesByName("puddle:inbox-all-painted").length,
      ).toBeGreaterThan(0),
    );
    expect(data[0]?.startTime).toBeLessThanOrEqual(
      painted().at(-1)?.startTime ?? 0,
    );
  });
});

describe("a long list is drawn in slices", () => {
  it("shows the first rows at once, then all of them, and counts every row in the group", async () => {
    for (let i = 1; i <= 150; i += 1) {
      inbox.add(
        request(i, { host: `h${i}.example.com`, first_seen: i }),
        "example.com",
      );
    }
    render(InboxPage);
    await screen.findByRole("heading", { name: "example.com" });
    expect(screen.getByText("150 waiting")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem").length).toBeLessThan(150);
    await vi.waitFor(() =>
      expect(screen.getAllByRole("listitem")).toHaveLength(150),
    );
  });
});
