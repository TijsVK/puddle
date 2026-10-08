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

const h = await vi.hoisted(async () => {
  const fakes = await import("#lib/testing/fake-rules.ts");
  const inbox = await import("#lib/testing/fake-inbox.ts");
  const sets = await import("#lib/testing/fake-rule-sets.ts");
  return {
    api: new fakes.FakeRules(),
    setsApi: new sets.FakeRuleSets(),
    source: new inbox.FakeSource(),
    rule: fakes.rule,
    builtIn: sets.builtIn,
    mine: sets.mine,
    systemHost: sets.systemHost,
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

vi.mock("#lib/stores/rules.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/rules.svelte.ts")>();
  return {
    ...mod,
    rulesStore: new mod.RulesStore({
      api: h.api as never,
      source: h.source,
      pollMs: 60_000,
    }),
  };
});

import { ruleSets } from "#lib/stores/rule-sets.svelte.ts";
import { rulesStore } from "#lib/stores/rules.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import RulesPage from "./+page.svelte";

const { api, setsApi, source, rule, builtIn, mine, systemHost } = h;

beforeEach(() => {
  api.rules = [];
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.refuse = null;
  rulesStore.rules = [];
  rulesStore.status = "loading";
  setsApi.sets = [];
  setsApi.system = [];
  setsApi.calls = [];
  setsApi.bodies = [];
  setsApi.down = false;
  ruleSets.sets = [];
  ruleSets.system = [];
  ruleSets.status = "loading";
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

function seed() {
  api.rules = [
    rule(1, { pattern: "registry.npmjs.org", created_at: 100 }),
    rule(2, {
      pattern: ".github.com",
      pattern_kind: "suffix",
      scope: { type: "workspace", workspace: "shop" as never },
      effect: "deny",
      created_at: 200,
    }),
    rule(3, {
      pattern: "old.example.com",
      expires_at: Date.now() - 60_000,
      created_at: 300,
    }),
  ];
}

const rows = () => screen.getAllByRole("row").slice(1);
const hosts = () =>
  rows().map((r) => within(r).getAllByRole("cell")[0]!.textContent?.trim());

async function loaded() {
  render(RulesPage);
  await waitFor(() => expect(rulesStore.status).toBe("ready"));
}

describe("the list", () => {
  it("says it is loading, then shows an empty state with a way forward", async () => {
    render(RulesPage);
    expect(screen.getByText(/loading rules/i)).toBeInTheDocument();
    expect(await screen.findByText("No rules yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Inbox" })).toHaveAttribute(
      "href",
      "/inbox",
    );
    expect(screen.queryByRole("search")).not.toBeInTheDocument();
  });
  it("says so when the service can't be read", async () => {
    api.down = true;
    render(RulesPage);
    expect(
      await screen.findByText(/couldn't read the rules/i),
    ).toBeInTheDocument();
  });
  it("shows each rule's host, effect, workspace and expiry, newest first", async () => {
    seed();
    await loaded();
    expect(hosts()).toEqual([
      "old.example.com",
      "*.github.com and subdomains",
      "registry.npmjs.org",
    ]);
    const old = rows()[0]!;
    expect(within(old).getByText("Expired")).toBeInTheDocument();
    expect(within(old).getByText("no longer applies")).toBeInTheDocument();
    expect(within(rows()[1]!).getByText("Deny")).toBeInTheDocument();
    expect(within(rows()[1]!).getByText("shop")).toBeInTheDocument();
    expect(within(rows()[2]!).getByText("Every workspace")).toBeInTheDocument();
    expect(within(rows()[2]!).getByText("Never")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 1, name: "Rules" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/most specific rule wins/i)).toBeInTheDocument();
  });
  it("sorts by a column and flips on a second click", async () => {
    seed();
    await loaded();
    await fireEvent.click(screen.getByRole("button", { name: "Sort by host" }));
    expect(hosts()[0]).toBe("*.github.com and subdomains");
    expect(screen.getByRole("columnheader", { name: /Host/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
    await fireEvent.click(screen.getByRole("button", { name: "Sort by host" }));
    expect(screen.getByRole("columnheader", { name: /Host/ })).toHaveAttribute(
      "aria-sort",
      "descending",
    );
    await fireEvent.click(
      screen.getByRole("button", { name: "Sort by expires" }),
    );
    expect(
      screen.getByRole("columnheader", { name: /Expires/ }),
    ).toHaveAttribute("aria-sort", "descending");
  });
});

describe("filters", () => {
  it("narrows by host, workspace, effect and state, counts, and clears", async () => {
    seed();
    await loaded();
    expect(
      screen.getByText(/rules?\b/, { selector: ".count" }),
    ).toHaveTextContent("3 rules");
    await fireEvent.input(screen.getByLabelText("Host contains"), {
      target: { value: "GITHUB" },
    });
    expect(hosts()).toHaveLength(1);
    expect(
      screen.getByText(/rules?\b/, { selector: ".count" }),
    ).toHaveTextContent("1 of 3 rules");
    await fireEvent.click(
      screen.getByRole("button", { name: "Clear filters" }),
    );
    expect(rows()).toHaveLength(3);
    await fireEvent.change(screen.getByLabelText("Workspace"), {
      target: { value: "global" },
    });
    expect(rows()).toHaveLength(2);
    await fireEvent.change(screen.getByLabelText("Workspace"), {
      target: { value: "shop" },
    });
    expect(rows()).toHaveLength(1);
    await fireEvent.change(screen.getByLabelText("Workspace"), {
      target: { value: "any" },
    });
    await fireEvent.change(screen.getByLabelText("Effect"), {
      target: { value: "allow" },
    });
    expect(rows()).toHaveLength(2);
    await fireEvent.change(screen.getByLabelText("State"), {
      target: { value: "expired" },
    });
    expect(hosts()).toEqual(["old.example.com"]);
  });
  it("says when nothing matches", async () => {
    seed();
    await loaded();
    await fireEvent.input(screen.getByLabelText("Host contains"), {
      target: { value: "zzz" },
    });
    expect(screen.getByText("No rule matches")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});

describe("adding", () => {
  async function open() {
    await loaded();
    await fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    return screen.findByRole("dialog", { name: "Add a rule" });
  }
  const fill = async (
    dialog: HTMLElement,
    host: string,
    workspace = "shop",
  ) => {
    await fireEvent.input(within(dialog).getByLabelText("Host"), {
      target: { value: host },
    });
    if (workspace)
      await fireEvent.input(within(dialog).getByLabelText("Workspace name"), {
        target: { value: workspace },
      });
  };

  it("adds a workspace rule with an expiry and says so", async () => {
    seed();
    const dialog = await open();
    await fill(dialog, "  *.example.org ");
    await fireEvent.click(within(dialog).getByLabelText("Deny"));
    await fireEvent.change(within(dialog).getByLabelText("Expires"), {
      target: { value: "3600" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const body = api.bodies[0] as {
      expires_at: number;
      scope: unknown;
      pattern: string;
      effect: string;
    };
    expect(body).toMatchObject({
      pattern: "*.example.org",
      effect: "deny",
      scope: { type: "workspace", workspace: "shop" },
    });
    expect(body.expires_at).toBeGreaterThan(Date.now());
    expect(toasts.items[0]?.message).toBe(
      "Added: deny *.example.org for workspace shop.",
    );
    expect(hosts()).toContain("*.example.org and subdomains");
  });
  it("checks the form before asking the server", async () => {
    const dialog = await open();
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    expect(
      within(dialog)
        .getAllByRole("alert")
        .map((a) => a.textContent),
    ).toEqual([
      expect.stringMatching(/enter a host/i),
      expect.stringMatching(/name the workspace/i),
    ]);
    expect(within(dialog).getByLabelText("Host")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(api.bodies).toHaveLength(0);
    await fill(dialog, "a.example.com", "Bad Name");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    expect(within(dialog).getByRole("alert")).toHaveTextContent(/lower-case/);
  });
  it("shows the server's refusal under the host and keeps what was typed", async () => {
    const dialog = await open();
    api.refuse = { status: 422, message: "`.com` is a public suffix" };
    await fill(dialog, "*.com");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("`.com` is a public suffix.");
    const host = within(dialog).getByLabelText("Host");
    expect(host).toHaveAttribute("aria-invalid", "true");
    expect(host.getAttribute("aria-describedby")).toContain(alert.id);
    expect(host).toHaveValue("*.com");
  });
  it("shows other failures for the whole form", async () => {
    const dialog = await open();
    api.down = true;
    await fill(dialog, "a.example.com");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /isn't answering/,
    );
  });
  it("asks before a rule for every workspace, and Cancel returns to the form", async () => {
    const dialog = await open();
    await fireEvent.click(within(dialog).getByLabelText(/Every workspace/));
    expect(
      within(dialog).queryByLabelText("Workspace name"),
    ).not.toBeInTheDocument();
    await fireEvent.input(within(dialog).getByLabelText("Host"), {
      target: { value: "cdn.example.com" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    const confirm = await screen.findByRole("alertdialog", {
      name: "Allow for every workspace?",
    });
    expect(api.bodies).toHaveLength(0);
    expect(confirm).toHaveTextContent(
      "Allow cdn.example.com for every workspace",
    );
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Cancel" }),
    );
    const again = await screen.findByRole("dialog", { name: "Add a rule" });
    expect(within(again).getByLabelText("Host")).toHaveValue("cdn.example.com");
    await fireEvent.click(
      within(again).getByRole("button", { name: "Add rule" }),
    );
    const second = await screen.findByRole("alertdialog");
    await fireEvent.click(
      within(second).getByRole("button", { name: "Allow in every workspace" }),
    );
    await waitFor(() => expect(api.bodies).toHaveLength(1));
    expect(api.bodies[0]).toMatchObject({ scope: { type: "global" } });
    await waitFor(() => expect(toasts.items.length).toBeGreaterThan(0));
  });
  it("brings the form back with the refusal when the confirmed rule is refused", async () => {
    const dialog = await open();
    await fireEvent.click(within(dialog).getByLabelText(/Every workspace/));
    await fireEvent.click(within(dialog).getByLabelText("Deny"));
    await fireEvent.input(within(dialog).getByLabelText("Host"), {
      target: { value: "*.co.uk" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    const confirm = await screen.findByRole("alertdialog", {
      name: "Deny for every workspace?",
    });
    api.refuse = { status: 422, message: "co.uk is a public suffix" };
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Deny in every workspace" }),
    );
    const again = await screen.findByRole("dialog", { name: "Add a rule" });
    expect(await within(again).findByRole("alert")).toHaveTextContent(
      "Co.uk is a public suffix.",
    );
  });
  it("starts empty the next time, and Cancel discards", async () => {
    const dialog = await open();
    await fill(dialog, "typed.example.com");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    expect(
      within(await screen.findByRole("dialog")).getByLabelText("Host"),
    ).toHaveValue("");
  });
});

describe("changing the expiry", () => {
  async function open(name: RegExp) {
    await loaded();
    await fireEvent.click(screen.getByRole("button", { name }));
    return screen.findByRole("dialog", { name: "Change expiry" });
  }
  it("makes a rule permanent, or ends it later", async () => {
    seed();
    api.rules[0]!.expires_at = Date.now() + 3_600_000;
    const dialog = await open(/Change expiry: allow registry/);
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent(/choose when/i);
    await fireEvent.change(within(dialog).getByLabelText("Ends"), {
      target: { value: "0" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.bodies[0]).toEqual({ expires_at: null });
    expect(toasts.items[0]?.message).toBe(
      "registry.npmjs.org never expires now.",
    );
    expect(
      within(
        rows().find((r) => r.textContent?.includes("registry"))!,
      ).getByText("Never"),
    ).toBeInTheDocument();
  });
  it("sets a new time, and shows the server's refusal", async () => {
    seed();
    const dialog = await open(/Change expiry: deny \*\.github/);
    expect(dialog).toHaveTextContent(/never expires now/i);
    api.refuse = { status: 422, message: "expiry must be in the future" };
    await fireEvent.change(within(dialog).getByLabelText("Ends"), {
      target: { value: "3600" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Expiry must be in the future.",
    );
    await fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(toasts.items.at(-1)?.message).toBe(
      "Changed the expiry of *.github.com.",
    );
  });
  it("Cancel closes it without a call", async () => {
    seed();
    const dialog = await open(/Change expiry: allow registry/);
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.bodies).toHaveLength(0);
  });
});

describe("deleting", () => {
  it("asks first, names the rule, and Cancel keeps it", async () => {
    seed();
    await loaded();
    await fireEvent.click(
      screen.getByRole("button", {
        name: "Delete rule: allow registry.npmjs.org for every workspace",
      }),
    );
    const dialog = await screen.findByRole("alertdialog", {
      name: "Delete this rule?",
    });
    expect(dialog).toHaveTextContent(
      "allow registry.npmjs.org for every workspace",
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
    expect(rows()).toHaveLength(3);
    expect(api.calls.some((c) => c.startsWith("DELETE"))).toBe(false);
  });
  it("deletes on confirm, and puts focus on the next row", async () => {
    seed();
    await loaded();
    await fireEvent.click(
      screen.getByRole("button", {
        name: /Delete rule: allow old.example.com/,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete rule" }),
    );
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(toasts.items[0]?.message).toBe(
      "Deleted: allow old.example.com for every workspace.",
    );
    await waitFor(() =>
      expect(document.activeElement?.closest("tr")).toBe(rows()[0]),
    );
  });
  it("reports a failure and keeps the rule", async () => {
    seed();
    await loaded();
    api.refuse = { status: 500, message: "x" };
    await fireEvent.click(
      screen.getByRole("button", {
        name: /Delete rule: allow old.example.com/,
      }),
    );
    await fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Delete rule",
      }),
    );
    await waitFor(() => expect(toasts.items[0]?.tone).toBe("error"));
    expect(rows()).toHaveLength(3);
  });
  it("focuses the heading when the last rule goes", async () => {
    api.rules = [rule(1)];
    await loaded();
    await fireEvent.click(screen.getByRole("button", { name: /Delete rule/ }));
    await fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Delete rule",
      }),
    );
    await screen.findByText("No rules yet");
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveFocus(),
    );
  });
});

describe("live", () => {
  it("shows a rule another client added when rules_changed arrives", async () => {
    seed();
    await loaded();
    api.rules = [
      ...api.rules,
      rule(9, { pattern: "late.example.com", created_at: 999 }),
    ];
    source.emit({ type: "rules_changed" });
    await waitFor(() => expect(hosts()[0]).toBe("late.example.com"));
  });
  it("shows an expiry that passes without a reload, at the next 30 s tick", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    api.rules = [rule(1, { expires_at: Date.now() + 10_000 })];
    try {
      render(RulesPage);
      await vi.waitFor(() =>
        expect(screen.getByRole("table")).toBeInTheDocument(),
      );
      expect(screen.queryByText("no longer applies")).not.toBeInTheDocument();
      await vi.advanceTimersByTimeAsync(30_000);
      expect(screen.getByText("no longer applies")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("rule sets and System managed (rules spec §7)", () => {
  async function withSets() {
    setsApi.sets = [
      builtIn("github", { name: "GitHub" }),
      mine(4, {
        name: "Client X",
        entries: [
          {
            pattern: "x.example",
            pattern_kind: "exact",
            effect: "deny",
            note: "",
            rule_id: 9,
            expires_at: null,
          },
        ],
      }),
    ];
    setsApi.system = [systemHost("open-vsx.org")];
    api.rules = [
      rule(1, { pattern: "mine.example" }),
      rule(9, { pattern: "x.example", scope: { type: "set", set: 4 } }),
    ];
    await loaded();
    await waitFor(() => expect(ruleSets.status).toBe("ready"));
  }
  const section = (name: string) =>
    screen.getByRole("region", { name }) as HTMLElement;

  it("keeps a set's entries out of your rules and shows them under the set", async () => {
    await withSets();
    const table = screen.getAllByRole("table")[0]!;
    expect(within(table).getByText("mine.example")).toBeInTheDocument();
    expect(within(table).queryByText("x.example")).not.toBeInTheDocument();
    expect(
      screen.getByText("1 rule", { selector: ".count" }),
    ).toBeInTheDocument();
    const sets = section("Rule sets");
    const card = within(sets).getByRole("article", { name: "Client X" });
    expect(within(card).getByText("x.example")).toBeInTheDocument();
    const system = section("System managed");
    expect(within(system).getByText("open-vsx.org")).toBeInTheDocument();
    expect(
      within(system).getByText(/bundled code-server/, { selector: "b" }),
    ).toBeInTheDocument();
  });

  it("asks before turning a set on for every workspace", async () => {
    await withSets();
    const card = within(section("Rule sets")).getByRole("article", {
      name: "GitHub",
    });
    await fireEvent.click(
      within(card).getByRole("switch", { name: "On for every workspace" }),
    );
    const confirm = await screen.findByRole("alertdialog", {
      name: "Turn on for every workspace?",
    });
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Turn on everywhere" }),
    );
    await waitFor(() =>
      expect(setsApi.calls).toContain("PUT /api/rule-sets/{id}/switch"),
    );
    expect(setsApi.bodies.at(-1)).toEqual({ workspace: null, enabled: true });
  });

  it("adds an entry into a set and deletes one", async () => {
    await withSets();
    const card = within(section("Rule sets")).getByRole("article", {
      name: "Client X",
    });
    await fireEvent.click(
      within(card).getByRole("button", { name: "Add entry" }),
    );
    const dialog = await screen.findByRole("dialog", { name: "Add a rule" });
    expect(
      within(dialog).getByRole("radio", { name: /In rule set Client X/ }),
    ).toBeChecked();
    await fireEvent.input(within(dialog).getByLabelText("Host"), {
      target: { value: "y.example" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Add rule" }),
    );
    // The set is on for every workspace, so it asks first.
    const confirm = await screen.findByRole("alertdialog");
    expect(confirm).toHaveTextContent(
      "Allow y.example in rule set Client X, which is on for every workspace",
    );
    await fireEvent.click(
      within(confirm).getByRole("button", { name: "Allow in every workspace" }),
    );
    await waitFor(() =>
      expect(api.bodies.at(-1)).toMatchObject({
        pattern: "y.example",
        scope: { type: "set", set: 4 },
      }),
    );
    // Or choose the set in a plain Add rule.
    await fireEvent.click(
      screen.getAllByRole("button", { name: "Add rule" })[0]!,
    );
    const plain = await screen.findByRole("dialog", { name: "Add a rule" });
    await fireEvent.click(
      within(plain).getByRole("radio", { name: /In rule set Client X/ }),
    );
    expect(
      within(plain).getByRole("radio", { name: /In rule set Client X/ }),
    ).toBeChecked();
    await fireEvent.click(
      within(plain).getByRole("button", { name: "Cancel" }),
    );
    await fireEvent.click(
      within(card).getByRole("button", {
        name: "Delete x.example from Client X",
      }),
    );
    await waitFor(() => expect(api.calls).toContain("DELETE /api/rules/{id}"));
  });
});
