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

const url = vi.hoisted(() => ({ id: "web-shop" }));
vi.mock("$app/state", () => ({
  page: {
    get params() {
      return { id: url.id };
    },
  },
}));

const h = await vi.hoisted(async () => {
  const fake = await import("#lib/testing/fake-identities.ts");
  const ws = await import("#lib/testing/fake-workspaces.ts");
  return { api: new fake.FakeIdentities(), workspace: ws.workspace };
});

vi.mock("#lib/api/client.ts", () => ({ api: h.api }));
vi.mock("#lib/stores/identities.svelte.ts", async (original) => {
  const mod =
    await original<typeof import("#lib/stores/identities.svelte.ts")>();
  return {
    ...mod,
    identities: new mod.IdentitiesStore({
      api: h.api as never,
      pollMs: 60_000,
    }),
  };
});

import { identities } from "#lib/stores/identities.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import { workspaces } from "#lib/stores/workspaces.svelte.ts";
import { credential, identity, repoRow } from "#lib/testing/fake-identities.ts";
import Page from "./+page.svelte";

const { api, workspace } = h;

beforeEach(() => {
  url.id = "web-shop";
  workspaces.list = [
    workspace("web-shop", { repo_url: "https://github.com/acme/web-shop.git" }),
    workspace("docs", {
      repo_url: "https://dev.azure.com/contoso/Platform/_git/Docs",
    }),
  ];
  api.identities = [
    identity(1, {
      label: "Work",
      credentials: [credential({ owners: ["acme"], rest: false })],
    }),
    identity(2, {
      label: "Personal",
      is_default: false,
      credentials: [credential({ rest: true })],
    }),
    identity(3, {
      label: "Clash",
      is_default: false,
      credentials: [credential({ owners: ["acme"], rest: false })],
    }),
  ];
  api.git = {
    "web-shop": {
      ids: [1],
      repos: [
        repoRow(7, { repo: "web-shop" }),
        repoRow(8, { repo: "design-tokens", push: false }),
      ],
      push: true,
      pull: false,
    },
    docs: { ids: [], repos: [], push: false, pull: true },
  };
  api.calls = [];
  api.bodies = [];
  api.down = false;
  api.refuse = null;
  identities.identities = [];
  identities.status = "loading";
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(cleanup);

const lastToast = () => toasts.items.at(-1)?.message;
const table = () =>
  within(screen.getByRole("table", { name: "Repositories of web-shop" }));
const idList = () =>
  within(
    screen.getByRole("list", { name: "Identities of web-shop, in order" }),
  );

async function mount() {
  render(Page);
  await screen.findByRole("heading", { name: "Identities" });
  await screen.findByRole("table");
}

describe("identities on a workspace", () => {
  it("lists them in order with what each covers", async () => {
    await mount();
    expect(idList().getByRole("link", { name: "Work" })).toHaveAttribute(
      "href",
      "/identities/1",
    );
    expect(idList().getByText("github.com: acme")).toBeInTheDocument();
    expect(screen.queryByText(/No identity here covers/)).toBeNull();
  });

  it("adds an identity from those not on it, last", async () => {
    await mount();
    const select = screen.getByLabelText("Add an identity");
    await waitFor(() =>
      expect(within(select).getAllByRole("option")).toHaveLength(3),
    );
    await fireEvent.change(select, { target: { value: "2" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    await waitFor(() =>
      expect(idList().getAllByRole("listitem")).toHaveLength(2),
    );
    const again = screen.getByLabelText("Add an identity");
    expect(again).toHaveValue("");
    // Added identities leave the choices.
    expect(
      within(again).queryByRole("option", { name: "Personal" }),
    ).toBeNull();
  });

  it("asks for a choice, and shows the host's collision message", async () => {
    await mount();
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Pick an identity to add.",
    );
    const select = screen.getByLabelText("Add an identity");
    await waitFor(() =>
      expect(within(select).getAllByRole("option")).toHaveLength(3),
    );
    await fireEvent.change(select, { target: { value: "3" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Work and Clash both cover github.com/acme; narrow one.",
    );
    expect(idList().getAllByRole("listitem")).toHaveLength(1);
  });

  it("moves, removes and keeps focus on a button that still works", async () => {
    api.git["web-shop"]!.ids = [1, 2];
    await mount();
    const work = () => idList().getAllByRole("listitem")[0]!;
    expect(
      within(work()).getByRole("button", { name: "Move Work up" }),
    ).toBeDisabled();
    const down = within(work()).getByRole("button", { name: "Move Work down" });
    down.focus();
    await fireEvent.click(down);
    await waitFor(() =>
      expect(
        idList()
          .getAllByRole("listitem")
          .map((li) => li.getAttribute("data-identity-id")),
      ).toEqual(["2", "1"]),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Move Work up" }),
      ).toHaveFocus(),
    );
    await fireEvent.click(
      screen.getByRole("button", { name: "Remove Personal from web-shop" }),
    );
    await waitFor(() =>
      expect(idList().getAllByRole("listitem")).toHaveLength(1),
    );
  });

  it("shows what went wrong when a move or a removal is refused", async () => {
    await mount();
    api.refuse = { status: 404, message: "no such identity" };
    await fireEvent.click(
      screen.getByRole("button", { name: "Remove Work from web-shop" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "No such identity.",
    );
    api.git["web-shop"]!.ids = [1, 2];
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    api.refuse = { status: 422, message: "an identity is listed twice" };
    await fireEvent.click(
      screen.getByRole("button", { name: "Move Work down" }),
    );
  });

  it("warns when no identity covers the workspace's own repository", async () => {
    url.id = "docs";
    render(Page);
    expect(
      await screen.findByText(/No identity here covers dev.azure.com\/contoso/),
    ).toBeInTheDocument();
    expect(screen.getByText(/No identity yet/)).toBeInTheDocument();
  });

  it("says when there is nothing to add", async () => {
    api.identities = [];
    await mount();
    expect(screen.getByLabelText("Add an identity")).toBeDisabled();
    expect(screen.getByText("No identities yet")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Make an identity" }),
    ).toHaveAttribute("href", "/identities");
    cleanup();
    api.identities = [identity(1)];
    api.git["web-shop"]!.ids = [1];
    identities.identities = [];
    await mount();
    await waitFor(() =>
      expect(
        screen.getByText("Every identity is on this workspace"),
      ).toBeInTheDocument(),
    );
  });
});

describe("the repository table", () => {
  it("shows a Pull and a Push box per repository and says what each switch means", async () => {
    await mount();
    expect(
      table().getByRole("checkbox", { name: "Push github.com/acme/web-shop" }),
    ).toBeChecked();
    expect(
      table().getByRole("checkbox", {
        name: "Push github.com/acme/design-tokens",
      }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("switch", { name: "Only push to listed repos" }),
    ).toBeChecked();
    expect(
      screen.getByRole("switch", { name: "Only pull from listed repos" }),
    ).not.toBeChecked();
    expect(
      screen.getByText(
        /a fetch may go to any repository the credential can read/,
      ),
    ).toBeInTheDocument();
  });

  it("changes a toggle at once, and puts it back when the change is refused", async () => {
    await mount();
    const pull = table().getByRole("checkbox", {
      name: "Pull github.com/acme/design-tokens",
    });
    await fireEvent.click(pull);
    await waitFor(() =>
      expect(api.git["web-shop"]!.repos[1]!.pull).toBe(false),
    );
    api.refuse = { status: 404, message: "no such repository" };
    const push = table().getByRole("checkbox", {
      name: "Push github.com/acme/design-tokens",
    });
    await fireEvent.click(push);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "No such repository.",
    );
    expect(push).not.toBeChecked();
  });

  it("flips each switch, and keeps it where it was when refused", async () => {
    await mount();
    await fireEvent.click(
      screen.getByRole("switch", { name: "Only pull from listed repos" }),
    );
    await waitFor(() => expect(api.git["web-shop"]!.pull).toBe(true));
    expect(
      await screen.findByText(
        /A fetch is allowed only from a repository whose Pull box is ticked/,
      ),
    ).toBeInTheDocument();
    await fireEvent.click(
      screen.getByRole("switch", { name: "Only push to listed repos" }),
    );
    await waitFor(() => expect(api.git["web-shop"]!.push).toBe(false));
    expect(
      await screen.findByText(/Off: a push may go to any repository/),
    ).toBeInTheDocument();
    api.refuse = { status: 500, message: "no" };
    const pull = screen.getByRole("switch", {
      name: "Only pull from listed repos",
    });
    await fireEvent.click(pull);
    expect(await screen.findByRole("alert")).toHaveTextContent("No.");
    expect(pull).toBeChecked();
  });

  it("removes a row, says so and puts focus on the heading", async () => {
    await mount();
    await fireEvent.click(
      table().getByRole("button", {
        name: "Remove github.com/acme/design-tokens from the list",
      }),
    );
    await waitFor(() =>
      expect(lastToast()).toBe(
        "Removed github.com/acme/design-tokens from the list.",
      ),
    );
    expect(table().queryByText("github.com/acme/design-tokens")).toBeNull();
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Repositories" }),
      ).toHaveFocus(),
    );
    api.refuse = { status: 500, message: "x" };
    await fireEvent.click(
      table().getByRole("button", {
        name: /Remove github.com\/acme\/web-shop/,
      }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "puddle couldn't remove the repository.",
    );
  });

  it("says what an empty table means", async () => {
    api.git["web-shop"]!.repos = [];
    render(Page);
    expect(
      await screen.findByText(
        /No repository is listed\. With Only push to listed repos on, nothing can be pushed\./,
      ),
    ).toBeInTheDocument();
    cleanup();
    api.git["web-shop"]!.push = false;
    render(Page);
    await waitFor(() =>
      expect(screen.getByText("No repository is listed.")).toBeInTheDocument(),
    );
  });
});

describe("adding a repository", () => {
  const url_ = () => screen.getByLabelText("Add a repository");
  const add = () =>
    fireEvent.click(screen.getByRole("button", { name: "Add repository" }));

  it("lists the repository an address names, with the boxes chosen", async () => {
    await mount();
    await fireEvent.input(url_(), {
      target: { value: "https://github.com/Acme/Billing.git" },
    });
    await fireEvent.click(screen.getByLabelText("Push"));
    await add();
    await waitFor(() =>
      expect(lastToast()).toBe("Listed github.com/acme/billing."),
    );
    expect(api.bodies.at(-1)).toEqual({
      host: "github.com",
      owner: "acme",
      repo: "billing",
      pull: true,
      push: false,
    });
    expect(url_()).toHaveValue("");
    expect(table().getByText("github.com/acme/billing")).toBeInTheDocument();
  });

  it("checks the address with the create form's words before it asks", async () => {
    await mount();
    await add();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter the repository's HTTPS URL.",
    );
    expect(url_()).toHaveFocus();
    await fireEvent.input(url_(), {
      target: { value: "git@github.com:acme/x.git" },
    });
    await add();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "SSH remotes are not supported yet",
    );
    await fireEvent.input(url_(), {
      target: { value: "https://github.com/acme" },
    });
    await add();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "not a repository address puddle can read",
    );
    expect(api.calls).not.toContain("POST /api/workspaces/{id}/git/repos");
  });

  it("shows the host's refusal at the field", async () => {
    await mount();
    await fireEvent.input(url_(), {
      target: { value: "https://github.com/acme/web-shop" },
    });
    await add();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "That repository is already listed.",
    );
    expect(url_()).toHaveFocus();
  });
});

describe("the page itself", () => {
  it("says it is loading, and when it cannot be read", async () => {
    api.down = true;
    render(Page);
    expect(screen.getByText(/Loading Git settings/)).toBeInTheDocument();
    expect(
      await screen.findByText(/Couldn't read the Git settings yet/),
    ).toBeInTheDocument();
  });

  it("repeats the trust line about desktop VS Code next to the credentials", async () => {
    await mount();
    expect(
      screen.getByText(/Credentials stay on this computer/),
    ).toHaveTextContent(
      /Opening the workspace in desktop VS Code is different/,
    );
  });
});
