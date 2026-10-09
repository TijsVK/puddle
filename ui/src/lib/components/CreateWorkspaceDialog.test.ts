// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import {
  credential,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import { FakeRepos, repoSource, repoView } from "#lib/testing/fake-repos.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";
import type { ActionResult } from "#lib/stores/workspaces.svelte.ts";
import type { Workspace } from "#lib/workspaces/model.ts";
import CreateWorkspaceDialog from "./CreateWorkspaceDialog.svelte";

const h = vi.hoisted(() => ({ repos: undefined as unknown, use: vi.fn() }));

vi.mock("#lib/identities/attach.ts", () => ({ useIdentities: h.use }));
vi.mock("#lib/stores/repos.svelte.ts", async (original) => {
  const mod = await original<typeof import("#lib/stores/repos.svelte.ts")>();
  return {
    ...mod,
    RepoLists: class extends mod.RepoLists {
      constructor() {
        super({ api: h.repos as never });
      }
    },
  };
});


vi.mock("$app/navigation", () => ({ goto: vi.fn() }));

afterEach(() => {
  cleanup();
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});

function mount(
  result: ActionResult<Workspace> | (() => Promise<ActionResult<Workspace>>) = {
    ok: true,
    value: workspace("made", { busy: "creating", status: "created" }),
  },
) {
  const create = vi.fn(async (_body: unknown) =>
    typeof result === "function" ? result() : result,
  );
  const onCreated = vi.fn();
  render(CreateWorkspaceDialog, {
    props: { open: true, store: { create }, onCreated },
  } as never);
  return { create, onCreated };
}

const field = (label: string) =>
  screen.getByLabelText(label) as HTMLInputElement;
const submit = () =>
  screen.getByRole("button", { name: /Create workspace|Creating/ });
const type = (label: string, value: string) =>
  fireEvent.input(field(label), { target: { value } });

describe("CreateWorkspaceDialog", () => {
  it("is a dialog with the repository first", async () => {
    mount();
    const dialog = await screen.findByRole("dialog", { name: "New workspace" });
    const first = dialog.querySelector("input");
    expect(first).toBe(field("Git repository (HTTPS)"));
  });

  it("names the workspace after the repository until a name is typed", async () => {
    mount();
    await screen.findByRole("dialog");
    await type(
      "Git repository (HTTPS)",
      "https://github.com/acme/Ledger_Service.git",
    );
    expect(field("Name").value).toBe("ledger-service");
    await type("Name", "mine");
    await type("Git repository (HTTPS)", "https://github.com/acme/other.git");
    expect(field("Name").value).toBe("mine");
  });

  it("sends what was typed, leaving out the image and memory when blank", async () => {
    const { create, onCreated } = mount();
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", " https://github.com/acme/web.git ");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(create).toHaveBeenCalledWith({
      name: "web",
      repo_url: "https://github.com/acme/web.git",
    });
  });

  it("sends the image and the memory in MiB when given", async () => {
    const { create } = mount();
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(screen.getByText("Image and memory"));
    await type("Image", " ghcr.io/acme/dev:1 ");
    await type("Memory (GiB)", "3");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(create).toHaveBeenCalled());
    expect(create).toHaveBeenCalledWith({
      name: "web",
      repo_url: "https://github.com/acme/web.git",
      image: "ghcr.io/acme/dev:1",
      memory_mib: 3072,
    });
  });

  it("checks the fields first and puts focus on the first bad one", async () => {
    const { create } = mount();
    await screen.findByRole("dialog");
    await fireEvent.click(submit());
    expect(screen.getAllByRole("alert")).toHaveLength(2);
    expect(field("Git repository (HTTPS)")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(field("Git repository (HTTPS)")).toHaveFocus();
    expect(create).not.toHaveBeenCalled();
    await type("Git repository (HTTPS)", "git@github.com:acme/web.git");
    await type("Name", "web");
    await fireEvent.click(submit());
    expect(screen.getByRole("alert")).toHaveTextContent(
      "SSH remotes are not supported yet; use the repository's HTTPS URL instead.",
    );
  });

  it("checks the memory field too", async () => {
    const { create } = mount();
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(screen.getByText("Image and memory"));
    await type("Memory (GiB)", "plenty");
    await fireEvent.click(submit());
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter a number of GiB.",
    );
    expect(field("Memory (GiB)")).toHaveFocus();
    expect(create).not.toHaveBeenCalled();
  });

  it.each([
    ["name", "Name", "a workspace named web already exists"],
    ["repo_url", "Git repository (HTTPS)", "use an https:// URL"],
    ["image", "Image", "bad image"],
    ["memory_mib", "Memory (GiB)", "memory is too small"],
  ] as const)(
    "shows a refusal about %s at that field",
    async (fieldName, label, message) => {
      mount({ ok: false, message, field: fieldName });
      await screen.findByRole("dialog");
      await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
      await fireEvent.click(screen.getByText("Image and memory"));
      await fireEvent.click(submit());
      await vi.waitFor(() =>
        expect(screen.getByRole("alert")).toHaveTextContent(message),
      );
      expect(field(label)).toHaveAttribute("aria-invalid", "true");
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    },
  );

  it("shows any other refusal for the whole form, and keeps what was typed", async () => {
    mount({ ok: false, message: "puddle's service isn't answering." });
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(submit());
    await vi.waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "puddle's service isn't answering.",
      ),
    );
    expect(field("Git repository (HTTPS)").value).toBe(
      "https://github.com/acme/web.git",
    );
  });

  it("can't be submitted twice", async () => {
    let finish!: (r: ActionResult<Workspace>) => void;
    const { create } = mount(
      () => new Promise((resolve) => (finish = resolve)),
    );
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(submit());
    expect(screen.getByRole("button", { name: "Creating…" })).toBeDisabled();
    await fireEvent.submit(screen.getByRole("dialog").querySelector("form")!);
    expect(create).toHaveBeenCalledTimes(1);
    finish({ ok: true, value: workspace("web") });
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("forgets what was typed when it is cancelled", async () => {
    mount();
    await screen.findByRole("dialog");
    await type("Name", "half-done");
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
  it("warns with the identity it got when none covers the repository, and offers the Git tab", async () => {
    const { goto } = await import("$app/navigation");
    const warning =
      "No identity covers github.com/acme, so this workspace got your default identity, Personal.";
    mount({
      ok: true,
      value: workspace("made", {
        busy: "creating",
        status: "created",
        identity: { identity: "Personal", basis: "default", warning },
      }),
    });
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(toasts.items).toHaveLength(1));
    const toast = toasts.items[0]!;
    expect(toast.message).toBe(warning);
    expect(toast.tone).toBe("error");
    expect(toast.action?.label).toBe("Open Git tab");
    await toast.action?.run();
    expect(goto).toHaveBeenCalledWith("/workspaces/made/git");
  });

  it("says nothing extra when an identity covers the repository or the answer has no identity", async () => {
    const covered = mount({
      ok: true,
      value: workspace("made", {
        identity: { identity: "Work", basis: "covers", warning: null },
      }),
    });
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/web.git");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(covered.onCreated).toHaveBeenCalled());
    expect(toasts.items).toHaveLength(0);
  });
});

describe("CreateWorkspaceDialog identities and repositories", () => {
  const work = identity(1, {
    label: "Work",
    credentials: [
      credential({
        source: ghSource("tijs-work"),
        owners: ["acme"],
        rest: false,
      }),
    ],
  });
  const personal = identity(2, {
    label: "Personal",
    is_default: false,
    credentials: [credential({ source: ghSource("tijs-demo"), rest: true })],
  });
  const ensureLoaded = vi.fn(async () => {});

  beforeEach(() => {
    const repos = new FakeRepos();
    repos.repos = [repoView("acme", "web", { identities: [2, 1] })];
    repos.sources = [repoSource({ repo_count: 1 })];
    h.repos = repos;
    h.use.mockReset();
    h.use.mockResolvedValue({ ok: true });
    ensureLoaded.mockClear();
    for (const t of [...toasts.items]) toasts.dismiss(t.id);
  });

  function open(
    prefill: { url: string; identity: number | null } | null = null,
  ) {
    const create = vi.fn(async (_body: unknown) => ({
      ok: true as const,
      value: workspace("web", { busy: "creating", status: "created" }),
    }));
    const onCreated = vi.fn();
    render(CreateWorkspaceDialog, {
      props: {
        open: true,
        store: { create },
        identities: { identities: [work, personal], ensureLoaded },
        prefill,
        onCreated,
      },
    } as never);
    return { create, onCreated };
  }

  const box = (name: RegExp) => screen.getByRole("checkbox", { name });

  it("reads the identities when it opens", async () => {
    open();
    await screen.findByRole("dialog");
    expect(ensureLoaded).toHaveBeenCalled();
  });

  it("offers the identities that cover a typed address and ticks the one that covers its owner", async () => {
    open();
    await screen.findByRole("dialog");
    expect(screen.queryByRole("group", { name: "Git identities" })).toBeNull();
    await type("Git repository (HTTPS)", "https://github.com/acme/web");
    expect(screen.getByRole("group", { name: "Git identities" })).toBeVisible();
    expect(box(/Work/)).toBeChecked();
    expect(box(/Personal/)).not.toBeChecked();
    await type("Git repository (HTTPS)", "https://github.com/someone/else");
    expect(screen.queryByRole("checkbox", { name: /Work/ })).toBeNull();
    expect(box(/Personal/)).toBeChecked();
  });

  it("offers nothing for an address no identity covers", async () => {
    open();
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://gitlab.com/acme/web");
    expect(screen.queryByRole("group", { name: "Git identities" })).toBeNull();
  });

  it('fills the repository from "Create a workspace for this" and ticks the identity that listed it', async () => {
    open({ url: "https://github.com/acme/web", identity: 2 });
    await screen.findByRole("dialog");
    expect(field("Git repository (HTTPS)").value).toBe(
      "https://github.com/acme/web",
    );
    expect(field("Name").value).toBe("web");
    expect(box(/Personal.*listed this repository/)).toBeChecked();
    expect(box(/Work/)).not.toBeChecked();
  });

  it("gives the new workspace the ticked identities, the one that listed it first", async () => {
    const { create, onCreated } = open({
      url: "https://github.com/acme/web",
      identity: 2,
    });
    await screen.findByRole("dialog");
    await fireEvent.click(box(/Work/));
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(h.use).toHaveBeenCalled());
    expect(create).toHaveBeenCalled();
    expect(onCreated).toHaveBeenCalled();
    expect(h.use).toHaveBeenCalledWith("web", [2, 1], expect.any(Function));
    expect(h.use.mock.calls[0]?.[2](2)).toBe("Personal");
    expect(h.use.mock.calls[0]?.[2](9)).toBe("Identity 9");
  });

  it("can be told to use no identity, and unticking again restores the choice", async () => {
    open({ url: "https://github.com/acme/web", identity: 1 });
    await screen.findByRole("dialog");
    await fireEvent.click(box(/Work/));
    expect(box(/Work/)).not.toBeChecked();
    await fireEvent.click(box(/Work/));
    expect(box(/Work/)).toBeChecked();
    await fireEvent.click(box(/Work/));
    await fireEvent.click(submit());
    await vi.waitFor(() =>
      expect(h.use).toHaveBeenCalledWith("web", [], expect.any(Function)),
    );
  });

  it("says when the identities could not be set, and that the workspace was made", async () => {
    h.use.mockResolvedValue({
      ok: false,
      message: "Work and Personal both cover x.",
    });
    open({ url: "https://github.com/acme/web", identity: 1 });
    await screen.findByRole("dialog");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(toasts.items.length).toBe(1));
    expect(toasts.items[0]?.message).toContain("The workspace was made");
    expect(toasts.items[0]?.message).toContain(
      "Work and Personal both cover x.",
    );
    expect(toasts.items[0]?.message).toContain("Git tab");
  });

  it("touches no identity when none covers the address", async () => {
    open();
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://gitlab.com/acme/web");
    await fireEvent.click(submit());
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(h.use).not.toHaveBeenCalled();
  });

  it("takes the repository and identity of a pick from the list", async () => {
    open();
    await screen.findByRole("dialog");
    await fireEvent.click(screen.getByText("Choose from your repositories"));
    await fireEvent.click(
      await screen.findByRole("button", { name: /acme\/web/ }),
    );
    expect(field("Git repository (HTTPS)").value).toBe(
      "https://github.com/acme/web",
    );
    expect(field("Name")).toHaveFocus();
    // The list names Personal first, so it listed the repository first.
    expect(box(/Personal.*listed this repository/)).toBeChecked();
  });

  it("forgets the identity that listed it when the address is typed over", async () => {
    open({ url: "https://github.com/acme/web", identity: 2 });
    await screen.findByRole("dialog");
    await type("Git repository (HTTPS)", "https://github.com/acme/api");
    expect(box(/Work/)).toBeChecked();
    expect(screen.queryByText(/listed this repository/)).toBeNull();
  });

  it("warns about an Azure DevOps project with a space in the address", async () => {
    open();
    await screen.findByRole("dialog");
    await type(
      "Git repository (HTTPS)",
      "https://dev.azure.com/contoso/Shop%20Floor/_git/scanner",
    );
    expect(screen.getByTestId("table-cannot-hold")).toHaveTextContent(
      "Only push to listed repos",
    );
  });
});
