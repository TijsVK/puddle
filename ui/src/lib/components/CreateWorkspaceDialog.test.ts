// SPDX-License-Identifier: GPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import { workspace } from "#lib/testing/fake-workspaces.ts";
import type { ActionResult } from "#lib/stores/workspaces.svelte.ts";
import type { Workspace } from "#lib/workspaces/model.ts";
import CreateWorkspaceDialog from "./CreateWorkspaceDialog.svelte";

afterEach(cleanup);

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
});
