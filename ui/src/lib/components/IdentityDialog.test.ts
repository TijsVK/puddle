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
import { IdentitiesStore } from "#lib/stores/identities.svelte.ts";
import {
  credential,
  FakeIdentities,
  ghSource,
  identity,
} from "#lib/testing/fake-identities.ts";
import IdentityDialog from "./IdentityDialog.svelte";

let api: FakeIdentities;
let store: IdentitiesStore;
let onSaved: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  api = new FakeIdentities();
  api.found = {
    accounts: [
      {
        via: "gh",
        host: "github.com",
        account: "tijs-work",
        org: null,
        signed_in: true,
      },
    ],
    problems: [],
  };
  store = new IdentitiesStore({ api: api as never });
  onSaved = vi.fn();
});
afterEach(cleanup);

function mount(props: {
  mode: "create" | "edit";
  identity?: never;
  open?: boolean;
}) {
  return render(IdentityDialog, {
    open: true,
    store,
    onSaved,
    ...props,
  } as never);
}

const type = (label: string | RegExp, value: string) =>
  fireEvent.input(screen.getByLabelText(label), { target: { value } });
const dialog = () => screen.getByRole("dialog");

describe("adding an identity", () => {
  it("makes one with an author and a credential found on this computer", async () => {
    mount({ mode: "create" });
    expect(dialog()).toHaveTextContent("Add identity");
    await type("Identity name", "Work");
    await fireEvent.input(screen.getByLabelText("Author name"), {
      target: { value: "Tijs Work" },
    });
    await fireEvent.input(screen.getByLabelText("Author email"), {
      target: { value: "tijs@acme.example" },
    });
    await fireEvent.click(
      screen.getByRole("button", { name: "Add a credential" }),
    );
    await fireEvent.click(
      await screen.findByLabelText(/tijs-work on github.com/),
    );
    await fireEvent.click(
      screen.getByRole("button", { name: "Add credential" }),
    );
    expect(
      await screen.findByText(
        "gh · tijs-work · github.com: the rest of github.com",
      ),
    ).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(onSaved.mock.calls[0]![0]).toMatchObject({
      label: "Work",
      author: { name: "Tijs Work", email: "tijs@acme.example" },
    });
    expect(store.identities).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("checks the name and the author first and puts focus on the first problem", async () => {
    api.identities = [identity(1, { label: "Work" })];
    await store.refresh();
    mount({ mode: "create" });
    const save = () =>
      fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    await save();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Give the identity a name",
    );
    expect(screen.getByLabelText("Identity name")).toHaveFocus();
    await type("Identity name", "work");
    await save();
    expect(screen.getByRole("alert")).toHaveTextContent("already called work");
    await type("Identity name", "Home");
    await save();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter the name Git writes",
    );
    await fireEvent.input(screen.getByLabelText("Author name"), {
      target: { value: "A" },
    });
    await save();
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the email");
    expect(api.calls).not.toContain("POST /api/identities");
  });

  it("shows the host's refusal and stays open", async () => {
    mount({ mode: "create" });
    await type("Identity name", "Home");
    await fireEvent.input(screen.getByLabelText("Author name"), {
      target: { value: "A" },
    });
    await fireEvent.input(screen.getByLabelText("Author email"), {
      target: { value: "a@b.example" },
    });
    api.refuse = { status: 409, message: "the label is taken" };
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The label is taken.",
    );
    expect(onSaved).not.toHaveBeenCalled();
    expect(dialog()).toBeInTheDocument();
  });

  it("closes the credential editor without adding anything", async () => {
    mount({ mode: "create" });
    await fireEvent.click(
      screen.getByRole("button", { name: "Add a credential" }),
    );
    const editor = await screen.findByRole("form", {
      name: "Add a credential",
    });
    await fireEvent.click(
      within(editor).getByRole("button", { name: "Cancel" }),
    );
    expect(screen.queryByRole("form", { name: "Add a credential" })).toBeNull();
    expect(
      screen.getByRole("button", { name: "Add a credential" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/None yet/)).toBeInTheDocument();
  });

  it("says an identity may have no credential yet", () => {
    mount({ mode: "create" });
    expect(screen.getByText(/None yet/)).toBeInTheDocument();
  });
});

describe("a token pasted into the dialog", () => {
  async function pasteOne() {
    await fireEvent.click(
      screen.getByRole("button", { name: "Add a credential" }),
    );
    await fireEvent.click(screen.getByLabelText("Paste a token"));
    await type("Token", "ghp_x");
    await fireEvent.click(
      screen.getByRole("button", { name: "Add credential" }),
    );
    await screen.findByRole("button", { name: /^Remove Pasted token/ });
  }

  it("is taken back when the dialog is cancelled", async () => {
    mount({ mode: "create" });
    await pasteOne();
    expect(api.tokens).toHaveLength(1);
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(api.tokens).toHaveLength(0));
  });

  it("is taken back when its credential is removed again", async () => {
    mount({ mode: "create" });
    await pasteOne();
    await fireEvent.click(
      screen.getByRole("button", { name: /^Remove Pasted token/ }),
    );
    await waitFor(() => expect(api.tokens).toHaveLength(0));
    expect(screen.getByText(/None yet/)).toBeInTheDocument();
  });

  it("stays when the identity is saved", async () => {
    mount({ mode: "create" });
    await type("Identity name", "Home");
    await fireEvent.input(screen.getByLabelText("Author name"), {
      target: { value: "A" },
    });
    await fireEvent.input(screen.getByLabelText("Author email"), {
      target: { value: "a@b.example" },
    });
    await pasteOne();
    await fireEvent.click(screen.getByRole("button", { name: "Add identity" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(api.tokens).toHaveLength(1);
  });
});

describe("editing an identity", () => {
  const existing = () =>
    identity(5, {
      label: "Work",
      credentials: [
        credential({
          source: ghSource("tijs-work"),
          owners: ["acme"],
          rest: false,
        }),
        credential({
          host: "dev.azure.com",
          source: {
            kind: "stored",
            id: "tok-old",
            host: "dev.azure.com",
            org: "contoso",
          },
          owners: ["contoso"],
          rest: false,
        }),
      ],
    });

  it("starts from the identity and saves a replaced credential list", async () => {
    api.identities = [existing()];
    await store.refresh();
    mount({ mode: "edit", identity: store.identities[0] as never });
    expect(dialog()).toHaveTextContent("Edit identity");
    expect(screen.getByLabelText("Identity name")).toHaveValue("Work");
    await fireEvent.click(screen.getByRole("button", { name: /^Remove gh/ }));
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(store.identities[0]!.credentials).toHaveLength(1);
    expect(api.bodies.at(-1)).toMatchObject({ label: "Work" });
  });

  it("removes the token of a credential the save took away, and only then", async () => {
    api.identities = [existing()];
    api.tokens = ["tok-old"];
    await store.refresh();
    mount({ mode: "edit", identity: store.identities[0] as never });
    await fireEvent.click(
      screen.getByRole("button", { name: /^Remove Pasted token/ }),
    );
    // Nothing is removed before Save: a cancel would otherwise lose a working credential.
    expect(api.tokens).toEqual(["tok-old"]);
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.tokens).toEqual([]));
  });

  it("keeps the existing token when the edit is cancelled", async () => {
    api.identities = [existing()];
    api.tokens = ["tok-old"];
    await store.refresh();
    mount({ mode: "edit", identity: store.identities[0] as never });
    await fireEvent.click(
      screen.getByRole("button", { name: /^Remove Pasted token/ }),
    );
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await Promise.resolve();
    expect(api.tokens).toEqual(["tok-old"]);
  });

  it("lets the same name stand for itself", async () => {
    api.identities = [existing()];
    await store.refresh();
    mount({ mode: "edit", identity: store.identities[0] as never });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });
});
