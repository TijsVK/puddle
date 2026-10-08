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

const api = await vi.hoisted(async () => {
  const mod = await import("#lib/testing/fake-settings.ts");
  return new mod.FakeSettings();
});
vi.mock("#lib/api/client.ts", () => ({ api }));

import { MS_TERMS_VERSION } from "#lib/settings/model.ts";
import { globalSettings } from "#lib/stores/global-settings.svelte.ts";
import Page from "./+page.svelte";

beforeEach(() => {
  api.reset();
  globalSettings.view = null;
  globalSettings.consents = null;
  globalSettings.status = "loading";
});
afterEach(cleanup);

const codeServer = () =>
  screen.getByRole("radio", { name: /code-server \(bundled\)/ });
const microsoft = () =>
  screen.getByRole("radio", { name: /Microsoft's VS Code server/ });
const directSsh = () =>
  screen.getByRole("checkbox", {
    name: /Allow direct SSH for new workspaces/,
  });
const puts = () => api.calls.filter((c) => c === "PUT /api/settings").length;

async function open() {
  render(Page);
  await screen.findByRole("group", { name: "Editor in your browser" });
}

describe("connect step", () => {
  it("shows the stored choices, code-server and direct SSH off by default", async () => {
    await open();
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "How do you want to connect?",
      }),
    ).toHaveFocus();
    expect(codeServer()).toBeChecked();
    expect(microsoft()).not.toBeChecked();
    expect(directSsh()).not.toBeChecked();
    expect(screen.getByText("default")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back" })).toHaveAttribute(
      "href",
      "/welcome/certificates",
    );
    expect(screen.getByRole("link", { name: "Continue" })).toHaveAttribute(
      "href",
      "/welcome/look",
    );
  });

  it("shows what is stored when it was chosen before", async () => {
    api.vscode.server = "microsoft";
    api.consent = {
      state: "granted",
      at: 1,
      terms_version: MS_TERMS_VERSION,
    };
    api.layer.direct_ssh = true;
    await open();
    expect(microsoft()).toBeChecked();
    expect(directSsh()).toBeChecked();
  });

  it("says it is loading, and when the settings can't be read or are from a newer puddle", async () => {
    render(Page);
    expect(screen.getByText(/Loading/)).toBeInTheDocument();
    await screen.findByRole("group", { name: "Editor in your browser" });
    cleanup();

    globalSettings.view = null;
    globalSettings.status = "loading";
    api.down = true;
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Couldn't read puddle's settings.",
    );
    cleanup();

    api.down = false;
    globalSettings.view = null;
    globalSettings.status = "loading";
    api.refuse.set("GET /api/settings", {
      status: 409,
      error: "newer_settings",
      message: "newer",
    });
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /saved by a newer puddle/,
    );
    expect(screen.queryByRole("radio")).toBeNull();
  });

  it("asks before choosing Microsoft's server, and keeps code-server when declined", async () => {
    await open();
    await fireEvent.click(microsoft());
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(
      "puddle downloads the server from Microsoft",
    );
    // Nothing is chosen until the popup is accepted.
    expect(codeServer()).toBeChecked();
    expect(microsoft()).not.toBeChecked();
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Keep code-server" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(puts()).toBe(0);
    expect(api.consent.state).toBe("not_asked");
    expect(codeServer()).toBeChecked();
  });

  it("records the consent and the telemetry answer, then uses Microsoft's server", async () => {
    await open();
    await fireEvent.click(microsoft());
    const dialog = await screen.findByRole("dialog");
    await fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Accept and use Microsoft's server",
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(await screen.findByText("Microsoft's server chosen.")).toBeVisible();
    expect(api.consent).toMatchObject({
      state: "granted",
      terms_version: MS_TERMS_VERSION,
    });
    expect(api.vscode.server).toBe("microsoft");
    expect(api.vscode.telemetry).toBe(false);
    expect(microsoft()).toBeChecked();
  });

  it("keeps the popup open and says why when puddle refuses the consent", async () => {
    await open();
    await fireEvent.click(microsoft());
    const dialog = await screen.findByRole("dialog");
    api.refuse.set("PUT /api/consents/{kind}", {
      status: 422,
      error: "invalid",
      message: "terms not accepted here",
    });
    await fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Accept and use Microsoft's server",
      }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "terms not accepted here",
    );
    expect(api.vscode.server).toBeNull();
  });

  it("switches servers without a popup once the terms were accepted", async () => {
    api.consent = {
      state: "granted",
      at: 1,
      terms_version: MS_TERMS_VERSION,
    };
    await open();
    await fireEvent.click(microsoft());
    expect(await screen.findByText("Server saved.")).toBeVisible();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.vscode.server).toBe("microsoft");
    await fireEvent.click(codeServer());
    await waitFor(() => expect(api.vscode.server).toBe("code_server"));
    expect(codeServer()).toBeChecked();
  });

  it("puts the radio back and says so when puddle refuses the choice", async () => {
    api.consent = {
      state: "granted",
      at: 1,
      terms_version: MS_TERMS_VERSION,
    };
    await open();
    api.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "no can do",
    });
    await fireEvent.click(microsoft());
    expect(await screen.findByRole("alert")).toHaveTextContent("no can do");
    await waitFor(() => expect(codeServer()).toBeChecked());
    expect(microsoft()).not.toBeChecked();
  });

  it("turns the direct-SSH default on only after the trust text", async () => {
    await open();
    await fireEvent.click(directSsh());
    const dialog = await screen.findByRole("alertdialog", {
      name: "Allow direct SSH for new workspaces?",
    });
    expect(dialog).toHaveTextContent("signed-in GitHub token");
    expect(directSsh()).not.toBeChecked();
    expect(puts()).toBe(0);
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Allow for new workspaces" }),
    );
    expect(await screen.findByText("Allow direct SSH saved.")).toBeVisible();
    expect(api.layer.direct_ssh).toBe(true);
    expect(directSsh()).toBeChecked();
  });

  it("cancelling the trust text changes nothing", async () => {
    await open();
    await fireEvent.click(directSsh());
    const dialog = await screen.findByRole("alertdialog");
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Cancel" }),
    );
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(directSsh()).not.toBeChecked();
    expect(puts()).toBe(0);
  });

  it("turns direct SSH off at once, and puts the box back when that is refused", async () => {
    api.layer.direct_ssh = true;
    await open();
    await fireEvent.click(directSsh());
    await screen.findByText("Allow direct SSH saved.");
    expect(api.layer.direct_ssh).toBe(false);
    expect(directSsh()).not.toBeChecked();

    api.layer.direct_ssh = true;
    await globalSettings.load(true);
    await waitFor(() => expect(directSsh()).toBeChecked());
    api.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "refused it",
    });
    await fireEvent.click(directSsh());
    expect(await screen.findByRole("alert")).toHaveTextContent("refused it");
    await waitFor(() => expect(directSsh()).toBeChecked());
  });
});
