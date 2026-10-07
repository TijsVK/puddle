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
import { toasts } from "#lib/stores/toasts.svelte.ts";
import { theme } from "#lib/theme/theme.svelte.ts";
import Page from "./+page.svelte";

beforeEach(() => {
  api.reset();
  globalSettings.view = null;
  globalSettings.consents = null;
  globalSettings.status = "loading";
  toasts.items = [];
  localStorage.clear();
  delete document.documentElement.dataset["theme"];
  theme.choice = "system";
});
afterEach(cleanup);

async function open() {
  render(Page);
  await screen.findByRole("heading", { level: 2, name: "Appearance" });
}

async function choose(label: string | RegExp, value: string) {
  const select = screen.getByLabelText(label) as HTMLSelectElement;
  select.value = value;
  await fireEvent.change(select);
}

const putBodies = () =>
  api.calls
    .map((c, i) => [c, api.bodies[i]] as const)
    .filter(([c]) => c === "PUT /api/settings");

describe("the screen", () => {
  it("has one h1, every section and the stored values", async () => {
    api.layer.memory = 4096;
    await open();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    const names = screen
      .getAllByRole("heading", { level: 2 })
      .map((h) => h.textContent);
    expect(names).toEqual([
      "Appearance",
      "Notifications",
      "Workspaces",
      "Network",
      "Browser VS Code",
      "Git and credentials",
      "Privacy",
      "About",
    ]);
    expect(screen.getByLabelText("Default memory")).toHaveValue("4096");
    expect(screen.getByLabelText("Theme")).toHaveValue("system");
    expect(
      screen.getByLabelText("System notifications for new requests"),
    ).toBeChecked();
    expect(screen.getByLabelText("Sound")).not.toBeChecked();
    expect(screen.getByLabelText("Zoom shortcuts")).toBeChecked();
    expect(screen.getByLabelText("Server")).toHaveValue("code_server");
    expect(screen.getByText(/Open VSX/)).toBeInTheDocument();
  });

  it("links to the network health details", async () => {
    await open();
    expect(screen.getByRole("link", { name: /Details/ })).toHaveAttribute(
      "href",
      "/settings/network-health",
    );
  });

  it("states that puddle sends nothing", async () => {
    await open();
    expect(
      screen.getByText(/puddle sends nothing about you or your use of it/),
    ).toBeInTheDocument();
  });

  it("says when the settings can't be read, and when a newer puddle wrote them", async () => {
    api.down = true;
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Couldn't read puddle's settings.",
    );
    cleanup();
    api.down = false;
    globalSettings.status = "loading";
    api.refuse.set("GET /api/settings", {
      status: 409,
      error: "newer_settings",
      message: "newer",
    });
    render(Page);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /newer puddle\. Update puddle/,
    );
  });

  it("shows puddle's version and loads the licences when asked", async () => {
    api.version = "9.8.7";
    await open();
    expect(await screen.findByText("puddle 9.8.7")).toBeInTheDocument();
    await fireEvent.click(screen.getByText("Third-party licences"));
    const text = await screen.findByLabelText("Third-party licences", {
      selector: "pre",
    });
    expect(text.textContent).toMatch(/Third-party software shipped/);
  });
});

describe("appearance and notifications", () => {
  it("stores the theme in the settings, and keeps a hint for the first paint", async () => {
    await open();
    await choose("Theme", "dark");
    await screen.findByText("Theme saved.");
    expect(api.ui.theme).toBe("dark");
    expect(document.documentElement.dataset["theme"]).toBe("dark");
    expect(localStorage.getItem("puddle.theme")).toBe("dark");
  });

  it("says when the theme applied but could not be stored", async () => {
    await open();
    api.refuse.set("PUT /api/settings", {
      status: 500,
      error: "internal",
      message: "x",
    });
    await choose("Theme", "light");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /couldn't save it/,
    );
    expect(document.documentElement.dataset["theme"]).toBe("light");
  });

  it("saves each notification setting", async () => {
    await open();
    await fireEvent.click(
      screen.getByLabelText("System notifications for new requests"),
    );
    await screen.findByText("Notifications saved.");
    expect(api.ui.notifications).toBe(false);
    await fireEvent.click(screen.getByLabelText("Sound"));
    await waitFor(() => expect(api.ui.sound).toBe(true));
    await choose("Closing the window", "quit");
    await waitFor(() => expect(api.ui.close_behaviour).toBe("quit"));
  });

  it("puts a control back when the save is refused", async () => {
    await open();
    api.refuse.set("PUT /api/settings", {
      status: 422,
      error: "invalid",
      message: "no thanks",
    });
    const box = screen.getByLabelText("Sound");
    await fireEvent.click(box);
    expect(await screen.findByRole("alert")).toHaveTextContent("no thanks");
    await waitFor(() => expect(box).not.toBeChecked());
    expect(api.ui.sound).toBeNull();
  });
});

describe("workspace defaults and the network", () => {
  it("changes the default memory", async () => {
    await open();
    await choose("Default memory", "16384");
    await screen.findByText("Default memory saved.");
    expect(api.layer.memory).toBe(16_384);
  });

  it("switches a local category on without touching the others", async () => {
    await open();
    await fireEvent.click(screen.getByLabelText("Private networks"));
    await screen.findByText("Private networks saved.");
    expect(api.layer.local_toggles.private).toBe(true);
    expect(api.layer.local_toggles.loopback).toBeNull();
    await fireEvent.click(screen.getByLabelText("This computer (loopback)"));
    await waitFor(() => expect(api.layer.local_toggles.loopback).toBe(true));
    expect(api.layer.local_toggles.private).toBe(true);
  });

  it("explains that a toggle only makes a destination approvable", async () => {
    await open();
    expect(
      screen.getByText(/each one still needs a rule or your approval/),
    ).toBeInTheDocument();
  });

  it("saves suffix-rule reach, zoom and clipboard", async () => {
    await open();
    await fireEvent.click(
      screen.getByLabelText("Let suffix rules reach local addresses"),
    );
    await waitFor(() => expect(api.layer.wildcards_reach_local).toBe(true));
    await fireEvent.click(screen.getByLabelText("Zoom shortcuts"));
    await waitFor(() => expect(api.layer.zoom_hotkeys).toBe(false));
    await choose("Clipboard reads by pages", "deny");
    await waitFor(() => expect(api.layer.clipboard_read).toBe("deny"));
  });

  it("checks the reconnection grace before saving it", async () => {
    await open();
    const input = screen.getByLabelText("Reconnection grace (seconds)");
    await fireEvent.input(input, { target: { value: "5" } });
    await fireEvent.change(input);
    expect(await screen.findByText(/Use between 30 and 86400/)).toBeVisible();
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(putBodies()).toHaveLength(0);
    await fireEvent.input(input, { target: { value: "600" } });
    await fireEvent.change(input);
    await screen.findByText("Grace saved.");
    expect(api.layer.reconnection_grace).toBe(600);
    expect(screen.queryByText(/Use between/)).toBeNull();
  });
});

describe("Microsoft's server", () => {
  async function pick() {
    await open();
    await choose("Server", "microsoft");
    return await screen.findByRole("dialog");
  }

  it("asks first, in the agreed words, with telemetry unchecked", async () => {
    const dialog = await pick();
    expect(
      within(dialog).getByRole("heading", {
        name: "Use Microsoft's VS Code server?",
      }),
    ).toBeInTheDocument();
    expect(dialog).toHaveTextContent(
      "puddle downloads the server from Microsoft",
    );
    const link = within(dialog).getByRole("link", {
      name: /Microsoft VS Code Server licence terms/,
    });
    expect(link).toHaveAttribute(
      "href",
      "https://code.visualstudio.com/license/server",
    );
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    expect(
      within(dialog).getByLabelText(
        "Allow the server to send telemetry to Microsoft",
      ),
    ).not.toBeChecked();
    // Nothing is stored yet, and the select still shows code-server.
    expect(api.consent.state).toBe("not_asked");
    expect(screen.getByLabelText("Server")).toHaveValue("code_server");
  });

  it("keeps code-server and records nothing when declined", async () => {
    const dialog = await pick();
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Keep code-server" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.consent.state).toBe("not_asked");
    expect(api.vscode.server).toBeNull();
    expect(api.calls.filter((c) => c.startsWith("PUT"))).toEqual([]);
  });

  it("records the consent with the terms version and chooses the server", async () => {
    const dialog = await pick();
    await fireEvent.click(
      within(dialog).getByLabelText(
        "Allow the server to send telemetry to Microsoft",
      ),
    );
    await fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Accept and use Microsoft's server",
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.consent).toMatchObject({
      state: "granted",
      terms_version: MS_TERMS_VERSION,
    });
    expect(api.vscode).toMatchObject({ server: "microsoft", telemetry: true });
    expect(screen.getByLabelText("Server")).toHaveValue("microsoft");
    expect(screen.getByLabelText("Send Microsoft telemetry")).toBeChecked();
    expect(screen.getByText(/You accepted Microsoft's terms on/)).toBeVisible();
    expect(toasts.items[0]?.message).toMatch(/Consent recorded/);
  });

  it("starts every popup with telemetry off", async () => {
    const dialog = await pick();
    await fireEvent.click(
      within(dialog).getByLabelText(
        "Allow the server to send telemetry to Microsoft",
      ),
    );
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Keep code-server" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await choose("Server", "microsoft");
    const again = await screen.findByRole("dialog");
    expect(
      within(again).getByLabelText(
        "Allow the server to send telemetry to Microsoft",
      ),
    ).not.toBeChecked();
  });

  it("keeps the popup open and says why when puddle refuses", async () => {
    const dialog = await pick();
    api.refuse.set("PUT /api/consents/{kind}", {
      status: 500,
      error: "internal",
      message: "disk is full",
    });
    await fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Accept and use Microsoft's server",
      }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "disk is full",
    );
    expect(api.vscode.server).toBeNull();
  });

  it("does not ask again once the terms were accepted, and can switch back", async () => {
    api.consent = {
      state: "granted",
      at: 1_700_000_000_000,
      terms_version: MS_TERMS_VERSION,
    };
    await open();
    await choose("Server", "microsoft");
    await screen.findByText("Server saved.");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.vscode.server).toBe("microsoft");
    await fireEvent.click(screen.getByLabelText("Send Microsoft telemetry"));
    await waitFor(() => expect(api.vscode.telemetry).toBe(true));
    await choose("Server", "code_server");
    await waitFor(() => expect(api.vscode.server).toBe("code_server"));
    expect(screen.queryByLabelText("Send Microsoft telemetry")).toBeNull();
    expect(api.consent.state).toBe("granted");
  });

  it("asks again when the terms changed since the user agreed", async () => {
    api.consent = { state: "granted", at: 1, terms_version: "older-terms" };
    await open();
    await choose("Server", "microsoft");
    expect(await screen.findByRole("dialog")).toBeVisible();
  });

  it("saves automatic updates", async () => {
    await open();
    await fireEvent.click(
      screen.getByLabelText("Update the server automatically"),
    );
    await waitFor(() => expect(api.vscode.auto_update).toBe(false));
  });
});
