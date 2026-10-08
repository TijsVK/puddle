// SPDX-License-Identifier: GPL-3.0-or-later
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const store = vi.hoisted(() => ({
  report: null as unknown,
  status: "ready" as string,
  reading: false,
  refresh: vi.fn(async () => undefined),
}));
vi.mock("#lib/stores/network-health.svelte.ts", () => ({
  networkHealth: store,
}));

import { report } from "#lib/testing/fake-network.ts";
import Page from "./+page.svelte";

beforeEach(() => {
  store.report = report();
  store.status = "ready";
  store.reading = false;
  store.refresh.mockClear();
});
afterEach(cleanup);

const section = (name: string) =>
  screen.getByRole("heading", { level: 2, name }).closest("section")!;

describe("network health page", () => {
  it("reads the report when it opens and puts focus on the heading", async () => {
    render(Page);
    expect(store.refresh).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(
      screen.getByRole("heading", { level: 1, name: "Network health" }),
    );
  });

  it("shows loading, failure and 'not yet' states plainly", () => {
    store.report = null;
    store.status = "loading";
    render(Page);
    expect(screen.getByText(/Loading/)).toBeInTheDocument();
    cleanup();
    store.status = "failed";
    render(Page);
    expect(screen.getByRole("alert")).toHaveTextContent(/isn't answering/);
    cleanup();
    store.status = "unavailable";
    render(Page);
    expect(screen.getByRole("status")).toHaveTextContent(
      /can't report on the network yet/,
    );
  });

  it("shows a healthy setup: found setup, sign-in method, roots, routes", () => {
    const r = report();
    r.proxy.last_change_at = Date.now() - 3 * 60_000;
    r.proxy.http_proxy = "fb:3128";
    r.proxy.bypass_entries = 1;
    r.sign_in.attempts = [
      {
        proxy: "a:8080",
        scheme: "Negotiate",
        result: "signed_in",
        detail: null,
        at: Date.now(),
      },
      {
        proxy: "b:8080",
        scheme: null,
        result: "not_required",
        detail: "open",
        at: Date.now(),
      },
    ];
    r.roots.certificates = [
      {
        subject: "Corp Root",
        fingerprint: "ab".repeat(32),
        kind: "root",
        not_after: 4102444800000,
        sources: ["LocalMachine\\Root"],
      },
      {
        subject: null,
        fingerprint: "cd".repeat(32),
        kind: "intermediate",
        not_after: 1,
        sources: [],
      },
    ];
    r.routes = [
      {
        scheme: "https",
        host: "github.com",
        port: 443,
        hops: ["PROXY a:8080", "DIRECT"],
        source: "pac",
      },
    ];
    store.report = r;
    render(Page);
    expect(screen.getByText("No problems found.")).toBeInTheDocument();
    const proxy = section("Proxy setup");
    expect(
      within(proxy).getByText("Automatic proxy script (PAC)"),
    ).toBeInTheDocument();
    expect(within(proxy).getByText("fb:3128")).toBeInTheDocument();
    expect(within(proxy).getByText("1 entry")).toBeInTheDocument();
    expect(within(proxy).getByText(/3 minutes ago/)).toBeInTheDocument();
    expect(within(proxy).getByText("None.")).toBeInTheDocument();
    const sign = section("Signing in to the proxy");
    expect(
      within(sign).getByText(/Negotiate \(Kerberos\), NTLM/),
    ).toBeInTheDocument();
    expect(within(sign).getByText("Signed in")).toBeInTheDocument();
    expect(within(sign).getByText("No sign-in needed")).toBeInTheDocument();
    const roots = section("Company certificates");
    expect(within(roots).getByText("Corp Root")).toBeInTheDocument();
    expect(within(roots).getByText("(no name)")).toBeInTheDocument();
    expect(within(roots).getByText("expired")).toBeInTheDocument();
    expect(within(roots).getByText("2100-01-01")).toBeInTheDocument();
    expect(within(roots).getByText("Nothing.")).toBeInTheDocument();
    const routes = section("Routes chosen");
    expect(
      within(routes).getByText("https://github.com:443"),
    ).toBeInTheDocument();
    expect(within(routes).getByText("a:8080, then direct")).toBeInTheDocument();
    expect(within(routes).getByText("Proxy script (PAC)")).toBeInTheDocument();
    expect(within(section("Image downloads")).getAllByText("Yes")).toHaveLength(
      2,
    );
  });

  it("shows trouble with a fix for each item, and singular wording", () => {
    const r = report();
    r.proxy.mode = "direct";
    r.proxy.pac_url = null;
    r.proxy.pac_state = "unreachable";
    r.proxy.auto_detect = false;
    r.proxy.dead_proxies = [{ proxy: "d:1", retry_in_secs: 30 }];
    r.sign_in = {
      methods: [],
      attempts: [
        {
          proxy: "d:1",
          scheme: "Negotiate",
          result: "failed",
          detail: "no ticket",
          at: 1,
        },
      ],
    };
    r.roots = {
      synced: false,
      synced_at: null,
      roots: 0,
      intermediates: 0,
      certificates: [],
      skipped: [
        { subject: "Old", fingerprint: "ee".repeat(32), reason: "expired" },
      ],
      unreadable_stores: ["LM\\Root: access denied"],
      left_out_of_tls: [],
    };
    r.pull_proxy = { active: false, via_upstream: false };
    store.report = r;
    store.status = "unavailable";
    render(Page);
    expect(screen.getByText("3 problems found.")).toBeInTheDocument();
    expect(screen.getAllByText(/What to do:/).length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText(/The latest read failed/)).toBeInTheDocument();
    expect(
      screen.getByText(/It cannot sign in to a proxy on this system/),
    ).toBeInTheDocument();
    expect(
      within(section("Proxy setup")).getByText("30 s"),
    ).toBeInTheDocument();
    expect(
      within(section("Proxy setup")).getByText("None since puddle started"),
    ).toBeInTheDocument();
    expect(
      within(section("Company certificates")).getByText("Not read yet."),
    ).toBeInTheDocument();
    expect(
      within(section("Company certificates")).getByText(
        "LM\\Root: access denied",
      ),
    ).toBeInTheDocument();
    expect(
      within(section("Company certificates")).getByText(/Old/),
    ).toBeInTheDocument();
  });

  it("lists the certificates left out of puddle's own TLS checks, with the reason", () => {
    const r = report();
    r.roots.left_out_of_tls = [
      {
        subject: "Corp CA",
        fingerprint: "cd".repeat(32),
        reason: "not usable",
      },
      { subject: null, fingerprint: "ef".repeat(32), reason: "bad key" },
    ];
    store.report = r;
    render(Page);
    expect(screen.getByText("1 problem found.")).toBeInTheDocument();
    const list = within(section("Company certificates"));
    expect(
      list.getByText("Left out of puddle's own TLS checks"),
    ).toBeInTheDocument();
    expect(list.getByText(/Corp CA/)).toBeInTheDocument();
    expect(list.getByText(/\(no name\)/)).toBeInTheDocument();
    expect(list.getByText(/bad key/)).toBeInTheDocument();
  });

  it("says one problem in the singular, and shows a settings error", () => {
    const r = report();
    r.proxy.settings_error = "no registry";
    store.report = r;
    render(Page);
    expect(screen.getByText("1 problem found.")).toBeInTheDocument();
    expect(
      screen.getByText(/Settings couldn't be read: no registry/),
    ).toBeInTheDocument();
  });

  it("lists a proxy setting puddle cannot use among the problems, drawn as text", () => {
    const r = report();
    r.proxy.problems = [
      {
        kind: "unusable_setting",
        detail:
          'the HTTPS_PROXY variable ("<b>socks5://p:1080</b>"): unsupported',
      },
    ];
    store.report = r;
    render(Page);
    expect(screen.getByText("1 problem found.")).toBeInTheDocument();
    expect(
      screen.getByText(
        /puddle can't use part of the proxy settings: the HTTPS_PROXY variable \("<b>socks5/,
      ),
    ).toBeInTheDocument();
  });

  it("draws text from outside as text, and checks again on request", async () => {
    const r = report();
    r.routes = [
      {
        scheme: "https",
        host: "<img src=x>",
        port: 1,
        hops: [],
        source: "bypass",
      },
    ];
    r.sign_in.attempts = [
      {
        proxy: "p:1",
        scheme: null,
        result: "failed",
        detail: "<b>x</b>",
        at: 1,
      },
    ];
    store.report = r;
    render(Page);
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("td b")).toBeNull();
    await fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    expect(store.refresh).toHaveBeenCalledTimes(2);
  });

  it("disables Check again while a read runs", () => {
    store.reading = true;
    render(Page);
    expect(screen.getByRole("button", { name: /Checking/ })).toBeDisabled();
  });
});
