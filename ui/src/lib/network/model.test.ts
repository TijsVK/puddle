// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  attemptKey,
  expiryText,
  findings,
  fixedProxies,
  hopsText,
  methodLabel,
  problemSummary,
  problems,
  waitText,
  type NetworkHealth,
} from "./model.ts";
import { isNetworkChanged } from "./events.ts";
import { report } from "#lib/testing/fake-network.ts";

const ids = (r: NetworkHealth) => findings(r).map((f) => f.id);

describe("findings", () => {
  it("finds nothing wrong on a healthy report", () => {
    expect(findings(report())).toEqual([]);
    expect(problems(report())).toEqual([]);
    expect(problemSummary([])).toBe("");
  });

  it("names an unreadable system setting and says what to do", () => {
    const r = report();
    r.proxy.settings_error = "registry key missing";
    const [f] = findings(r);
    expect(f).toMatchObject({ id: "settings-error", level: "problem" });
    expect(f?.title).toContain("registry key missing");
    expect(f?.fix).toMatch(/network settings/);
  });

  it("names a PAC that does not answer, with or without its address", () => {
    const r = report();
    r.proxy.pac_state = "unreachable";
    expect(findings(r)[0]?.title).toContain("http://wpad.corp.example");
    r.proxy.pac_url = null;
    expect(findings(r)[0]?.title).toContain("the proxy script");
  });

  it("explains a failed sign-in with the scheme and detail when there are some", () => {
    const r = report();
    r.sign_in.attempts = [
      {
        proxy: "p:8080",
        scheme: "Negotiate",
        result: "failed",
        detail: "no ticket",
        at: 1,
      },
      { proxy: "q:8080", scheme: null, result: "failed", detail: null, at: 2 },
      {
        proxy: "r:8080",
        scheme: "Basic",
        result: "signed_in",
        detail: null,
        at: 3,
      },
      {
        proxy: "s:8080",
        scheme: null,
        result: "not_required",
        detail: null,
        at: 4,
      },
    ];
    const list = findings(r);
    expect(list.map((f) => f.id)).toEqual(["sign-in-p:8080", "sign-in-q:8080"]);
    expect(list[0]?.title).toBe(
      "Signing in to p:8080 failed (Negotiate): no ticket",
    );
    expect(list[1]?.title).toBe("Signing in to q:8080 failed.");
    expect(list[0]?.fix).toMatch(/logged in/);
  });

  it("explains an unsupported sign-in by what puddle can answer", () => {
    const r = report();
    r.sign_in.attempts = [
      {
        proxy: "p:1",
        scheme: null,
        result: "unsupported",
        detail: "wants Digest",
        at: 1,
      },
    ];
    expect(findings(r)[0]?.title).toContain("wants Digest");
    expect(findings(r)[0]?.fix).toContain("Negotiate (Kerberos), NTLM");
    r.sign_in.methods = [];
    r.sign_in.attempts[0]!.detail = null;
    expect(findings(r)[0]?.title).toBe(
      "p:1 asks for a sign-in puddle can't give.",
    );
    expect(findings(r)[0]?.fix).toMatch(/no way to sign in/);
  });

  it("reports unreadable stores with a count, and does not also say the roots are unread", () => {
    const r = report();
    r.roots.synced = false;
    r.roots.unreadable_stores = ["A: denied"];
    expect(ids(r)).toEqual(["unreadable-stores"]);
    expect(findings(r)[0]?.title).toBe(
      "puddle couldn't read a certificate store.",
    );
    r.roots.unreadable_stores = ["A: denied", "B: denied"];
    expect(findings(r)[0]?.title).toBe(
      "puddle couldn't read 2 certificate stores.",
    );
  });

  it("lists notes after problems: dead proxies, unread roots, skipped roots, pull proxy", () => {
    const r = report();
    r.proxy.dead_proxies = [{ proxy: "b:8080", retry_in_secs: 212 }];
    r.roots.synced = false;
    r.roots.skipped = [{ subject: null, fingerprint: "ff", reason: "expired" }];
    r.pull_proxy = { active: false, via_upstream: false };
    r.proxy.settings_error = "x";
    expect(ids(r)).toEqual([
      "settings-error",
      "dead-b:8080",
      "roots-not-read",
      "roots-skipped",
      "pull-off",
    ]);
    const dead = findings(r).find((f) => f.id === "dead-b:8080");
    expect(dead?.title).toContain("4 min");
    r.roots.skipped.push({ subject: "B", fingerprint: "ee", reason: "x" });
    expect(findings(r).find((f) => f.id === "roots-skipped")?.title).toMatch(
      /^2 certificates were/,
    );
  });

  it("notes image downloads that skip the company proxy only when a proxy was found", () => {
    const r = report();
    r.pull_proxy = { active: true, via_upstream: false };
    expect(ids(r)).toEqual(["pull-direct"]);
    r.proxy.detected = "direct";
    expect(ids(r)).toEqual([]);
  });

  it("summarises the problems", () => {
    const r = report();
    r.proxy.settings_error = "x";
    r.proxy.pac_state = "unreachable";
    const list = problems(r);
    expect(problemSummary(list)).toMatch(/\(and 1 more\)$/);
    expect(problemSummary(list.slice(0, 1))).toBe(list[0]?.title);
  });
});

describe("words", () => {
  it("writes routes, waits, expiry and methods", () => {
    expect(hopsText([])).toBe("none");
    expect(hopsText(["PROXY a:1", "DIRECT"])).toBe("a:1, then direct");
    expect(waitText(45)).toBe("45 s");
    expect(waitText(-3)).toBe("0 s");
    expect(waitText(180)).toBe("3 min");
    expect(expiryText(100, 200)).toBe("expired");
    expect(expiryText(4102444800000, 200)).toBe("2100-01-01");
    expect(methodLabel("basic")).toBe("Basic");
    expect(methodLabel("digest")).toBe("digest");
    expect(
      attemptKey({
        proxy: "p:1",
        scheme: null,
        result: "failed",
        detail: null,
        at: 5,
      }),
    ).toBe("p:1|5");
  });

  it("lists fixed proxies once each", () => {
    const r = report();
    expect(fixedProxies(r.proxy)).toEqual([]);
    r.proxy.http_proxy = "a:1";
    r.proxy.https_proxy = "a:1";
    expect(fixedProxies(r.proxy)).toEqual(["a:1"]);
    r.proxy.https_proxy = "b:2";
    expect(fixedProxies(r.proxy)).toEqual(["a:1", "b:2"]);
  });

  it("recognises the network_changed event and nothing looser", () => {
    expect(isNetworkChanged({ type: "network_changed", epoch: 2 })).toBe(true);
    expect(isNetworkChanged({ type: "network_changed" })).toBe(false);
    expect(isNetworkChanged({ type: "rules_changed" })).toBe(false);
    expect(isNetworkChanged(null)).toBe(false);
    expect(isNetworkChanged("network_changed")).toBe(false);
  });
});
