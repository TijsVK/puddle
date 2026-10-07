// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  DURATIONS,
  build,
  describe as describeChoice,
  durationPhrase,
  isIpLiteral,
  narrowest,
  needsConfirm,
  patternLabel,
  suffixFor,
  type Choice,
  type Effect,
  type Match,
  type Scope,
  type Target,
} from "./model.ts";

const target: Target = {
  host: "api.registry.example.co.uk",
  registrableDomain: "example.co.uk",
};
const bare: Target = { host: "example.com", registrableDomain: "example.com" };
const ip: Target = { host: "192.168.1.10", registrableDomain: "192.168.1.10" };

/** Every choice the model can express: the space is small enough to walk completely. */
function everyChoice(): Choice[] {
  const out: Choice[] = [];
  for (const effect of ["allow", "deny"] as Effect[])
    for (const scope of ["sandbox", "global"] as Scope[])
      for (const match of ["exact", "suffix"] as Match[])
        for (const d of DURATIONS)
          out.push({
            effect,
            scope,
            ruleSet: null,
            match,
            durationSecs: d.secs,
          });
  return out;
}

describe("narrowest", () => {
  it("is this workspace, the exact host, permanent (R-15), for either effect", () => {
    expect(narrowest("allow")).toEqual({
      effect: "allow",
      scope: "sandbox",
      ruleSet: null,
      match: "exact",
      durationSecs: null,
    });
    expect(narrowest("deny").effect).toBe("deny");
  });

  it("builds an API body that only names the scope", () => {
    expect(build(narrowest("allow"), target, false)).toEqual({
      ok: true,
      effect: "allow",
      body: { scope: "sandbox" },
    });
  });
});

describe("build: no path produces scope global without the confirm step", () => {
  it("refuses every global choice that is not confirmed, over the whole choice space", () => {
    const choices = everyChoice();
    expect(choices).toHaveLength(2 * 2 * 2 * 5);
    for (const choice of choices) {
      for (const t of [target, bare, ip]) {
        const result = build(choice, t, false);
        if (choice.scope === "global") {
          expect(result).toEqual({ ok: false, error: "confirmation_required" });
        } else if (result.ok) {
          expect(result.body.scope).toBe("sandbox");
        }
        const sure = build(choice, t, true);
        if (sure.ok) expect(sure.body.scope).toBe(choice.scope);
      }
    }
  });

  it("agrees with needsConfirm", () => {
    expect(needsConfirm({ scope: "global", ruleSet: null })).toBe(true);
    expect(needsConfirm({ scope: "sandbox", ruleSet: null })).toBe(false);
  });
});

describe("build: match and duration", () => {
  it("sends the suffix with a leading dot, and only for a host under the group's domain", () => {
    const choice: Choice = { ...narrowest("allow"), match: "suffix" };
    expect(build(choice, target, false)).toEqual({
      ok: true,
      effect: "allow",
      body: { scope: "sandbox", suffix: ".example.co.uk" },
    });
    expect(build(choice, bare, false)).toEqual({
      ok: false,
      error: "no_suffix",
    });
    expect(build(choice, ip, false)).toEqual({ ok: false, error: "no_suffix" });
  });

  it("sends every offered duration as seconds, and permanent as nothing", () => {
    const secs = DURATIONS.map((d) => d.secs);
    expect(secs).toEqual([null, 3600, 28_800, 86_400, 604_800]);
    for (const durationSecs of secs) {
      const result = build(
        { ...narrowest("deny"), durationSecs },
        target,
        false,
      );
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      if (durationSecs === null) {
        expect("expires_in_secs" in result.body).toBe(false);
      } else {
        expect(result.body.expires_in_secs).toBe(durationSecs);
      }
    }
  });
});

describe("suffixFor", () => {
  it("is null when the host is the domain, an IP literal, or not under the domain", () => {
    expect(suffixFor(bare)).toBeNull();
    expect(suffixFor(ip)).toBeNull();
    expect(suffixFor({ host: "[::1]", registrableDomain: "[::1]" })).toBeNull();
    expect(
      suffixFor({ host: "evil.test", registrableDomain: "example.com" }),
    ).toBeNull();
    expect(
      suffixFor({ host: "badexample.com", registrableDomain: "example.com" }),
    ).toBeNull();
  });

  it("ignores case", () => {
    expect(
      suffixFor({ host: "A.Example.COM", registrableDomain: "example.com" }),
    ).toBe(".example.com");
  });
});

describe("isIpLiteral", () => {
  it("knows IPv4 and IPv6 literals from names", () => {
    expect(isIpLiteral("10.0.0.1")).toBe(true);
    expect(isIpLiteral("fe80::1")).toBe(true);
    expect(isIpLiteral("10.0.0.1.example.com")).toBe(false);
    expect(isIpLiteral("example.com")).toBe(false);
  });
});

describe("wording", () => {
  it("describes a choice in one sentence naming the workspace, pattern and duration", () => {
    expect(describeChoice(narrowest("allow"), target, "demo")).toBe(
      "Allow api.registry.example.co.uk for workspace demo, permanently",
    );
    expect(
      describeChoice(
        {
          effect: "deny",
          scope: "global",
          ruleSet: null,
          match: "suffix",
          durationSecs: 28_800,
        },
        target,
        "demo",
      ),
    ).toBe("Deny *.example.co.uk for every workspace, for 8 hours");
  });

  it("falls back to the exact host when a suffix choice has no suffix", () => {
    expect(patternLabel({ ...narrowest("allow"), match: "suffix" }, bare)).toBe(
      "example.com",
    );
  });

  it("phrases an unlisted duration in seconds", () => {
    expect(durationPhrase(90)).toBe("for 90 s");
  });
});

describe("into a rule set (R-38)", () => {
  const into = (everywhere: boolean): Choice => ({
    ...narrowest("allow"),
    ruleSet: { id: 4, name: "Client X", everywhere },
  });

  it("sends the set instead of a scope", () => {
    const built = build(into(false), target, false);
    expect(built).toEqual({
      ok: true,
      effect: "allow",
      body: { scope: "sandbox", rule_set: 4 },
    });
  });

  it("asks first when the set is on for every workspace", () => {
    expect(needsConfirm(into(true))).toBe(true);
    expect(needsConfirm(into(false))).toBe(false);
    expect(build(into(true), target, false)).toEqual({
      ok: false,
      error: "confirmation_required",
    });
    expect(build(into(true), target, true).ok).toBe(true);
  });

  it("names the set and where it is on", () => {
    expect(describeChoice(into(true), target, "demo")).toBe(
      "Allow api.registry.example.co.uk in rule set Client X (which is on for every workspace), permanently",
    );
    expect(describeChoice(into(false), target, "demo")).toBe(
      "Allow api.registry.example.co.uk in rule set Client X (which is on for demo), permanently",
    );
  });
});
