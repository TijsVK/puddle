// SPDX-License-Identifier: GPL-3.0-or-later
// The network-health report in words: what puddle found, what each state means and what to do
// about it. Pure functions over the generated wire types. Every string that comes from outside
// (hosts, certificate subjects, proxy detail) is returned as data and only ever drawn as text.
import type { components } from "#lib/api/schema.d.ts";

type S = components["schemas"];
export type NetworkHealth = S["NetworkHealth"];
export type SignInAttempt = S["SignInAttempt"];
export type RouteDecision = S["RouteDecision"];

/** A problem needs action; a note is worth knowing and needs none. */
export type Level = "problem" | "note";

export interface Finding {
  /** Stable key, also the element id of the row on the page. */
  id: string;
  level: Level;
  /** What is wrong, in a sentence. */
  title: string;
  /** What to do about it; `null` when there is nothing the user can do. */
  fix: string | null;
}

export const DETECTED_LABEL: Record<S["ProxyDetected"], string> = {
  pac: "Automatic proxy script (PAC)",
  wpad: "Automatic detection (WPAD)",
  static: "A fixed proxy from the system settings",
  env: "Proxy environment variables",
  direct: "No proxy (direct connection)",
};

export const MODE_LABEL: Record<S["ProxyMode"], string> = {
  system: "Follow the system settings",
  manual: "Fixed in puddle's settings",
  direct: "Never use a proxy",
};

export const PAC_STATE_LABEL: Record<S["PacState"], string> = {
  not_used: "Not used",
  not_asked: "Not asked yet (no connection needed it)",
  answering: "Answering",
  unreachable: "Not answering",
};

export const SIGN_IN_LABEL: Record<S["SignInResult"], string> = {
  signed_in: "Signed in",
  not_required: "No sign-in needed",
  failed: "Failed",
  unsupported: "Not possible here",
};

export const ROUTE_SOURCE_LABEL: Record<S["RouteSource"], string> = {
  loopback: "Local address, never proxied",
  disabled: "Proxy use is off",
  manual: "Fixed in puddle's settings",
  pac: "Proxy script (PAC)",
  pac_unsupported: "Proxy script, a function puddle can't run",
  system: "System proxy settings",
  env: "Environment variables",
  bypass: "On the bypass list",
  no_proxy: "On the NO_PROXY list",
};

export const METHOD_LABEL: Record<string, string> = {
  negotiate: "Negotiate (Kerberos)",
  ntlm: "NTLM",
  basic: "Basic",
};

/** `hops` as one line: `proxy-a:8080, then direct`. */
export function hopsText(hops: readonly string[]): string {
  if (hops.length === 0) return "none";
  return hops
    .map((h) => (h === "DIRECT" ? "direct" : h.replace(/^PROXY /, "")))
    .join(", then ");
}

/** The wire name of an authentication method, as a person reads it. */
export function methodLabel(method: string): string {
  return METHOD_LABEL[method] ?? method;
}

/** Seconds as `3 min` / `45 s`. */
export function waitText(secs: number): string {
  if (secs < 60) return `${Math.max(0, Math.round(secs))} s`;
  const min = Math.round(secs / 60);
  return `${min} min`;
}

/** The fixed proxies of the report, `host:port` each, without repeats. */
export function fixedProxies(proxy: S["ProxyReport"]): string[] {
  return [
    ...new Set(
      [proxy.http_proxy, proxy.https_proxy].filter(
        (p): p is string => p !== null,
      ),
    ),
  ];
}

/** One entry of `proxy.problems` as a sentence and what to do about it. */
function problemWords(
  problem: S["ProxyProblem"],
): Pick<Finding, "title" | "fix"> {
  switch (problem.kind) {
    case "unusable_setting":
      return {
        title: `puddle can't use part of the proxy settings: ${problem.detail}.`,
        fix: "puddle sends traffic through plain HTTP proxies (host:port) only. What that setting was meant for is not sent through it: it goes straight out, or through the other settings that are fine. Change it to an HTTP proxy or remove it, then press Check again.",
      };
    case "changes_not_noticed":
      return {
        title: `puddle can't see changes to the proxy settings or the network: ${problem.detail}.`,
        fix: "puddle keeps the routes it has worked out until it is restarted. After you change the proxy settings or move to another network, quit puddle and start it again.",
      };
    default:
      return {
        title: `puddle found a problem with the proxy setup: ${problem.detail}.`,
        fix: null,
      };
  }
}

/** Everything in the report that is wrong or worth knowing, problems first. */
export function findings(report: NetworkHealth): Finding[] {
  const out: Finding[] = [];
  const { proxy, sign_in, roots, pull_proxy } = report;

  if (proxy.settings_error !== null) {
    out.push({
      id: "settings-error",
      level: "problem",
      title: `puddle couldn't read the system proxy settings: ${proxy.settings_error}`,
      fix: "Check the proxy page of the operating system's network settings, or set the proxy for puddle in its own settings. Then press Check again.",
    });
  }
  proxy.problems.forEach((problem, i) => {
    out.push({
      id: `proxy-problem-${i}`,
      level: "problem",
      ...problemWords(problem),
    });
  });
  if (proxy.pac_state === "unreachable") {
    const address = proxy.pac_url ?? "the proxy script";
    out.push({
      id: "pac-unreachable",
      level: "problem",
      title: `The proxy script at ${address} isn't answering.`,
      fix: "Open that address in a browser on this computer. If it fails there too you are probably off the company network or the VPN is down. puddle looks again by itself when the network changes.",
    });
  }
  for (const attempt of sign_in.attempts) {
    if (attempt.result === "failed") {
      out.push({
        id: `sign-in-${attempt.proxy}`,
        level: "problem",
        title: `Signing in to ${attempt.proxy} failed${attempt.scheme ? ` (${attempt.scheme})` : ""}${attempt.detail ? `: ${attempt.detail}` : "."}`,
        fix: "puddle signs in as the person who is logged in to this computer. Check you are signed in to the company account (lock and unlock the computer, or sign in again) and on the company network. puddle tries again at the next connection.",
      });
    } else if (attempt.result === "unsupported") {
      out.push({
        id: `sign-in-${attempt.proxy}`,
        level: "problem",
        title: `${attempt.proxy} asks for a sign-in puddle can't give${attempt.detail ? `: ${attempt.detail}` : "."}`,
        fix:
          sign_in.methods.length === 0
            ? "puddle has no way to sign in to a proxy on this system yet. Ask for this destination to be let through without sign-in, or use a proxy that doesn't ask."
            : `puddle can answer ${sign_in.methods.map(methodLabel).join(", ")}. Ask IT whether the proxy can accept one of these.`,
      });
    }
  }
  if (roots.unreadable_stores.length > 0) {
    out.push({
      id: "unreadable-stores",
      level: "problem",
      title: `puddle couldn't read ${roots.unreadable_stores.length === 1 ? "a certificate store" : `${roots.unreadable_stores.length} certificate stores`}.`,
      fix: "Tools inside workspaces may then fail with certificate errors on sites the company proxy inspects. Make sure puddle runs as a user who may read the computer's certificate stores, or ask IT. Then press Check again.",
    });
  }

  for (const dead of proxy.dead_proxies) {
    out.push({
      id: `dead-${dead.proxy}`,
      level: "note",
      title: `${dead.proxy} is marked as not answering. puddle tries it again in ${waitText(dead.retry_in_secs)}.`,
      fix: "Nothing to do unless it stays that way: puddle uses the next proxy in the list meanwhile, and starts over when the network changes.",
    });
  }
  if (!roots.synced && roots.unreadable_stores.length === 0) {
    out.push({
      id: "roots-not-read",
      level: "note",
      title: "The company certificates haven't been read yet.",
      fix: null,
    });
  }
  if (roots.skipped.length > 0) {
    out.push({
      id: "roots-skipped",
      level: "note",
      title: `${roots.skipped.length} ${roots.skipped.length === 1 ? "certificate was" : "certificates were"} left out of what workspaces get (see the list below for each reason).`,
      fix: "Expired certificates are left out on purpose. If one you rely on is listed, ask IT for a renewed one.",
    });
  }
  const leftOut = roots.left_out_of_tls;
  if (leftOut.length > 0) {
    out.push({
      id: "roots-left-out-of-tls",
      level: "problem",
      title: `puddle can't use ${leftOut.length === 1 ? "a company certificate" : `${leftOut.length} company certificates`} when it checks the servers it adds your credentials for.`,
      fix: "A Git host reached through a company proxy that inspects traffic may then fail with an unknown-issuer error. The list below says which certificate and why. Ask IT for it again as a standard CA certificate, then restart puddle.",
    });
  }
  if (!pull_proxy.active) {
    out.push({
      id: "pull-off",
      level: "note",
      title:
        "Image downloads don't go through puddle's pull proxy, so puddle's rules and address guard don't apply to them.",
      fix: null,
    });
  } else if (!pull_proxy.via_upstream && proxy.detected !== "direct") {
    out.push({
      id: "pull-direct",
      level: "note",
      title:
        "Image downloads go straight out, not through the company proxy found above.",
      fix: null,
    });
  }
  return out.sort(
    (a, b) => Number(b.level === "problem") - Number(a.level === "problem"),
  );
}

/** The problems only: what a notice mentions. */
export function problems(report: NetworkHealth): Finding[] {
  return findings(report).filter((f) => f.level === "problem");
}

/** One line for a notice: the first problem, and how many more there are. */
export function problemSummary(list: readonly Finding[]): string {
  const [first, ...rest] = list;
  if (!first) return "";
  return rest.length === 0
    ? first.title
    : `${first.title} (and ${rest.length} more)`;
}

/** Newest first, as the API sends them; a proxy's row id for lists. */
export function attemptKey(a: SignInAttempt): string {
  return `${a.proxy}|${a.at}`;
}

/** The certificate expiry as a date (`2100-01-01`), or `expired` when it is behind `now`. */
export function expiryText(notAfter: number, now: number): string {
  if (notAfter < now) return "expired";
  return new Date(notAfter).toISOString().slice(0, 10);
}
