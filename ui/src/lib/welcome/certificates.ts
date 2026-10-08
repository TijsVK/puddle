// SPDX-License-Identifier: GPL-3.0-or-later
// What the certificates step says: the development certificate (what puddle knows about it) and
// the company roots workspaces get. Words only; the page decides the layout.
import type { components } from "#lib/api/schema.d.ts";
import type { NetworkHealth } from "#lib/network/model.ts";
import type { DoctorStatus } from "./doctor.ts";

export type DevCertificate = components["schemas"]["DevCertificate"];

export interface Line {
  /** Drawn like a check of the system check: `ok`, `info`, `warn`, or `skipped` for "not looked at". */
  tone: Extract<DoctorStatus, "ok" | "info" | "warn" | "skipped">;
  title: string;
  text: string;
}

/** The line about an ASP.NET development certificate. */
export function devCertificateLine(status: DevCertificate | undefined): Line {
  if (status === "reusing_existing") {
    return {
      tone: "ok",
      title: "Using your existing .NET development certificate",
      text: "Windows already trusts it, so HTTPS on localhost works in your browser for apps in every workspace. No trust dialog needed.",
    };
  }
  return {
    tone: "skipped",
    title: "Development certificate: not checked yet",
    text: "An HTTPS development server in a workspace shows a browser warning until puddle can trust a certificate for it.",
  };
}

const plural = (n: number, one: string, many: string): string =>
  n === 1 ? one : many;

/** The line about the company roots, from the network-health report; `null` while it is unread. */
export function rootsLine(
  report: Pick<NetworkHealth, "roots"> | null,
  failed: boolean,
): Line {
  if (report === null) {
    return failed
      ? {
          tone: "skipped",
          title: "Company certificates: not read",
          text: "puddle couldn't read its certificate report. Workspaces still get the standard certificates.",
        }
      : {
          tone: "skipped",
          title: "Company certificates",
          text: "puddle is reading this computer's certificate stores…",
        };
  }
  const { roots } = report;
  if (!roots.synced) {
    return {
      tone: "skipped",
      title: "Company certificates: not read yet",
      text: "puddle has not read this computer's certificate stores yet.",
    };
  }
  if (roots.unreadable_stores.length > 0) {
    const n = roots.unreadable_stores.length;
    return {
      tone: "warn",
      title: `${n} certificate ${plural(n, "store", "stores")} couldn't be read`,
      text: "Tools in a workspace may fail on sites your company network inspects. The details are in Network health.",
    };
  }
  if (roots.roots === 0) {
    return {
      tone: "info",
      title: "No company root certificates found",
      text: "Workspaces use the standard set of certificates.",
    };
  }
  return {
    tone: "ok",
    title: `${roots.roots} company root ${plural(roots.roots, "certificate", "certificates")} found`,
    text: "Added to every workspace, so tools trust your network's TLS inspection.",
  };
}
