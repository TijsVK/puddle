// SPDX-License-Identifier: GPL-3.0-or-later
// Which local-destination toggle (R-14) an IP literal falls under, so a request that needs a
// switched-off toggle can say so. The proxy is the authority; this only names the toggle in
// the UI. Hosts that are names return `null`: they are checked after resolving, in the proxy.

export type LocalCategory =
  "loopback" | "private" | "link_local" | "metadata" | "special";

export const LOCAL_LABELS: Record<LocalCategory, string> = {
  loopback: "This computer (loopback)",
  private: "Private networks",
  link_local: "Link-local",
  metadata: "Cloud metadata",
  special: "Other special ranges",
};

function ipv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return parts as [number, number, number, number];
}

function ipv4Category(a: number, b: number, c: number): LocalCategory | null {
  if (a === 127) return "loopback";
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 0) return "special";
  if (a === 100 && b >= 64 && b <= 127) return "special";
  if (a === 198 && (b === 18 || b === 19)) return "special";
  if (a === 192 && b === 0 && c === 0) return "special";
  if (a >= 240) return "special";
  return null;
}

export function localCategory(rawHost: string): LocalCategory | null {
  const host = rawHost.replace(/^\[|\]$/g, "").toLowerCase();
  const v4 = ipv4(host);
  if (v4) {
    // 169.254.169.254 is the metadata address; the rest of 169.254/16 is link-local.
    if (v4[0] === 169 && v4[1] === 254) {
      return v4[2] === 169 && v4[3] === 254 ? "metadata" : "link_local";
    }
    return ipv4Category(v4[0], v4[1], v4[2]);
  }
  if (!host.includes(":")) return null;
  if (host === "::1") return "loopback";
  if (host === "fd00:ec2::254") return "metadata";
  if (/^fe[89ab]/.test(host)) return "link_local";
  if (/^f[cd]/.test(host)) return "private";
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
  if (mapped?.[1]) return localCategory(mapped[1]);
  return null;
}
