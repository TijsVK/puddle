// SPDX-License-Identifier: GPL-3.0-or-later
// The one list of top-level sections. Later rows add a screen by adding an entry here (and a
// folder under src/routes), never by editing the layout.
import Inbox from "@lucide/svelte/icons/inbox";
import Boxes from "@lucide/svelte/icons/boxes";
import ShieldCheck from "@lucide/svelte/icons/shield-check";
import ScrollText from "@lucide/svelte/icons/scroll-text";
import Settings from "@lucide/svelte/icons/settings";
import type { Component } from "svelte";

export interface NavItem {
  /** Route path, also the key. */
  href: string;
  /** Sidebar label and page title. */
  label: string;
  icon: Component;
  /** Show the pending-requests badge. */
  badge?: "pending";
}

export const NAV: readonly NavItem[] = [
  {
    href: "/inbox",
    label: "Inbox",
    icon: Inbox as Component,
    badge: "pending",
  },
  { href: "/workspaces", label: "Workspaces", icon: Boxes as Component },
  { href: "/rules", label: "Rules", icon: ShieldCheck as Component },
  { href: "/activity", label: "Activity", icon: ScrollText as Component },
  { href: "/settings", label: "Settings", icon: Settings as Component },
];

export const APP_NAME = "puddle";

/** The section a path belongs to (`/rules/123` belongs to `/rules`). */
export function sectionFor(pathname: string): NavItem | undefined {
  return NAV.find(
    (item) => pathname === item.href || pathname.startsWith(`${item.href}/`),
  );
}

/** `Inbox (3) - puddle`: the document title, with the pending count when there is one. */
export function documentTitle(pathname: string, pending: number): string {
  const section = sectionFor(pathname);
  const label = section?.label ?? "Not found";
  const count =
    section?.badge === "pending" && pending > 0 ? ` (${pending})` : "";
  return `${label}${count} - ${APP_NAME}`;
}
