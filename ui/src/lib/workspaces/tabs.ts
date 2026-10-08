// SPDX-License-Identifier: GPL-3.0-or-later
// The tabs of a workspace's page, in order. A tab is a folder under `routes/workspaces/[id]/`
// (the overview is the folder itself); a later tab is added here and as a folder.
export interface Tab {
  /** The path segment after the workspace's, empty for the overview. */
  slug: string;
  label: string;
}

export const TABS: readonly Tab[] = [
  { slug: "", label: "Overview" },
  { slug: "network", label: "Network" },
  { slug: "git", label: "Git" },
  { slug: "environment", label: "Environment" },
  { slug: "shell-init", label: "Shell init" },
  { slug: "ports", label: "Ports" },
  { slug: "settings", label: "Settings" },
];

/** The tab a path is on: `/workspaces/demo/network` is `network`; unknown is the overview. */
export function activeTab(pathname: string, id: string): string {
  const prefix = `/workspaces/${encodeURIComponent(id)}`;
  const rest = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : "";
  const slug = rest.split("/").filter(Boolean)[0] ?? "";
  return TABS.some((t) => t.slug === slug) ? slug : "";
}

export function tabHref(id: string, slug: string): string {
  const base = `/workspaces/${encodeURIComponent(id)}`;
  return slug === "" ? base : `${base}/${slug}`;
}
