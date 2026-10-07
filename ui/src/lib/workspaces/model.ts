// SPDX-License-Identifier: GPL-3.0-or-later
// What the workspace screens decide without the server: which buttons make sense for a state,
// the words for states and progress steps, and the checks a create form can make before it asks.
// Pure TypeScript, no DOM.
import type { components } from "#lib/api/schema.d.ts";

export type Workspace = components["schemas"]["Workspace"];
export type Status = components["schemas"]["SandboxStatus"];
export type Operation = components["schemas"]["WorkspaceOperation"];
export type Step = components["schemas"]["WorkspaceStep"];
export type DeleteCheck = components["schemas"]["DeleteCheck"];

/** States with no VM: the workspace can be started or deleted. */
export function isDown(status: Status): boolean {
  return status === "created" || status === "stopped" || status === "crashed";
}

/** Nothing is changing the workspace right now. */
export const isIdle = (w: Workspace): boolean => w.busy === null;

export const canStart = (w: Workspace): boolean =>
  isIdle(w) && isDown(w.status);
export const canStop = (w: Workspace): boolean =>
  isIdle(w) && w.status === "running";
export const canAttach = canStop;
export const canDelete = (w: Workspace): boolean =>
  isIdle(w) && isDown(w.status);
export const canReclaim = (w: Workspace): boolean =>
  isIdle(w) && (w.status === "running" || w.status === "stopped");

const STATUS_WORDS: Record<Status, string> = {
  created: "Not started",
  starting: "Starting",
  running: "Running",
  draining: "Stopping",
  paused: "Paused",
  stopped: "Stopped",
  crashed: "Crashed",
};

export const statusLabel = (status: Status): string => STATUS_WORDS[status];

/** The tone a status chip takes; never the only carrier of the meaning (the label says it too). */
export type Tone = "ok" | "busy" | "warn" | "bad" | "idle";

const STATUS_TONES: Record<Status, Tone> = {
  created: "idle",
  starting: "busy",
  running: "ok",
  draining: "busy",
  paused: "warn",
  stopped: "idle",
  crashed: "bad",
};

export const statusTone = (status: Status): Tone => STATUS_TONES[status];

const OPERATION_WORDS: Record<Operation, string> = {
  creating: "Creating",
  starting: "Starting",
  stopping: "Stopping",
  reclaiming: "Reclaiming space",
  deleting: "Deleting",
};

export const operationLabel = (op: Operation): string => OPERATION_WORDS[op];

const STEP_WORDS: Record<Step, string> = {
  preparing_volume: "Preparing the disk",
  pulling_image: "Downloading the image",
  cloning: "Cloning the repository",
  starting: "Starting the workspace",
  syncing: "Syncing your settings",
  checking: "Checking for unsaved work",
  reclaiming: "Reclaiming free space",
  stopping: "Stopping the workspace",
  removing: "Removing the workspace",
  done: "Done",
  failed: "Failed",
};

export const stepLabel = (step: Step): string => STEP_WORDS[step];

/** The ordered steps each operation goes through, to show "step 2 of 3". */
const SCRIPTS: Record<Operation, readonly Step[]> = {
  creating: ["preparing_volume", "pulling_image", "cloning"],
  starting: ["starting", "syncing"],
  stopping: ["stopping", "reclaiming"],
  reclaiming: ["reclaiming"],
  deleting: ["checking", "removing"],
};

/**
 * The operation a step belongs to, for when the page hears the step before it knows what the
 * workspace is doing (events can beat the answer to the request). `null` where the step says
 * nothing: `done`, `failed`.
 */
export function operationOfStep(step: Step): Operation | null {
  // `reclaiming` is also the last step of a stop; seen alone it is taken as a reclaim.
  const found = (
    Object.entries(SCRIPTS) as [Operation, readonly Step[]][]
  ).filter(([, steps]) => steps.includes(step));
  return (
    found.find(([op]) => op === "reclaiming")?.[0] ?? found[0]?.[0] ?? null
  );
}

/** Where a step sits in its operation: `{ index: 2, of: 3 }`, or `null` for a step not in it. */
export function stepPosition(
  op: Operation,
  step: Step,
): { index: number; of: number } | null {
  const steps = SCRIPTS[op];
  const at = steps.indexOf(step);
  return at < 0 ? null : { index: at + 1, of: steps.length };
}

/** Largest first name length: 63 for a DNS label, less the `ws-` volume prefix. */
export const MAX_NAME_LENGTH = 60;
const RESERVED_NAMES = new Set(["tauri", "ipc", "asset"]);

/** The reason a name can't be a workspace, or `null` when it can. */
export function nameProblem(name: string): string | null {
  if (name === "") return "Give the workspace a name.";
  if (name.length > MAX_NAME_LENGTH)
    return `Use at most ${MAX_NAME_LENGTH} characters.`;
  if (!/^[a-z0-9-]+$/.test(name))
    return "Use only lowercase letters, digits and hyphens.";
  if (name.startsWith("-") || name.endsWith("-"))
    return "Start and end with a letter or digit.";
  if (name.startsWith("m--"))
    return "Names starting with m-- are reserved for puddle's own use.";
  if (RESERVED_NAMES.has(name)) return `"${name}" is reserved; pick another.`;
  return null;
}

export const SSH_MESSAGE =
  "SSH remotes are not supported yet; use the repository's HTTPS URL instead.";

function looksLikeScp(url: string): boolean {
  if (url.includes("://") || /^http/i.test(url)) return false;
  const colon = url.indexOf(":");
  const slash = url.indexOf("/");
  if (colon <= 1) return false;
  return slash < 0 || colon < slash;
}

/** The reason a repository URL can't be cloned, or `null` when it can. */
export function repoUrlProblem(raw: string): string | null {
  const url = raw.trim();
  if (url === "") return "Enter the repository's HTTPS URL.";
  if (/^ssh:\/\//i.test(url) || looksLikeScp(url)) return SSH_MESSAGE;
  if (/\s/.test(url)) return "The URL must not contain spaces.";
  if (!/^https:\/\//i.test(url)) return "Use an https:// URL.";
  const authority = url.slice(8).split(/[/?#]/)[0] ?? "";
  if (authority.includes("@"))
    return "Remove the user name and password from the URL; puddle supplies credentials itself.";
  const host = authority.includes(":")
    ? authority.slice(0, authority.lastIndexOf(":"))
    : authority;
  if (host === "") return "The URL has no host.";
  return null;
}

/** A workspace name suggested by a repository URL: its last path segment, made a valid label. */
export function suggestName(repoUrl: string): string {
  const path = repoUrl.trim().split(/[?#]/)[0] ?? "";
  const last = path.split("/").filter(Boolean).pop() ?? "";
  const label = last
    .replace(/\.git$/i, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, MAX_NAME_LENGTH)
    .replace(/-+$/g, "");
  return RESERVED_NAMES.has(label) ? "" : label;
}

export const MIN_MEMORY_MIB = 256;
export const MAX_MEMORY_MIB = 1_048_576;

/** Reads a memory amount in GiB as typed; `null` means "use the default". */
export function parseMemoryGib(
  text: string,
): { ok: true; mib: number | null } | { ok: false; message: string } {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, mib: null };
  const gib = Number(trimmed);
  if (!Number.isFinite(gib))
    return { ok: false, message: "Enter a number of GiB." };
  const mib = Math.round(gib * 1024);
  if (mib < MIN_MEMORY_MIB || mib > MAX_MEMORY_MIB)
    return {
      ok: false,
      message: `Use between ${MIN_MEMORY_MIB / 1024} GiB and ${MAX_MEMORY_MIB / 1024} GiB.`,
    };
  return { ok: true, mib };
}

/** `8 GiB`, `512 MiB`, `1.5 GiB`. */
export function formatMib(mib: number): string {
  if (mib < 1024) return `${mib} MiB`;
  const gib = mib / 1024;
  return `${Number.isInteger(gib) ? gib : gib.toFixed(1)} GiB`;
}

/** `6 GiB of 32 GiB used`, or just the size when what is used isn't known. */
export function diskLabel(w: Workspace): string {
  return w.disk_used_mib === null
    ? `${formatMib(w.disk_size_mib)} disk`
    : `${formatMib(w.disk_used_mib)} of ${formatMib(w.disk_size_mib)} used`;
}

/** Names order the list; the API already sorts by id, the store sorts again after a change. */
export function sortWorkspaces(list: readonly Workspace[]): Workspace[] {
  return [...list].sort((a, b) => a.name.localeCompare(b.name));
}

/** What a delete would lose, as sentences for the confirm dialog. */
export interface LossLine {
  /** The checkout's directory; empty for what is outside any. */
  where: string;
  what: string;
  items: string[];
  more: number;
}

export function losses(check: DeleteCheck): LossLine[] {
  const lines: LossLine[] = [];
  for (const repo of check.repos) {
    const parts: [string, typeof repo.uncommitted][] = [
      ["Uncommitted changes", repo.uncommitted],
      ["Commits that are on no remote branch", repo.unpushed],
      ["Stashes", repo.stashes],
    ];
    for (const [what, list] of parts) {
      if (list.items.length > 0 || list.more > 0)
        lines.push({
          where: repo.dir,
          what,
          items: list.items,
          more: list.more,
        });
    }
  }
  if (check.other.items.length > 0 || check.other.more > 0)
    lines.push({
      where: "",
      what: "Files outside any repository",
      items: check.other.items,
      more: check.other.more,
    });
  return lines;
}
