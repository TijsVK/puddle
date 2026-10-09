// SPDX-License-Identifier: GPL-3.0-or-later
// The notice for a login made inside a workspace that puddle could not capture, or could not
// use after a restart. Capture is on by default and is meant to be invisible, so every case where
// it does not work says so: the first four leave the real token in the workspace (the login still
// works, it is just not protected), the last means the tool will ask for a new sign-in.
import type { components } from "#lib/api/schema.d.ts";
import type { Notifier } from "./notifier.ts";

type Event = components["schemas"]["Event"];
export type LoginProblem = Extract<Event, { type: "login_problem" }>;
type Kind = components["schemas"]["LoginProblemKind"];

const KINDS: readonly Kind[] = [
  "store_unavailable",
  "unexpected_answer",
  "unusable_token",
  "bound_token",
  "unreadable",
];

const WHY: Record<Kind, string> = {
  store_unavailable:
    "puddle can't keep tokens in this computer's credential store, so a login made in this workspace stays in it as the real token. The login works, but an agent in the workspace could copy it. Make the credential store available and sign in again to protect it.",
  unexpected_answer:
    "puddle could not read the service's answer, so the workspace received the real token. The login works, but an agent in the workspace could copy it.",
  unusable_token:
    "the token has a form puddle cannot imitate, so the workspace received the real token. The login works, but an agent in the workspace could copy it.",
  bound_token:
    "the service ties its token to a key of the tool's own, which puddle cannot stand in for, so the workspace received the real token. The login works, but an agent in the workspace could copy it.",
  unreadable:
    "puddle could not read the login it kept for this workspace from the credential store, so the tool will ask you to sign in again. Sign in inside the workspace to keep a new login.",
};

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null;

/** The event when it is a login problem with the right field types; anything else is ignored. */
export function asLoginProblem(raw: unknown): LoginProblem | null {
  if (!isObject(raw) || raw["type"] !== "login_problem") return null;
  const kind = raw["kind"];
  return typeof raw["workspace"] === "string" &&
    typeof raw["service"] === "string" &&
    typeof kind === "string" &&
    KINDS.includes(kind as Kind)
    ? (raw as LoginProblem)
    : null;
}

export const loginKey = (e: LoginProblem) =>
  `login:${e.workspace}:${e.service}:${e.kind}`;

const keptLogin = (kind: Kind) => kind === "unreadable";

export class LoginNotices {
  readonly #notifier: Notifier;

  constructor(notifier: Notifier) {
    this.#notifier = notifier;
  }

  /** Raises the notice a login problem calls for; false when the event is not one. */
  handle(raw: unknown): boolean {
    const event = asLoginProblem(raw);
    if (!event) return false;
    this.#notifier.notify({
      key: loginKey(event),
      tone: "warning",
      title: keptLogin(event.kind)
        ? `${event.service} login in ${event.workspace} can't be used.`
        : `${event.service} login in ${event.workspace} is not protected.`,
      detail: WHY[event.kind][0]!.toUpperCase() + WHY[event.kind].slice(1),
      link: {
        href: `/workspaces/${encodeURIComponent(event.workspace)}/settings`,
        label: "Workspace settings",
      },
    });
    return true;
  }
}
