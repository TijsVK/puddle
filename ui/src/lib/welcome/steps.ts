// SPDX-License-Identifier: GPL-3.0-or-later
// The steps of the first-run flow, in order. One list, so the step bar, the page titles and the
// Back and Continue links agree.

export type StepId =
  "welcome" | "check" | "certificates" | "connect" | "look" | "workspace";

export interface Step {
  id: StepId;
  href: string;
  /** In the step bar and the page title. */
  label: string;
}

export const WELCOME_ROOT = "/welcome";

export const STEPS: readonly Step[] = [
  { id: "welcome", href: WELCOME_ROOT, label: "Welcome" },
  { id: "check", href: `${WELCOME_ROOT}/check`, label: "System check" },
  {
    id: "certificates",
    href: `${WELCOME_ROOT}/certificates`,
    label: "Certificates",
  },
  { id: "connect", href: `${WELCOME_ROOT}/connect`, label: "Connect" },
  { id: "look", href: `${WELCOME_ROOT}/look`, label: "Look" },
  {
    id: "workspace",
    href: `${WELCOME_ROOT}/workspace`,
    label: "First workspace",
  },
];

/** Whether a path belongs to the flow (the app's sidebar is left out there). */
export const isWelcome = (pathname: string): boolean =>
  pathname === WELCOME_ROOT || pathname.startsWith(`${WELCOME_ROOT}/`);

/** The step a path shows, if it is one. */
export function stepFor(pathname: string): Step | undefined {
  const path = pathname.length > 1 ? pathname.replace(/\/$/, "") : pathname;
  return STEPS.find((step) => step.href === path);
}

/** Where Back and Continue go from a step; `undefined` at the ends. */
export function around(id: StepId): {
  back: string | undefined;
  next: string | undefined;
} {
  const at = STEPS.findIndex((step) => step.id === id);
  return { back: STEPS[at - 1]?.href, next: STEPS[at + 1]?.href };
}
