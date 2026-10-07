// SPDX-License-Identifier: GPL-3.0-or-later
// The words about direct SSH, in one place: the trust text shown once when it is turned on, and
// the labels the connect step, the workspace settings and the global settings share.

/** What the switch is called wherever it appears. */
export const DIRECT_SSH_LABEL = "Allow direct SSH";

/** What the switch opens up, in the words of someone who has not met SSH. */
export const DIRECT_SSH_HINT =
  "Lets desktop VS Code and other SSH tools on this computer connect to the workspace.";

/** The trust text: said once, when the switch is turned on. */
export const TRUST_DETAIL =
  "Anything that already runs in the workspace, including code in its repository, runs with your rights on this computer when you connect with desktop VS Code: it can read your VS Code secrets, including a signed-in GitHub token, and run commands here through a local terminal. Turning the switch off later closes the way in but does not undo what already ran. Only allow it for code you trust. The browser editor keeps the workspace isolated.";

export interface TrustWords {
  title: string;
  summary: string;
  detail: string;
  confirmLabel: string;
}

/** The confirmation for one workspace. */
export const trustWordsFor = (name: string): TrustWords => ({
  title: `Allow direct SSH to ${name}?`,
  summary: `Allowing direct SSH makes ${name} a trusted workspace: desktop VS Code and other SSH tools can connect to it.`,
  detail: TRUST_DETAIL,
  confirmLabel: DIRECT_SSH_LABEL,
});

/** The confirmation for the global default: it reaches every workspace that sets no switch of its own. */
export const TRUST_WORDS_GLOBAL: TrustWords = {
  title: "Allow direct SSH for new workspaces?",
  summary:
    "Every workspace that does not set its own switch becomes trusted, including the ones you already have.",
  detail: TRUST_DETAIL,
  confirmLabel: "Allow for new workspaces",
};

/** The badge text on a workspace that has direct SSH on. */
export const TRUSTED_LABEL = "Trusted";
export const TRUSTED_TITLE =
  "Direct SSH is on: desktop VS Code and other SSH tools can connect, and code in this workspace can reach this computer through them.";
