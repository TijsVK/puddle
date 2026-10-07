// SPDX-License-Identifier: GPL-3.0-or-later
import { redirect } from "@sveltejs/kit";

// The start screen: the workspace list, with a strip that links to the inbox when requests wait.
export function load(): never {
  redirect(307, "/workspaces");
}
