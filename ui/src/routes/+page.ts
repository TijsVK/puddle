// SPDX-License-Identifier: GPL-3.0-or-later
import { redirect } from "@sveltejs/kit";

// The start screen: the approval inbox.
export function load(): never {
  redirect(307, "/inbox");
}
