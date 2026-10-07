// SPDX-License-Identifier: GPL-3.0-or-later
import { redirect } from "@sveltejs/kit";

// The start screen (D-80's default): the approval inbox.
export function load(): never {
  redirect(307, "/inbox");
}
