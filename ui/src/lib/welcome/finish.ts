// SPDX-License-Identifier: GPL-3.0-or-later
// Ends the first-run flow: records that it is done and opens the workspace list. The list opens
// even when puddle could not keep that, so a failing service never traps the user in the flow;
// the toast says why, and that the flow may come back.
import { goto } from "$app/navigation";
import { firstRun } from "#lib/stores/first-run.svelte.ts";
import { toasts } from "#lib/stores/toasts.svelte.ts";

export async function finishFlow(): Promise<void> {
  const result = await firstRun.complete();
  if (!result.ok) {
    toasts.push(
      `puddle couldn't record that setup is done: ${result.message} It may show again next time.`,
      { tone: "error" },
    );
  }
  await goto("/workspaces");
}
