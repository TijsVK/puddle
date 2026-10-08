// SPDX-License-Identifier: GPL-3.0-or-later
import { redirect } from "@sveltejs/kit";
import { api } from "#lib/api/client.ts";

// The start screen: the first-run flow until it has been through, then the workspace list with
// a strip that links to the inbox when requests wait. When puddle can't say whether the flow
// ran, the list is the safer start: it shows what is wrong with the service.
export async function load(): Promise<never> {
  const completed = await api.GET("/api/first-run").then(
    ({ data }) => data?.completed ?? true,
    () => true,
  );
  redirect(307, completed ? "/workspaces" : "/welcome");
}
