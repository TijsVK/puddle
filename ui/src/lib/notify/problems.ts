// SPDX-License-Identifier: GPL-3.0-or-later
// Background problems: something puddle did on its own failed (a sweep, a clean-up, a start-up
// step), so no request carried the error. The host lists them (`GET /api/problems`) and says when
// the list changed (`problems_changed`); each becomes one notice that goes away with its cause.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import type { Notifier } from "./notifier.ts";

type Problem = components["schemas"]["Problem"];

const noticeKey = (key: string) => `problem:${key}`;

export class ProblemNotices {
  readonly #notifier: Notifier;
  readonly #api: Pick<ApiClient, "GET">;
  /** The keys whose notices stand, so one that left the list can be withdrawn. */
  #raised = new Set<string>();

  constructor(notifier: Notifier, api: Pick<ApiClient, "GET"> = defaultApi) {
    this.#notifier = notifier;
    this.#api = api;
  }

  /** Rereads the list on the event that says it changed; false for any other event. */
  handle(raw: unknown): boolean {
    if (
      typeof raw !== "object" ||
      raw === null ||
      (raw as { type?: unknown }).type !== "problems_changed"
    ) {
      return false;
    }
    void this.refresh();
    return true;
  }

  /** Makes the notices match the host's list; never throws. A failed read leaves them as they are. */
  async refresh(): Promise<void> {
    let problems: Problem[];
    try {
      const { data } = await this.#api.GET("/api/problems");
      if (!data || !Array.isArray(data.problems)) return;
      problems = data.problems;
    } catch {
      return;
    }
    const now = new Set<string>();
    for (const problem of problems) {
      now.add(problem.key);
      this.#notifier.notify({
        key: noticeKey(problem.key),
        tone: "warning",
        title: problem.title,
        detail: problem.detail,
        ...(problem.workspace
          ? {
              link: {
                href: `/workspaces/${encodeURIComponent(problem.workspace)}`,
                label: "Open workspace",
              },
            }
          : {}),
      });
    }
    for (const key of this.#raised) {
      if (!now.has(key)) this.#notifier.resolve(noticeKey(key));
    }
    this.#raised = now;
  }
}
