// SPDX-License-Identifier: GPL-3.0-or-later
// The system check, run on request. A run takes a few seconds (it boots a tiny test machine), so
// the screens show `running` and keep the buttons off meanwhile.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { DoctorReport } from "#lib/welcome/doctor.ts";

/**
 * `unavailable`: this puddle can't run the check (the API answers 503). `failed`: the answer
 * didn't come, or wasn't a report.
 */
export type Status = "idle" | "running" | "ready" | "unavailable" | "failed";

type StoreApi = Pick<ApiClient, "GET">;

export class DoctorStore {
  report = $state.raw<DoctorReport | null>(null);
  status = $state<Status>("idle");
  /** Why a run failed, in words: puddle's own reason, or that nothing answered. */
  problem = $state<string | null>(null);

  readonly #api: StoreApi;

  constructor(api: StoreApi = defaultApi) {
    this.#api = api;
  }

  /** Runs the checks; never throws. A run that is already going is not started twice. */
  async run(): Promise<void> {
    if (this.status === "running") return;
    this.status = "running";
    // The last result is not shown beside a new run: it may be what the user just fixed.
    this.report = null;
    this.problem = null;
    try {
      const { data, error, response } = await this.#api.GET("/api/doctor");
      if (data) {
        this.report = data;
        this.status = "ready";
      } else if (response.status === 503) {
        this.status = "unavailable";
      } else {
        this.status = "failed";
        this.problem =
          response.status === 408
            ? "the check took longer than puddle allows."
            : (error?.message ?? `puddle answered ${response.status}.`);
      }
    } catch {
      this.status = "failed";
      this.problem = "puddle's service isn't answering.";
    }
  }
}

export const doctor = new DoctorStore();
