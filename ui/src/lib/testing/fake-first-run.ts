// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for the API's system-check and first-run endpoints, in the shape openapi-fetch returns
// them. Not shipped (tests import it).
import type { FirstRun } from "#lib/stores/first-run.svelte.ts";
import type { DoctorCheck, DoctorReport } from "#lib/welcome/doctor.ts";

export function check(
  id: string,
  title: string,
  over: Partial<DoctorCheck> = {},
): DoctorCheck {
  return {
    id,
    title,
    status: "ok",
    summary: `${title} is fine.`,
    finding: null,
    fix: null,
    detail: null,
    ...over,
  };
}

export function healthyReport(over: Partial<DoctorReport> = {}): DoctorReport {
  return {
    schema_version: 1,
    puddle_version: "0.1.0",
    os: "linux",
    arch: "x86_64",
    ok: true,
    checks: [
      check("virtualization", "CPU virtualization"),
      check("hypervisor", "Hypervisor"),
      check("test_boot", "Test boot", { summary: "booted in 1.4 s" }),
    ],
    elapsed_ms: 1800,
    ...over,
  };
}

export function brokenReport(): DoctorReport {
  const report = healthyReport({ ok: false });
  report.checks[1] = check("hypervisor", "Hypervisor", {
    status: "fail",
    summary: "/dev/kvm doesn't exist",
    finding: "kvm_missing",
    fix: "Turn on virtualization in your UEFI setup.",
    detail: "No such file or directory (os error 2)",
  });
  report.checks[2] = check("test_boot", "Test boot", {
    status: "skipped",
    summary: "not checked: no usable hypervisor",
  });
  return report;
}

export class FakeFirstRun {
  state: FirstRun = {
    completed: false,
    completed_at: null,
    dev_certificate: "not_checked",
  };
  report: DoctorReport = healthyReport();
  /** The status the system check answers with; 503 means this build has none. */
  doctorStatus = 200;
  calls: string[] = [];
  bodies: unknown[] = [];
  down = false;
  /** Holds the next system check until released. */
  hold: Promise<void> | null = null;
  /** Answers `PUT /api/first-run` with a failure. */
  refusePut = false;

  GET = async (path: string) => {
    this.calls.push(`GET ${path}`);
    if (this.down) throw new TypeError("down");
    const response = (status: number) =>
      ({ status, ok: status < 400 }) as Response;
    if (path === "/api/doctor") {
      if (this.hold) await this.hold;
      return this.doctorStatus === 200
        ? { data: this.report, response: response(200) }
        : {
            error: { error: "unavailable", message: "not here" },
            response: response(this.doctorStatus),
          };
    }
    if (path === "/api/first-run") {
      return { data: this.state, response: response(200) };
    }
    throw new Error(`unexpected GET ${path}`);
  };

  PUT = async (path: string, init: { body: unknown }) => {
    this.calls.push(`PUT ${path}`);
    this.bodies.push(init.body);
    if (this.down) throw new TypeError("down");
    const response = (status: number) =>
      ({ status, ok: status < 400 }) as Response;
    if (path !== "/api/first-run") throw new Error(`unexpected PUT ${path}`);
    if (this.refusePut) {
      return {
        error: { error: "newer_settings", message: "newer" },
        response: response(409),
      };
    }
    const completed = (init.body as { completed: boolean }).completed;
    this.state = {
      ...this.state,
      completed,
      completed_at: completed ? 1_700_000_000_000 : null,
    };
    return { data: this.state, response: response(200) };
  };
}
