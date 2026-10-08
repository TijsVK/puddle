// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import type { DoctorReport } from "#lib/welcome/doctor.ts";
import { DoctorStore } from "./doctor.svelte.ts";

const report: DoctorReport = {
  schema_version: 1,
  puddle_version: "1.0.0",
  os: "linux",
  arch: "x86_64",
  ok: true,
  checks: [],
  elapsed_ms: 10,
};

type Answer =
  { data?: unknown; error?: unknown; response: { status: number } } | "throw";
let answers: Answer[];
let calls: number;
let hold: Promise<void> | null;

const api = {
  GET: async () => {
    calls += 1;
    if (hold) await hold;
    const answer = answers.shift() ?? {
      data: report,
      response: { status: 200 },
    };
    if (answer === "throw") throw new Error("down");
    return answer;
  },
};
const make = () => new DoctorStore(api as never);

beforeEach(() => {
  answers = [];
  calls = 0;
  hold = null;
});

describe("DoctorStore", () => {
  it("starts idle with no report", () => {
    const store = make();
    expect(store.status).toBe("idle");
    expect(store.report).toBeNull();
  });

  it("runs the checks and keeps the report", async () => {
    const store = make();
    await store.run();
    expect(store.status).toBe("ready");
    expect(store.report).toEqual(report);
  });

  it("says unavailable on 503", async () => {
    answers.push({ response: { status: 503 } });
    const store = make();
    await store.run();
    expect(store.status).toBe("unavailable");
    expect(store.problem).toBeNull();
  });

  it("fails with puddle's own reason, or says what is known", async () => {
    answers.push({
      error: { error: "internal", message: "internal error; see puddle's log" },
      response: { status: 500 },
    });
    const a = make();
    await a.run();
    expect(a.status).toBe("failed");
    expect(a.problem).toBe("internal error; see puddle's log");

    answers.push({ response: { status: 408 } });
    const b = make();
    await b.run();
    expect(b.problem).toBe("the check took longer than puddle allows.");

    answers.push({ response: { status: 502 } });
    const c = make();
    await c.run();
    expect(c.problem).toBe("puddle answered 502.");

    answers.push("throw");
    const d = make();
    await d.run();
    expect(d.status).toBe("failed");
    expect(d.problem).toBe("puddle's service isn't answering.");
    expect(d.report).toBeNull();
  });

  it("drops the old report while a new run is going, and keeps none if it fails", async () => {
    const store = make();
    await store.run();
    expect(store.report).not.toBeNull();
    let release = () => {};
    hold = new Promise<void>((resolve) => (release = resolve));
    answers.push("throw");
    const second = store.run();
    expect(store.status).toBe("running");
    expect(store.report).toBeNull();
    release();
    await second;
    expect(store.status).toBe("failed");
    expect(store.report).toBeNull();
  });

  it("does not start a second run while one is going", async () => {
    const store = make();
    let release = () => {};
    hold = new Promise<void>((resolve) => (release = resolve));
    const first = store.run();
    await store.run();
    expect(calls).toBe(1);
    release();
    await first;
    expect(store.status).toBe("ready");
  });
});
