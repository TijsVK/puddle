// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it } from "vitest";
import { FirstRunStore, type FirstRun } from "./first-run.svelte.ts";

const open: FirstRun = {
  completed: false,
  completed_at: null,
  dev_certificate: "not_checked",
};
const done: FirstRun = { ...open, completed: true, completed_at: 5 };

type Answer =
  { data?: unknown; error?: unknown; response: { status: number } } | "throw";
let answers: Answer[];
let bodies: unknown[];

const api = {
  GET: async () => {
    const answer = answers.shift() ?? { data: open, response: { status: 200 } };
    if (answer === "throw") throw new Error("down");
    return answer;
  },
  PUT: async (_path: string, init: { body: unknown }) => {
    bodies.push(init.body);
    const answer = answers.shift() ?? { data: done, response: { status: 200 } };
    if (answer === "throw") throw new Error("down");
    return answer;
  },
};
const make = () => new FirstRunStore(api as never);

beforeEach(() => {
  answers = [];
  bodies = [];
});

describe("FirstRunStore", () => {
  it("reads the state", async () => {
    const store = make();
    expect(store.status).toBe("loading");
    await store.load();
    expect(store.status).toBe("ready");
    expect(store.state).toEqual(open);
  });

  it("fails when nothing was ever read, and keeps what it had otherwise", async () => {
    answers.push({ response: { status: 500 } });
    const a = make();
    await a.load();
    expect(a.status).toBe("failed");
    answers.push("throw");
    const b = make();
    await b.load();
    expect(b.status).toBe("failed");

    const c = make();
    await c.load();
    answers.push({ response: { status: 500 } }, "throw");
    await c.load();
    await c.load();
    expect(c.status).toBe("ready");
    expect(c.state).toEqual(open);
  });

  it("records that the flow is done", async () => {
    const store = make();
    expect(await store.complete()).toEqual({ ok: true });
    expect(bodies).toEqual([{ completed: true }]);
    expect(store.state).toEqual(done);
    expect(store.status).toBe("ready");
  });

  it("says why it could not record that", async () => {
    answers.push(
      {
        error: { error: "newer_settings", message: "newer" },
        response: { status: 409 },
      },
      {
        error: { error: "internal", message: "disk full" },
        response: { status: 500 },
      },
      { response: { status: 500 } },
      "throw",
    );
    const store = make();
    expect(await store.complete()).toEqual({
      ok: false,
      message:
        "These settings were saved by a newer puddle. Update puddle to change them.",
    });
    expect(await store.complete()).toEqual({ ok: false, message: "disk full" });
    expect(await store.complete()).toEqual({
      ok: false,
      message: "puddle refused that.",
    });
    expect(await store.complete()).toEqual({
      ok: false,
      message: "puddle's service isn't answering.",
    });
    expect(store.state).toBeNull();
  });
});
