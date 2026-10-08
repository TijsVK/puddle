// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from "vitest";

type Answer = { data?: unknown; error?: unknown } | "throw";
const script = vi.hoisted(() => ({
  answers: [] as unknown[],
  asked: [] as string[],
}));
vi.mock("#lib/api/client.ts", () => ({
  api: {
    GET: async (path: string) => {
      script.asked.push(path);
      const answer = script.answers.shift() as Answer;
      if (answer === "throw") throw new Error("down");
      return answer;
    },
  },
}));

import { load } from "./+page.ts";

beforeEach(() => {
  script.answers = [];
  script.asked = [];
});

/** What `load` redirects to. */
async function redirectsTo(...answers: Answer[]): Promise<string> {
  script.answers = answers;
  try {
    await load();
  } catch (thrown) {
    return (thrown as { location: string }).location;
  }
  throw new Error("the start page did not redirect");
}

describe("the start page", () => {
  it("opens the first-run flow until it has been through", async () => {
    expect(await redirectsTo({ data: { completed: false } })).toBe("/welcome");
    expect(script.asked).toEqual(["/api/first-run"]);
  });

  it("opens the workspace list once it has", async () => {
    expect(await redirectsTo({ data: { completed: true } })).toBe(
      "/workspaces",
    );
  });

  it("opens the workspace list when puddle can't say, so its problems show there", async () => {
    expect(await redirectsTo({ error: { error: "internal" } })).toBe(
      "/workspaces",
    );
    expect(await redirectsTo("throw")).toBe("/workspaces");
  });
});
