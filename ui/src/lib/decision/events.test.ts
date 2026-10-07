// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { asInboxEvent } from "./events.ts";

const request = {
  id: 7,
  sandbox: "demo",
  host: "a.example.com",
  port: 443,
  first_seen: 1,
  last_seen: 2,
  attempts: 1,
  state: "requested",
  decided_at: null,
  decided_by: null,
  rule_id: null,
};

describe("asInboxEvent", () => {
  it("reads the four inbox events", () => {
    expect(
      asInboxEvent({
        type: "pending_opened",
        request,
        registrable_domain: "example.com",
      }),
    ).toEqual({
      type: "pending_opened",
      request,
      registrable_domain: "example.com",
    });
    expect(asInboxEvent({ type: "pending_opened", request })).toMatchObject({
      registrable_domain: null,
    });
    expect(
      asInboxEvent({
        type: "pending_updated",
        id: 7,
        attempts: 3,
        last_seen: 9,
      }),
    ).toEqual({
      type: "pending_updated",
      id: 7,
      attempts: 3,
      last_seen: 9,
    });
    expect(
      asInboxEvent({
        type: "pending_closed",
        id: 7,
        state: "allowed",
        rule_id: 4,
      }),
    ).toEqual({ type: "pending_closed", id: 7, state: "allowed", rule_id: 4 });
    expect(
      asInboxEvent({ type: "pending_closed", id: 7, state: "expired" }),
    ).toMatchObject({
      rule_id: null,
    });
    expect(
      asInboxEvent({
        type: "suppression_changed",
        sandbox: "demo",
        active: true,
        count: 12,
      }),
    ).toEqual({
      type: "suppression_changed",
      sandbox: "demo",
      active: true,
      count: 12,
    });
  });

  it("widens the API's short form of a request to an open one, with its domain", () => {
    const summary = {
      id: 7,
      sandbox: "demo",
      host: "a.example.com",
      port: 443,
      first_seen: 1,
      last_seen: 2,
      attempts: 1,
      registrable_domain: "example.com",
    };
    expect(asInboxEvent({ type: "pending_opened", request: summary })).toEqual({
      type: "pending_opened",
      request: {
        id: 7,
        sandbox: "demo",
        host: "a.example.com",
        port: 443,
        first_seen: 1,
        last_seen: 2,
        attempts: 1,
        state: "requested",
        decided_at: null,
        decided_by: null,
        rule_id: null,
        blocked_by: null,
      },
      registrable_domain: "example.com",
    });
    // An empty domain is no domain: the list is refetched instead.
    expect(
      asInboxEvent({
        type: "pending_opened",
        request: { ...summary, registrable_domain: "" },
      }),
    ).toMatchObject({ registrable_domain: null });
  });

  it("drops other events and anything malformed", () => {
    for (const bad of [
      null,
      "text",
      42,
      {},
      { type: "status_changed", sandbox: "demo", status: "running" },
      { type: "pending_opened" },
      { type: "pending_opened", request: { id: 1 } },
      { type: "pending_opened", request: null },
      { type: "pending_updated", id: "7", attempts: 3, last_seen: 9 },
      { type: "pending_updated", id: 7, attempts: Number.NaN, last_seen: 9 },
      { type: "pending_closed", id: 7 },
      { type: "suppression_changed", sandbox: "demo", active: "yes", count: 1 },
      { type: "suppression_changed", sandbox: 3, active: true, count: 1 },
    ]) {
      expect(asInboxEvent(bad)).toBeUndefined();
    }
  });
});
