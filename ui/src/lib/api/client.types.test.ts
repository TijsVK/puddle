// SPDX-License-Identifier: GPL-3.0-or-later
// Compile-time checks, enforced by `svelte-check`: each `@ts-expect-error` below must be a type
// error, or svelte-check fails ("unused directive"). So a wrong path, verb, parameter or body
// breaks the gate. The functions are never called.
import { expect, it } from "vitest";
import { createApiClient } from "./client.ts";

const client = createApiClient({ baseUrl: "http://x" });

function typeChecks() {
  // Right.
  void client.GET("/api/pending");
  void client.POST("/api/rules", {
    body: {
      pattern: "example.com",
      effect: "allow",
      scope: { type: "global" },
    },
  });
  void client.DELETE("/api/rules/{id}", { params: { path: { id: 1 } } });

  // Wrong path.
  // @ts-expect-error no such route
  void client.GET("/api/pendng");
  // Wrong verb for a real path.
  // @ts-expect-error /api/pending has no DELETE
  void client.DELETE("/api/pending");
  // Wrong path parameter type.
  // @ts-expect-error id is a number
  void client.DELETE("/api/rules/{id}", { params: { path: { id: "one" } } });
  // Missing path parameter.
  // @ts-expect-error id is required
  void client.DELETE("/api/rules/{id}", { params: { path: {} } });
  // Wrong body.
  // @ts-expect-error pattern is required and others are not fields
  void client.POST("/api/rules", { body: { nonsense: true } });
}

it("type checks are compiled by svelte-check, not run", () => {
  expect(typeof typeChecks).toBe("function");
});
