// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { LOCAL_LABELS, localCategory } from "./local.ts";

describe("localCategory", () => {
  it.each([
    ["127.0.0.1", "loopback"],
    ["127.9.9.9", "loopback"],
    ["10.1.2.3", "private"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["192.168.1.10", "private"],
    ["169.254.1.1", "link_local"],
    ["169.254.169.254", "metadata"],
    ["0.0.0.0", "special"],
    ["100.64.0.1", "special"],
    ["198.18.0.1", "special"],
    ["192.0.0.8", "special"],
    ["240.0.0.1", "special"],
    ["::1", "loopback"],
    ["[::1]", "loopback"],
    ["fe80::1", "link_local"],
    ["fd12:3456::1", "private"],
    ["fc00::1", "private"],
    ["fd00:ec2::254", "metadata"],
    ["::ffff:10.0.0.1", "private"],
  ])("%s is %s", (host, category) => {
    expect(localCategory(host)).toBe(category);
  });

  it.each([
    "8.8.8.8",
    "172.32.0.1",
    "172.15.0.1",
    "100.128.0.1",
    "999.1.1.1",
    "example.com",
    "localhost",
    "2606:4700::1111",
    "::ffff:8.8.8.8",
    "::ffff:",
  ])("%s is not local", (host) => {
    expect(localCategory(host)).toBeNull();
  });

  it("has a label for every category", () => {
    expect(Object.keys(LOCAL_LABELS).sort()).toEqual([
      "link_local",
      "loopback",
      "metadata",
      "private",
      "special",
    ]);
  });
});
