// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { report } from "#lib/testing/fake-network.ts";
import { devCertificateLine, rootsLine } from "./certificates.ts";

const roots = (over: Partial<ReturnType<typeof report>["roots"]>) => ({
  roots: { ...report().roots, ...over },
});

describe("the development certificate line", () => {
  it("says puddle uses the one Windows already trusts", () => {
    const line = devCertificateLine("reusing_existing");
    expect(line.tone).toBe("ok");
    expect(line.title).toBe("Using your existing .NET development certificate");
    expect(line.text).toMatch(/No trust dialog/);
  });

  it("says plainly that nothing was looked at yet", () => {
    for (const status of ["not_checked", undefined] as const) {
      const line = devCertificateLine(status);
      expect(line.tone).toBe("skipped");
      expect(line.title).toBe("Development certificate: not checked yet");
      expect(line.text).toMatch(/browser warning/);
    }
  });
});

describe("the company roots line", () => {
  it("waits for the report, and says when it never came", () => {
    expect(rootsLine(null, false).text).toMatch(/reading/);
    const failed = rootsLine(null, true);
    expect(failed.title).toBe("Company certificates: not read");
    expect(failed.text).toMatch(/standard certificates/);
  });

  it("says the stores were not read yet", () => {
    const line = rootsLine(roots({ synced: false, roots: 0 }), false);
    expect(line.tone).toBe("skipped");
    expect(line.title).toBe("Company certificates: not read yet");
  });

  it("warns when a certificate store could not be read, whatever else was found", () => {
    const one = rootsLine(
      roots({
        synced: true,
        roots: 2,
        unreadable_stores: ["LocalMachine\\Root: access denied"],
      }),
      false,
    );
    expect(one.tone).toBe("warn");
    expect(one.title).toBe("1 certificate store couldn't be read");
    expect(one.text).toMatch(/Network health/);
    const two = rootsLine(
      roots({ synced: true, roots: 0, unreadable_stores: ["a", "b"] }),
      false,
    );
    expect(two.title).toBe("2 certificate stores couldn't be read");
  });

  it("says none were found", () => {
    const line = rootsLine(roots({ synced: true, roots: 0 }), false);
    expect(line.tone).toBe("info");
    expect(line.title).toBe("No company root certificates found");
  });

  it("counts the roots workspaces get", () => {
    const one = rootsLine(roots({ synced: true, roots: 1 }), false);
    expect(one.title).toBe("1 company root certificate found");
    expect(one.tone).toBe("ok");
    const two = rootsLine(roots({ synced: true, roots: 2 }), false);
    expect(two.title).toBe("2 company root certificates found");
    expect(two.text).toMatch(/Added to every workspace/);
  });
});
