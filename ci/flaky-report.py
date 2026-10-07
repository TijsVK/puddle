#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""List the tests that failed and then passed on a retry, from a nextest junit.xml.

Usage: flaky-report.py <junit.xml>. Prints a Markdown section (appended to the job summary by the
caller), emits one ::warning:: per flaky test, and always exits 0: a flake is reported, never red.
Genuine failures (no pass on the retry) stay the test step's own failure.
"""
import sys
import xml.etree.ElementTree as ET


def main() -> int:
    try:
        root = ET.parse(sys.argv[1]).getroot()
    except (OSError, ET.ParseError, IndexError) as err:
        print(f"### Flaky tests\n\nNo report: {err}")
        return 0
    flaky = []
    for case in root.iter("testcase"):
        if case.find("flakyFailure") is not None or case.find("flakyError") is not None:
            flaky.append(f"{case.get('classname', '')}::{case.get('name', '')}")
    print("### Flaky tests (failed, passed on one retry)\n")
    if not flaky:
        print("None.")
    for name in sorted(flaky):
        print(f"- `{name}`")
        print(f"::warning title=flaky test::{name} failed and passed on retry", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
