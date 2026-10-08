// SPDX-License-Identifier: GPL-3.0-or-later
// The launch switches the Windows e2e project gives the installed Edge.
//
// From Windows 11 22H2 on, Chromium asks Windows for a random local port for each connection it
// opens (`TcpPortRandomizationWin`, on by default). With the default pool of 16 384 dynamic ports
// and the thousands of short loopback connections a full e2e run opens, Windows now and then
// answers such a `connect()` at once with error 10055 (no buffer space), Chromium reports it as
// `net::ERR_NO_BUFFER_SPACE`, and the page being loaded never starts: about one full run in four.
// With the feature off, Windows picks the port itself and no run failed that way.
//
// Playwright passes its own `--disable-features` list, and Chromium reads only the last such
// switch, so that list is repeated here with the one feature added.
//
// A stopgap: take the switch out when a full run of the installed Edge no longer fails that way
// without it (try that after each Edge or Playwright update; the test beside this file already
// fails on a Playwright update).

/** The version of Playwright whose list `PLAYWRIGHT_DISABLED_FEATURES` copies. */
export const COPIED_FROM_PLAYWRIGHT = "1.63.0";

/** `disabledFeatures` in Playwright's `chromiumSwitches.ts`. */
const PLAYWRIGHT_DISABLED_FEATURES = [
  "AvoidUnnecessaryBeforeUnloadCheckSync",
  "DestroyProfileOnBrowserClose",
  "DialMediaRouteProvider",
  "GlobalMediaControls",
  "HttpsUpgrades",
  "LensOverlay",
  "MediaRouter",
  "PaintHolding",
  "ThirdPartyStoragePartitioning",
  "BlockOriginHeaderModificationOnRedirect",
  "Translate",
  "AutoDeElevate",
  "OptimizationHints",
  "msForceBrowserSignIn",
  "msEdgeUpdateLaunchServicesPreferredVersion",
];

export const EDGE_DISABLED_FEATURES = [
  ...PLAYWRIGHT_DISABLED_FEATURES,
  "TcpPortRandomizationWin",
];

export function edgeLaunchArgs(): string[] {
  return [`--disable-features=${EDGE_DISABLED_FEATURES.join(",")}`];
}
