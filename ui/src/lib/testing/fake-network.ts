// SPDX-License-Identifier: GPL-3.0-or-later
// A healthy network-health report to change in a test. Not shipped (tests import it).
import type { NetworkHealth } from "#lib/network/model.ts";

export function report(over: Partial<NetworkHealth> = {}): NetworkHealth {
  return {
    generated_at: 1000,
    proxy: {
      mode: "system",
      detected: "pac",
      auto_detect: true,
      pac_url: "http://wpad.corp.example/proxy.pac",
      pac_state: "answering",
      http_proxy: null,
      https_proxy: null,
      bypass_entries: 0,
      settings_error: null,
      epoch: 3,
      last_change_at: null,
      dead_proxies: [],
    },
    sign_in: { methods: ["negotiate", "ntlm"], attempts: [] },
    roots: {
      synced: true,
      synced_at: 900,
      roots: 1,
      intermediates: 0,
      certificates: [],
      skipped: [],
      unreadable_stores: [],
    },
    pull_proxy: { active: true, via_upstream: true },
    routes: [],
    ...over,
  };
}
