// SPDX-License-Identifier: GPL-3.0-or-later
// Turns the shell's event stream into notices: out-of-memory kills, a workspace that stopped
// or crashed without being asked to, and a network that got worse.
//
// "Without being asked": a stop is expected when the stream said the workspace was stopping,
// draining or being removed since it last ran. A stop with none of those, or a crash, is not.
// Statuses are tracked here from the events, seeded from the workspace list; a workspace never
// seen before can't be called unexpected.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import type { components } from "#lib/api/schema.d.ts";
import {
  problems,
  problemSummary,
  type NetworkHealth,
} from "#lib/network/model.ts";
import { asWorkspaceEvent } from "#lib/workspaces/events.ts";
import { identities } from "#lib/stores/identities.svelte.ts";
import type { LiveSource } from "#lib/stores/live.svelte.ts";
import { CredentialNotices, type IdentityLookup } from "./credentials.ts";
import { InAppNotifier, type Notifier } from "./notifier.ts";

type Status = components["schemas"]["WorkspaceStatus"];

const RUNNING: readonly Status[] = ["starting", "running", "paused"];
const NETWORK_KEY = "network";
const stopKey = (name: string) => `stop:${name}`;
const oomKey = (name: string) => `oom:${name}`;

export interface WatcherDeps {
  source?: LiveSource;
  notifier?: Notifier;
  api?: Pick<ApiClient, "GET" | "POST" | "PUT">;
  /** What the sign-in notice asks of the identities; the app's own by default. */
  identities?: IdentityLookup;
}

export class NoticeWatcher {
  readonly #source: LiveSource | undefined;
  readonly #notifier: Notifier;
  readonly #api: Pick<ApiClient, "GET" | "POST" | "PUT">;
  readonly #credentials: CredentialNotices;
  readonly #status = new Map<string, Status>();
  readonly #expected = new Set<string>();
  /** The summary the network notice last said, so an unchanged problem is not announced again. */
  #network: string | null = null;

  constructor(deps: WatcherDeps = {}) {
    this.#source = deps.source;
    this.#notifier = deps.notifier ?? new InAppNotifier();
    this.#api = deps.api ?? defaultApi;
    this.#credentials = new CredentialNotices({
      notifier: this.#notifier,
      identities: deps.identities ?? identities,
      api: this.#api,
    });
  }

  /** Reads the statuses the events will be compared with; never throws. */
  async seed(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/workspaces");
      if (!data) return;
      for (const w of data.workspaces) {
        // An event that already told us more recent news wins over the list.
        if (!this.#status.has(w.name)) this.#status.set(w.name, w.status);
      }
    } catch {
      // Without a list, the events alone still work for workspaces they name.
    }
  }

  /** Applies one stream event. */
  handle(raw: unknown): void {
    if (this.#credentials.handle(raw)) return;
    const event = asWorkspaceEvent(raw);
    if (!event) return;
    const name = event.workspace;
    switch (event.type) {
      case "oom_kill":
        this.#notifier.notify({
          key: oomKey(name),
          tone: "warning",
          title: `${name} ran out of memory and a process was killed.`,
          detail: `${event.process} (process ${event.pid}) was stopped. Give the workspace more memory in its settings; it applies at the next restart.`,
          link: {
            href: `/workspaces/${encodeURIComponent(name)}/settings`,
            label: "Workspace settings",
          },
        });
        return;
      case "workspace_progress":
        if (event.step === "stopping" || event.step === "removing") {
          this.#expected.add(name);
        }
        return;
      case "status_changed":
        this.#onStatus(name, event.status);
        return;
    }
  }

  #onStatus(name: string, status: Status): void {
    const before = this.#status.get(name);
    this.#status.set(name, status);
    if (status === "draining") {
      this.#expected.add(name);
      return;
    }
    if (RUNNING.includes(status) || status === "created") {
      this.#expected.delete(name);
      this.#notifier.resolve(stopKey(name));
      return;
    }
    const wasUp =
      before !== undefined && [...RUNNING, "draining"].includes(before);
    if (status === "crashed") {
      this.#notifier.notify({
        key: stopKey(name),
        tone: "warning",
        title: `${name} crashed.`,
        detail:
          "Its machine stopped working. Start it again from the workspace list.",
        link: {
          href: `/workspaces/${encodeURIComponent(name)}`,
          label: "Open workspace",
        },
      });
    } else if (status === "volume_missing") {
      this.#notifier.notify({
        key: stopKey(name),
        tone: "warning",
        title: `${name} can't start: its disk is missing.`,
        detail:
          "Restore the volume and start it again, or delete the workspace.",
        link: {
          href: `/workspaces/${encodeURIComponent(name)}`,
          label: "Open workspace",
        },
      });
    } else if (status === "stopped" && wasUp && !this.#expected.has(name)) {
      this.#notifier.notify({
        key: stopKey(name),
        tone: "warning",
        title: `${name} stopped without being asked to.`,
        detail:
          "Nothing in puddle stopped it. Start it again from the workspace list.",
        link: {
          href: `/workspaces/${encodeURIComponent(name)}`,
          label: "Open workspace",
        },
      });
    }
  }

  /** The network got worse or better: raises the notice while there is a problem, withdraws it after. */
  network(report: NetworkHealth | null): void {
    if (!report) return;
    const list = problems(report);
    if (list.length === 0) {
      this.#network = null;
      this.#notifier.resolve(NETWORK_KEY);
      return;
    }
    const title = `Network trouble: ${problemSummary(list)}`;
    if (title === this.#network) return;
    this.#network = title;
    this.#notifier.notify({
      key: NETWORK_KEY,
      tone: "warning",
      title,
      link: { href: "/settings/network-health", label: "Network health" },
    });
  }

  /** Listens to the stream; returns the function that stops it. */
  start(): () => void {
    void this.seed();
    const unsubscribe = this.#source?.subscribe({
      event: (e) => this.handle(e),
      resync: () => void this.seed(),
    });
    const stopCredentials = this.#credentials.start();
    return () => {
      unsubscribe?.();
      stopCredentials();
    };
  }
}
