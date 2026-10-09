<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import UnknownFields from "#lib/components/UnknownFields.svelte";
  import { onMount } from "svelte";
  import DirectSshDialog from "#lib/components/DirectSshDialog.svelte";
  import MicrosoftServerDialog from "#lib/components/MicrosoftServerDialog.svelte";
  import { api } from "#lib/api/client.ts";
  import { LOCAL_LABELS, type LocalCategory } from "#lib/decision/local.ts";
  import {
    CLOSE_OPTIONS,
    LOCAL_EXPLAIN,
    memorySizes,
    needsMicrosoftConsent,
    parseGrace,
    serverNote,
    serverOf,
    type CloseBehaviour,
    type Layer,
    type ServerChoice,
  } from "#lib/settings/model.ts";
  import { globalSettings as store } from "#lib/stores/global-settings.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import { density } from "#lib/theme/density.svelte.ts";
  import { isDensityChoice } from "#lib/theme/density.ts";
  import { theme } from "#lib/theme/theme.svelte.ts";
  import {
    DIRECT_SSH_HINT,
    DIRECT_SSH_LABEL,
    TRUST_WORDS_GLOBAL,
  } from "#lib/workspaces/direct-ssh.ts";
  import { isThemeChoice } from "#lib/theme/theme.ts";
  import "#lib/theme/controls.css";

  const SECTIONS: [string, string][] = [
    ["s-app", "Appearance"],
    ["s-notify", "Notifications"],
    ["s-ws", "Workspaces"],
    ["s-net", "Network"],
    ["s-vsc", "Browser VS Code"],
    ["s-git", "Git and credentials"],
    ["s-priv", "Privacy"],
    ["s-about", "About"],
  ];
  const CATEGORIES: LocalCategory[] = [
    "loopback",
    "private",
    "link_local",
    "metadata",
    "special",
  ];

  let saved = $state<string | null>(null);
  let problem = $state<string | null>(null);
  let graceError = $state<string | null>(null);
  let trustOpen = $state(false);
  let popupOpen = $state(false);
  let popupBusy = $state(false);
  let popupError = $state<string | null>(null);
  let version = $state<string | null>(null);
  let notices = $state<string | null>(null);
  let noticesFailed = $state(false);

  onMount(() => {
    void store.load(store.view !== null);
    void api
      .GET("/api/health")
      .then((r) => (version = r.data?.version ?? null))
      .catch(() => undefined);
  });

  /** Saves one change; when the API refuses it the control goes back to what is stored. */
  async function save(
    patch: Parameters<typeof store.save>[0],
    what: string,
    undo: () => void,
  ): Promise<void> {
    saved = null;
    problem = null;
    const result = await store.save(patch);
    if (result.ok) {
      saved = `${what} saved.`;
    } else {
      problem = result.message;
      undo();
    }
  }

  const layerPatch = (patch: Partial<Layer>, what: string, undo: () => void) =>
    save({ layer: patch }, what, undo);

  async function chooseTheme(select: HTMLSelectElement) {
    const value = select.value;
    if (!isThemeChoice(value)) return;
    saved = null;
    problem = null;
    if (await theme.set(value)) saved = "Theme saved.";
    else problem = "The theme changed here but puddle couldn't save it.";
  }

  async function chooseDensity(select: HTMLSelectElement) {
    const value = select.value;
    if (!isDensityChoice(value)) return;
    saved = null;
    problem = null;
    if (await density.set(value)) saved = "Density saved.";
    else problem = "The density changed here but puddle couldn't save it.";
  }

  async function chooseServer(select: HTMLSelectElement) {
    const view = store.view;
    const consent = store.consents?.vscode_server;
    if (!view || !consent) return;
    const choice = select.value as ServerChoice;
    if (choice === "microsoft" && needsMicrosoftConsent(consent)) {
      select.value = serverOf(view);
      popupError = null;
      popupOpen = true;
      return;
    }
    await save({ server: { server: choice } }, "Server", () => {
      select.value = serverOf(view);
    });
  }

  async function accept(telemetry: boolean) {
    popupBusy = true;
    popupError = null;
    const result = await store.grantMicrosoft(telemetry);
    popupBusy = false;
    if (result.ok) {
      popupOpen = false;
      saved = "Microsoft's server chosen.";
      toasts.push(
        "Consent recorded. puddle downloads the server the next time you open browser VS Code.",
      );
    } else {
      popupError = result.message;
    }
  }

  async function saveGrace(input: HTMLInputElement) {
    const parsed = parseGrace(input.value);
    if (!parsed.ok) {
      graceError = parsed.message;
      return;
    }
    graceError = null;
    await layerPatch({ reconnection_grace: parsed.secs }, "Grace", () => {
      input.value = String(store.view?.effective.reconnection_grace.value);
    });
  }

  async function loadNotices() {
    if (notices !== null || noticesFailed) return;
    try {
      notices = (await import("../../../THIRD-PARTY-NOTICES.txt?raw")).default;
    } catch {
      noticesFailed = true;
    }
  }

  const when = (ms: number) =>
    new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(ms);
</script>

<h1 tabindex="-1">Settings</h1>
<p class="sub">
  Global values. A workspace can override most of them in its own Settings tab.
</p>

<div class="status" aria-live="polite">
  {#if saved}<p class="saved">{saved}</p>{/if}
  {#if problem}<p class="error" role="alert">{problem}</p>{/if}
</div>

{#if store.status === "loading" && !store.view}
  <p class="muted">Loading settings&hellip;</p>
{:else if store.status === "newer"}
  <p class="error" role="alert">
    These settings were saved by a newer puddle. Update puddle to change them.
  </p>
{:else if !store.view || !store.consents}
  <p class="muted" role="alert">Couldn't read puddle's settings.</p>
{:else}
  {@const view = store.view}
  {@const eff = view.effective}
  {@const server = serverOf(view)}
  {@const consent = store.consents.vscode_server}
  <UnknownFields fields={view.unknown_fields} />
  <div class="layout">
    <nav aria-label="Settings sections">
      {#each SECTIONS as [id, name] (id)}
        <a href="#{id}">{name}</a>
      {/each}
    </nav>
    <div class="sections">
      <section class="card" id="s-app" aria-labelledby="h-app">
        <h2 id="h-app">Appearance</h2>
        <div class="setting">
          <div class="grow">
            <label for="set-theme">Theme</label>
            <p class="desc">Follows your system unless you pick one.</p>
          </div>
          <select
            id="set-theme"
            value={theme.choice}
            onchange={(e) => void chooseTheme(e.currentTarget)}
          >
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-density">Density</label>
            <p class="desc">
              Compact tightens the spacing so more fits on screen. Buttons and
              fields stay easy to hit.
            </p>
          </div>
          <select
            id="set-density"
            value={density.choice}
            onchange={(e) => void chooseDensity(e.currentTarget)}
          >
            <option value="comfortable">Comfortable</option>
            <option value="compact">Compact</option>
          </select>
        </div>
      </section>

      <section class="card" id="s-notify" aria-labelledby="h-notify">
        <h2 id="h-notify">Notifications</h2>
        <div class="setting">
          <div class="grow">
            <label for="set-notify">System notifications for new requests</label
            >
            <p class="desc">
              One notification per host, at most one every 10 seconds per
              workspace. Clicking it opens the request.
            </p>
          </div>
          <input
            id="set-notify"
            type="checkbox"
            checked={view.ui.notifications ?? true}
            onchange={(e) => {
              const box = e.currentTarget;
              void save(
                { ui: { notifications: box.checked } },
                "Notifications",
                () => {
                  box.checked = view.ui.notifications ?? true;
                },
              );
            }}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-sound">Sound</label>
            <p class="desc">Play the system notification sound.</p>
          </div>
          <input
            id="set-sound"
            type="checkbox"
            checked={view.ui.sound ?? false}
            onchange={(e) => {
              const box = e.currentTarget;
              void save({ ui: { sound: box.checked } }, "Sound", () => {
                box.checked = view.ui.sound ?? false;
              });
            }}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-close">Closing the window</label>
            <p class="desc">
              Keeping puddle in the tray lets workspaces keep running, so builds
              carry on. Quitting from the tray menu stops every workspace.
            </p>
          </div>
          <select
            id="set-close"
            value={view.ui.close_behaviour ?? "tray"}
            onchange={(e) => {
              const select = e.currentTarget;
              void save(
                { ui: { close_behaviour: select.value as CloseBehaviour } },
                "Closing the window",
                () => {
                  select.value = view.ui.close_behaviour ?? "tray";
                },
              );
            }}
          >
            {#each CLOSE_OPTIONS as option (option.value)}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
        </div>
      </section>

      <section class="card" id="s-ws" aria-labelledby="h-ws">
        <h2 id="h-ws">Workspaces</h2>
        <div class="setting">
          <div class="grow">
            <label for="set-memory">Default memory</label>
            <p class="desc">
              Applies the next time a workspace without its own value starts.
            </p>
          </div>
          <select
            id="set-memory"
            value={String(eff.memory.value)}
            onchange={(e) => {
              const select = e.currentTarget;
              void layerPatch(
                { memory: Number(select.value) },
                "Default memory",
                () => {
                  select.value = String(eff.memory.value);
                },
              );
            }}
          >
            {#each memorySizes(eff.memory.value) as size (size.value)}
              <option value={String(size.value)}>{size.label}</option>
            {/each}
          </select>
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-direct-ssh"
              >{DIRECT_SSH_LABEL} for new workspaces</label
            >
            <p class="desc" id="set-direct-ssh-desc">
              {DIRECT_SSH_HINT} Off by default. A workspace can set its own switch.
            </p>
          </div>
          <input
            id="set-direct-ssh"
            type="checkbox"
            aria-describedby="set-direct-ssh-desc"
            checked={eff.direct_ssh.value}
            onchange={(e) => {
              const box = e.currentTarget;
              if (box.checked) {
                // Turning it on says the trust text first; the dialog saves.
                box.checked = eff.direct_ssh.value;
                trustOpen = true;
                return;
              }
              void layerPatch({ direct_ssh: false }, DIRECT_SSH_LABEL, () => {
                box.checked = eff.direct_ssh.value;
              });
            }}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-capture">Keep logins made in workspaces</label>
            <p class="desc" id="set-capture-desc">
              When you sign in to Claude Code, GitHub or Copilot inside a
              workspace, puddle keeps the real token on this computer and the
              workspace gets a stand-in that works only through puddle. On by
              default. A workspace can set its own switch; a change takes effect
              when a workspace next starts, and turning it off leaves the logins
              puddle already kept unused.
            </p>
          </div>
          <input
            id="set-capture"
            type="checkbox"
            aria-describedby="set-capture-desc"
            checked={eff.capture_logins.value}
            onchange={(e) => {
              const box = e.currentTarget;
              void layerPatch(
                { capture_logins: box.checked },
                "Login capture",
                () => {
                  box.checked = eff.capture_logins.value;
                },
              );
            }}
          />
        </div>
      </section>

      <section class="card" id="s-net" aria-labelledby="h-net">
        <h2 id="h-net">Network</h2>
        <h3>Network health</h3>
        <div class="setting">
          <div class="grow">
            <p class="desc">
              The proxy puddle found, how it signs in, and the company
              certificates workspaces get.
            </p>
          </div>
          <a class="btn" href="/settings/network-health"
            >Details<span class="visually-hidden">
              about network health</span
            ></a
          >
        </div>
        <h3>System check</h3>
        <div class="setting">
          <div class="grow">
            <p class="desc">
              Checks this computer again: virtualization, the hypervisor, the
              bundled runtime and a test start of a tiny workspace.
            </p>
          </div>
          <a class="btn" href="/welcome/check?from=settings"
            >Run the system check again</a
          >
        </div>
        <h3>Local destinations</h3>
        <p class="desc">
          Off by default. Turning one on makes those destinations
          <b>approvable</b>: each one still needs a rule or your approval.
          Nothing is allowed by turning it on.
        </p>
        {#each CATEGORIES as category (category)}
          <div class="setting">
            <div class="grow">
              <label for="set-local-{category}">{LOCAL_LABELS[category]}</label>
              <p class="desc">{LOCAL_EXPLAIN[category]}</p>
            </div>
            <input
              id="set-local-{category}"
              type="checkbox"
              checked={eff.local_toggles[category].value}
              onchange={(e) => {
                const box = e.currentTarget;
                void layerPatch(
                  {
                    local_toggles: {
                      ...view.workspace_defaults.local_toggles,
                      [category]: box.checked,
                    },
                  },
                  LOCAL_LABELS[category],
                  () => {
                    box.checked = eff.local_toggles[category].value;
                  },
                );
              }}
            />
          </div>
        {/each}
        <div class="setting">
          <div class="grow">
            <label for="set-wild">Let suffix rules reach local addresses</label>
            <p class="desc">
              Off: <span class="mono">.example.com</span> never matches a name that
              resolves to a local address; local destinations need an exact rule.
            </p>
          </div>
          <input
            id="set-wild"
            type="checkbox"
            checked={eff.wildcards_reach_local.value}
            onchange={(e) => {
              const box = e.currentTarget;
              void layerPatch(
                { wildcards_reach_local: box.checked },
                "Suffix rules",
                () => {
                  box.checked = eff.wildcards_reach_local.value;
                },
              );
            }}
          />
        </div>
      </section>

      <section class="card" id="s-vsc" aria-labelledby="h-vsc">
        <h2 id="h-vsc">Browser VS Code</h2>
        <div class="setting">
          <div class="grow">
            <label for="set-server">Server</label>
            <p class="desc" id="set-server-note">{serverNote(server)}</p>
            {#if consent.state === "granted"}
              <p class="desc">
                You accepted Microsoft's terms on {when(consent.at)}.
              </p>
            {/if}
          </div>
          <select
            id="set-server"
            aria-describedby="set-server-note"
            value={server}
            onchange={(e) => void chooseServer(e.currentTarget)}
          >
            <option value="code_server">code-server (bundled)</option>
            <option value="microsoft">Microsoft's VS Code server</option>
          </select>
        </div>
        {#if server === "microsoft"}
          <div class="setting">
            <div class="grow">
              <label for="set-ms-telemetry">Send Microsoft telemetry</label>
              <p class="desc">
                Off adds <span class="mono">--disable-telemetry</span>.
              </p>
            </div>
            <input
              id="set-ms-telemetry"
              type="checkbox"
              checked={view.vscode_server.telemetry ?? false}
              onchange={(e) => {
                const box = e.currentTarget;
                void save(
                  { server: { telemetry: box.checked } },
                  "Telemetry",
                  () => {
                    box.checked = view.vscode_server.telemetry ?? false;
                  },
                );
              }}
            />
          </div>
        {/if}
        <div class="setting">
          <div class="grow">
            <label for="set-update">Update the server automatically</label>
            <p class="desc">
              Only switches when no window of that workspace is open.
            </p>
          </div>
          <input
            id="set-update"
            type="checkbox"
            checked={view.vscode_server.auto_update ?? true}
            onchange={(e) => {
              const box = e.currentTarget;
              void save(
                { server: { auto_update: box.checked } },
                "Updates",
                () => {
                  box.checked = view.vscode_server.auto_update ?? true;
                },
              );
            }}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-grace">Reconnection grace (seconds)</label>
            <p class="desc" id="set-grace-desc">
              How long a closed window's session is kept for a reconnect.
              {#if graceError}<span class="error" role="alert"
                  >{graceError}</span
                >{/if}
            </p>
          </div>
          <input
            id="set-grace"
            type="text"
            inputmode="numeric"
            class="narrow"
            aria-describedby="set-grace-desc"
            aria-invalid={graceError ? "true" : undefined}
            value={String(eff.reconnection_grace.value)}
            onchange={(e) => void saveGrace(e.currentTarget)}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-zoom">Zoom shortcuts</label>
            <p class="desc">Ctrl and plus or minus in workspace windows.</p>
          </div>
          <input
            id="set-zoom"
            type="checkbox"
            checked={eff.zoom_hotkeys.value}
            onchange={(e) => {
              const box = e.currentTarget;
              void layerPatch({ zoom_hotkeys: box.checked }, "Zoom", () => {
                box.checked = eff.zoom_hotkeys.value;
              });
            }}
          />
        </div>
        <div class="setting">
          <div class="grow">
            <label for="set-clip">Clipboard reads by pages</label>
            <p class="desc">
              Typing Ctrl+V always works; this is for pages that read the
              clipboard by themselves.
            </p>
          </div>
          <select
            id="set-clip"
            value={eff.clipboard_read.value}
            onchange={(e) => {
              const select = e.currentTarget;
              void layerPatch(
                { clipboard_read: select.value as "ask" | "allow" | "deny" },
                "Clipboard",
                () => {
                  select.value = eff.clipboard_read.value;
                },
              );
            }}
          >
            <option value="ask">Ask once per workspace</option>
            <option value="allow">Always allow</option>
            <option value="deny">Never allow</option>
          </select>
        </div>
      </section>

      <section class="card" id="s-git" aria-labelledby="h-git">
        <h2 id="h-git">Git and credentials</h2>
        <p>
          The Git name and email, and the credentials puddle adds to outgoing
          requests, are kept as identities. The secret of a credential never
          enters a workspace.
        </p>
        <p><a href="/identities">Manage identities</a></p>
      </section>

      <section class="card" id="s-priv" aria-labelledby="h-priv">
        <h2 id="h-priv">Privacy</h2>
        <p>
          puddle sends nothing about you or your use of it. There is no
          telemetry in this version, and puddle makes no update check.
        </p>
        <p class="muted">
          Traffic from inside your workspaces (including editor and extension
          telemetry) goes through your rules like any other request.
        </p>
      </section>

      <section class="card" id="s-about" aria-labelledby="h-about">
        <h2 id="h-about">About</h2>
        <p>
          <b>puddle{version ? ` ${version}` : ""}</b>
          <span class="muted"> &middot; GPL-3.0-or-later</span>
        </p>
        <details ontoggle={() => void loadNotices()}>
          <summary>Third-party licences</summary>
          {#if notices !== null}
            <!-- A scrollable region must be reachable by keyboard. -->
            <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
            <pre
              class="notices"
              tabindex="0"
              aria-label="Third-party licences">{notices}</pre>
          {:else if noticesFailed}
            <p class="error">Couldn't load the licence texts.</p>
          {:else}
            <p class="muted">Loading&hellip;</p>
          {/if}
        </details>
      </section>
    </div>
  </div>
{/if}

<DirectSshDialog
  bind:open={trustOpen}
  words={TRUST_WORDS_GLOBAL}
  onConfirm={() =>
    void layerPatch({ direct_ssh: true }, DIRECT_SSH_LABEL, () => undefined)}
/>

<MicrosoftServerDialog
  bind:open={popupOpen}
  busy={popupBusy}
  error={popupError}
  onAccept={(telemetry) => void accept(telemetry)}
/>

<style>
  h1 {
    margin: 0;
  }
  .sub,
  .muted,
  .desc {
    color: var(--color-text-muted);
  }
  .sub {
    margin: 0 0 var(--space-3);
  }
  .status {
    min-height: 1.5rem;
    margin-bottom: var(--space-2);
  }
  .status p,
  .desc {
    margin: 0;
  }
  .desc {
    font-size: var(--text-sm);
  }
  .saved {
    color: var(--color-success);
  }
  .error {
    color: var(--color-danger);
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 11rem) minmax(0, 1fr);
    gap: var(--space-5);
    align-items: start;
  }
  nav {
    position: sticky;
    top: var(--space-4);
    display: grid;
    gap: var(--space-1);
  }
  nav a {
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    color: var(--color-text);
    text-decoration: none;
  }
  nav a:hover {
    background: var(--color-surface-raised);
  }
  .sections {
    display: grid;
    gap: var(--space-4);
    max-width: 48rem;
  }
  .card {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    scroll-margin-top: var(--space-4);
  }
  h2 {
    margin: 0;
    font-size: var(--text-md);
  }
  h3 {
    margin: 0;
    font-size: var(--text-base, 1rem);
  }
  .card p {
    margin: 0;
  }
  .setting {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  label {
    font-weight: 600;
  }
  input[type="checkbox"] {
    width: 1.5rem;
    height: 1.5rem;
    flex: none;
  }
  select,
  input[type="text"] {
    min-height: var(--control-size);
    max-width: 18rem;
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  input[aria-invalid="true"] {
    border-color: var(--color-danger);
  }
  .narrow {
    width: 6rem;
  }
  .notices {
    max-height: 20rem;
    overflow: auto;
    margin: var(--space-2) 0 0;
    padding: var(--space-3);
    background: var(--color-bg);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    white-space: pre-wrap;
  }
  @media (max-width: 760px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
    }
    nav {
      position: static;
      display: flex;
      flex-wrap: wrap;
    }
    .setting {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
