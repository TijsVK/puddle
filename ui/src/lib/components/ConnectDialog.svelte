<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import Code from "@lucide/svelte/icons/code";
  import Globe from "@lucide/svelte/icons/globe";
  import FormDialog from "./FormDialog.svelte";
  import TrustedBadge from "./TrustedBadge.svelte";
  import {
    DIRECT_SSH_HINT,
    DIRECT_SSH_LABEL,
  } from "#lib/workspaces/direct-ssh.ts";
  import { serverNote, type ServerChoice } from "#lib/settings/model.ts";
  import type { Workspace } from "#lib/workspaces/model.ts";
  import "#lib/theme/controls.css";

  // The one "how do you want to connect" step. The browser editor is on top and keeps the
  // workspace isolated. Below it is the switch for direct SSH (off by default); desktop VS Code
  // works only once it is on, and turning it on asks for the trust text first (the caller does).
  let {
    open = $bindable(false),
    workspace,
    server,
    onDesktop,
    onDirectSsh,
  }: {
    open?: boolean;
    workspace: Workspace;
    /** The VS Code server the browser editor uses, once known. */
    server: ServerChoice | null;
    onDesktop: (w: Workspace) => void;
    /** The user flipped the switch: turn direct SSH `on` or off for this workspace. */
    onDirectSsh: (w: Workspace, on: boolean) => void;
  } = $props();
</script>

<FormDialog
  bind:open
  title="Connect to {workspace.name}"
  description="Choose how to open this workspace."
>
  <div class="connect">
    <section aria-labelledby="connect-browser-h">
      <h3 id="connect-browser-h">In the browser</h3>
      <p class="desc" id="connect-browser-desc">
        Keeps the workspace isolated from this computer.
        {#if server}{serverNote(server)}{/if}
        <a href="/settings#s-vsc" onclick={() => (open = false)}
          >Change the server in Settings</a
        >. The browser editor is not available yet.
      </p>
      <button
        type="button"
        class="btn"
        disabled
        aria-describedby="connect-browser-desc"
      >
        <Globe aria-hidden="true" size={16} />Open in the browser
      </button>
    </section>

    <section aria-labelledby="connect-ssh-h">
      <h3 id="connect-ssh-h">
        On this computer {#if workspace.direct_ssh}<TrustedBadge />{/if}
      </h3>
      <label class="choice">
        <input
          type="checkbox"
          checked={workspace.direct_ssh}
          aria-describedby="connect-ssh-desc"
          onchange={(e) => {
            const box = e.currentTarget;
            const wanted = box.checked;
            // The switch shows what is stored; the caller changes it once the change is saved.
            box.checked = workspace.direct_ssh;
            onDirectSsh(workspace, wanted);
          }}
        />
        {DIRECT_SSH_LABEL}
      </label>
      <p class="desc" id="connect-ssh-desc">
        {DIRECT_SSH_HINT}
        {#if !workspace.direct_ssh}Off: puddle opens no SSH way in and writes no
          ssh config entry.{/if}
      </p>
      <button
        type="button"
        class="btn primary"
        disabled={!workspace.direct_ssh}
        onclick={() => {
          // Closing the step clears its workspace, so take it first.
          const w = workspace;
          open = false;
          onDesktop(w);
        }}
      >
        <Code aria-hidden="true" size={16} />Open in VS Code
      </button>
    </section>

    <div class="actions">
      <button type="button" class="btn" onclick={() => (open = false)}
        >Close</button
      >
    </div>
  </div>
</FormDialog>

<style>
  .connect {
    display: grid;
    gap: var(--space-4);
  }
  section {
    display: grid;
    gap: var(--space-2);
    justify-items: start;
  }
  h3 {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: 0;
    font-size: var(--text-md);
  }
  .desc {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  a {
    color: var(--color-accent);
  }
  .btn:disabled {
    cursor: default;
    opacity: 0.6;
  }
</style>
