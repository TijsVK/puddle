<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import DirectSshDialog from "#lib/components/DirectSshDialog.svelte";
  import MicrosoftServerDialog from "#lib/components/MicrosoftServerDialog.svelte";
  import {
    CODE_SERVER_NOTE,
    MICROSOFT_NOTE,
    needsMicrosoftConsent,
    serverOf,
    type ServerChoice,
  } from "#lib/settings/model.ts";
  import { globalSettings as store } from "#lib/stores/global-settings.svelte.ts";
  import StepHeading from "#lib/welcome/StepHeading.svelte";
  import { around } from "#lib/welcome/steps.ts";
  import {
    DIRECT_SSH_HINT,
    DIRECT_SSH_LABEL,
    TRUST_WORDS_GLOBAL,
  } from "#lib/workspaces/direct-ssh.ts";
  import "#lib/theme/controls.css";

  let saved = $state<string | null>(null);
  let problem = $state<string | null>(null);
  let trustOpen = $state(false);
  let popupOpen = $state(false);
  let popupBusy = $state(false);
  let popupError = $state<string | null>(null);
  // What the radios show: the stored server, except while the popup asks about Microsoft's.
  let choice = $state<ServerChoice>("code_server");

  onMount(() => void store.load(store.view !== null));

  $effect(() => {
    if (store.view) choice = serverOf(store.view);
  });

  /** Saves one change at once, as Settings does: no draft to lose by going Back. */
  async function save(
    patch: Parameters<typeof store.save>[0],
    what: string,
  ): Promise<boolean> {
    saved = null;
    problem = null;
    const result = await store.save(patch);
    if (result.ok) saved = `${what} saved.`;
    else problem = result.message;
    return result.ok;
  }

  async function chooseServer() {
    const consent = store.consents?.vscode_server;
    if (choice === "microsoft" && consent && needsMicrosoftConsent(consent)) {
      // The radio goes back to what is stored until the popup is accepted.
      choice = store.view ? serverOf(store.view) : "code_server";
      popupError = null;
      popupOpen = true;
      return;
    }
    if (!(await save({ server: { server: choice } }, "Server"))) {
      choice = store.view ? serverOf(store.view) : "code_server";
    }
  }

  async function accept(telemetry: boolean) {
    popupBusy = true;
    popupError = null;
    const result = await store.grantMicrosoft(telemetry);
    popupBusy = false;
    if (result.ok) {
      popupOpen = false;
      saved = "Microsoft's server chosen.";
    } else {
      popupError = result.message;
    }
  }
</script>

<StepHeading
  title="How do you want to connect?"
  lead="You can change both choices later in Settings. Each is saved as soon as you make it."
/>

<div class="status" aria-live="polite">
  {#if saved}<p class="saved">{saved}</p>{/if}
  {#if problem}<p class="error" role="alert">{problem}</p>{/if}
</div>

{#if store.status === "loading" && !store.view}
  <p class="muted">Loading&hellip;</p>
{:else if store.status === "newer"}
  <p class="error" role="alert">
    These settings were saved by a newer puddle. Update puddle to change them.
  </p>
{:else if !store.view || !store.consents}
  <p class="error" role="alert">Couldn't read puddle's settings.</p>
{:else}
  {@const view = store.view}
  <fieldset class="card">
    <legend>Editor in your browser</legend>
    <p class="muted">Optional: it needs nothing installed on this computer.</p>
    <label class="choice">
      <input
        type="radio"
        name="server"
        id="set-server"
        value="code_server"
        bind:group={choice}
        onchange={() => void chooseServer()}
      />
      <span>
        <b>code-server (bundled)</b>
        <span class="chip">default</span>
        <span class="desc">{CODE_SERVER_NOTE}</span>
      </span>
    </label>
    <label class="choice">
      <input
        type="radio"
        name="server"
        value="microsoft"
        bind:group={choice}
        onchange={() => void chooseServer()}
      />
      <span>
        <b>Microsoft's VS Code server</b>
        <span class="desc"
          >{MICROSOFT_NOTE} You accept Microsoft's licence terms.</span
        >
      </span>
    </label>
  </fieldset>

  <fieldset class="card">
    <legend>Desktop VS Code</legend>
    <label class="choice">
      <input
        type="checkbox"
        id="set-direct-ssh"
        checked={view.effective.direct_ssh.value}
        onchange={async (e) => {
          const box = e.currentTarget;
          if (box.checked) {
            // Turning it on says the trust text first; the dialog saves.
            box.checked = false;
            trustOpen = true;
            return;
          }
          if (
            !(await save({ layer: { direct_ssh: false } }, DIRECT_SSH_LABEL))
          ) {
            box.checked = store.view?.effective.direct_ssh.value ?? false;
          }
        }}
      />
      <span>
        <b>{DIRECT_SSH_LABEL} for new workspaces</b>
        <span class="desc">{DIRECT_SSH_HINT} Off by default.</span>
      </span>
    </label>
  </fieldset>
{/if}

<div class="actions">
  <a class="btn" href={around("connect").back}>Back</a>
  <a class="btn primary" href={around("connect").next}>Continue</a>
</div>

<DirectSshDialog
  bind:open={trustOpen}
  words={TRUST_WORDS_GLOBAL}
  onConfirm={() => void save({ layer: { direct_ssh: true } }, DIRECT_SSH_LABEL)}
/>

<MicrosoftServerDialog
  bind:open={popupOpen}
  busy={popupBusy}
  error={popupError}
  onAccept={(telemetry) => void accept(telemetry)}
/>

<style>
  .muted,
  .desc {
    color: var(--color-text-muted);
  }
  .muted {
    margin: 0;
  }
  .desc {
    display: block;
    font-size: var(--text-sm);
  }
  .status {
    min-height: 1.5rem;
  }
  .status p {
    margin: 0;
  }
  .saved {
    color: var(--color-success);
  }
  .error {
    color: var(--color-danger);
  }
  .card {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  legend {
    padding: 0 var(--space-1);
    font-weight: 600;
  }
  .choice {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    cursor: pointer;
  }
  .choice input {
    flex: none;
    width: 1.5rem;
    height: 1.5rem;
    margin: 0;
  }
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
