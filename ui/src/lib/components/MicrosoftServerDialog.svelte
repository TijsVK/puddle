<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import FormDialog from "./FormDialog.svelte";
  import { MS_POPUP, MS_TERMS_URL } from "#lib/settings/model.ts";
  import "#lib/theme/controls.css";

  // The one place a user agrees to download Microsoft's VS Code server. Closing it in any way
  // other than the accept button records nothing and keeps code-server.
  let {
    open = $bindable(false),
    busy = false,
    error = null,
    onAccept,
  }: {
    open?: boolean;
    busy?: boolean;
    error?: string | null;
    onAccept: (telemetry: boolean) => void;
  } = $props();

  let telemetry = $state(false);

  $effect(() => {
    // A fresh popup always starts with telemetry off.
    if (open) telemetry = false;
  });
</script>

<FormDialog
  bind:open
  title={MS_POPUP.title}
  returnFocusTo={() => document.getElementById("set-server")}
>
  <form
    onsubmit={(event) => {
      event.preventDefault();
      if (!busy) onAccept(telemetry);
    }}
  >
    <p class="body">
      <strong>{MS_POPUP.statement}</strong>
      {MS_POPUP.rest}
      <a href={MS_TERMS_URL} target="_blank" rel="noopener noreferrer"
        >{MS_POPUP.licenceLink}<span class="visually-hidden">
          (opens in your browser)</span
        ></a
      >
    </p>
    <label class="choice">
      <input type="checkbox" bind:checked={telemetry} />
      {MS_POPUP.telemetry}
    </label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="actions">
      <button type="button" class="btn" onclick={() => (open = false)}
        >{MS_POPUP.decline}</button
      >
      <button type="submit" class="btn primary" disabled={busy}
        >{MS_POPUP.accept}</button
      >
    </div>
  </form>
</FormDialog>

<style>
  .body {
    margin: 0;
  }
  a {
    color: var(--color-accent);
  }
</style>
