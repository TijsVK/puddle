<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { AlertDialog } from "bits-ui";
  import { losses, type DeleteCheck } from "#lib/workspaces/model.ts";
  import "#lib/theme/controls.css";

  let {
    open = $bindable(false),
    name,
    check,
    working = false,
    error = null,
    onConfirm,
    onCancel,
  }: {
    open?: boolean;
    name: string;
    check: DeleteCheck;
    working?: boolean;
    error?: string | null;
    onConfirm: () => void;
    onCancel: () => void;
  } = $props();

  let cancelButton = $state<HTMLElement | null>(null);
  let understood = $state(false);

  const lines = $derived(losses(check));
  // A new check (the workspace changed) needs a new yes.
  $effect(() => {
    void check.fingerprint;
    understood = false;
  });
</script>

<AlertDialog.Root
  bind:open
  onOpenChange={(next) => {
    if (!next) onCancel();
  }}
>
  <AlertDialog.Portal>
    <AlertDialog.Overlay class="confirm-overlay" />
    <AlertDialog.Content
      class="confirm-content delete-dialog"
      onOpenAutoFocus={(event) => {
        // The safe choice first: Enter right after opening cancels.
        event.preventDefault();
        cancelButton?.focus();
      }}
    >
      <AlertDialog.Title class="confirm-title">Delete {name}?</AlertDialog.Title
      >
      <AlertDialog.Description class="confirm-detail">
        This removes the workspace and everything on its disk. It can't be
        undone.
      </AlertDialog.Description>

      {#if error}
        <p class="notice" role="alert">{error}</p>
      {/if}

      {#if check.clean && check.errors.length === 0}
        <p class="clean">
          puddle found nothing unsaved: no uncommitted changes, unpushed commits
          or stashes.
        </p>
      {:else}
        <section aria-labelledby="loss-heading">
          <h3 id="loss-heading">You would lose</h3>
          {#if lines.length === 0}
            <p class="clean">
              Nothing was found, but not everything could be checked.
            </p>
          {/if}
          <ul class="losses">
            {#each lines as line (line.where + line.what)}
              <li>
                <b>{line.what}</b> in <span class="mono">{line.where}</span>
                <ul>
                  {#each line.items as item, i (i)}
                    <li class="mono">{item}</li>
                  {/each}
                  {#if line.more > 0}
                    <li class="muted">and {line.more} more</li>
                  {/if}
                </ul>
              </li>
            {/each}
          </ul>
          {#if check.errors.length > 0}
            <div class="notice">
              <b>puddle couldn't check everything:</b>
              <ul>
                {#each check.errors as message, i (i)}
                  <li>{message}</li>
                {/each}
              </ul>
            </div>
          {/if}
        </section>
      {/if}

      <label class="confirm-check">
        <input type="checkbox" bind:checked={understood} />
        <span>
          {check.clean && check.errors.length === 0
            ? `Delete ${name} and its disk`
            : `I understand this work will be lost: delete ${name}`}
        </span>
      </label>

      <div class="confirm-actions">
        <AlertDialog.Cancel class="btn" bind:ref={cancelButton}
          >Cancel</AlertDialog.Cancel
        >
        <button
          type="button"
          class="btn deny"
          disabled={!understood || working}
          onclick={onConfirm}
        >
          {working ? "Deleting…" : "Delete workspace"}
        </button>
      </div>
    </AlertDialog.Content>
  </AlertDialog.Portal>
</AlertDialog.Root>

<style>
  :global(.delete-dialog h3) {
    margin: 0 0 var(--space-1);
    font-size: var(--text-md);
  }
  :global(.delete-dialog ul) {
    margin: 0;
    padding-inline-start: var(--space-4);
    overflow-wrap: anywhere;
  }
  :global(.delete-dialog .losses) {
    display: grid;
    gap: var(--space-2);
    max-height: 40vh;
    overflow-y: auto;
  }
  :global(.delete-dialog .clean),
  :global(.delete-dialog .muted) {
    margin: 0;
    color: var(--color-text-muted);
  }
  :global(.delete-dialog .notice) {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-md);
  }
  :global(.delete-dialog .confirm-check) {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    font-weight: 600;
  }
  :global(.delete-dialog .confirm-actions) {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
  .btn:disabled {
    cursor: default;
    opacity: 0.6;
  }
</style>
