<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { AlertDialog } from "bits-ui";
  import "#lib/theme/controls.css";

  let cancelButton = $state<HTMLElement | null>(null);

  let {
    open = $bindable(false),
    title,
    summary,
    detail,
    confirmLabel,
    tone = "allow",
    onConfirm,
    onCancel,
  }: {
    open?: boolean;
    title: string;
    /** The one-line statement of what will happen. */
    summary: string;
    detail?: string;
    confirmLabel: string;
    tone?: "allow" | "deny";
    onConfirm: () => void;
    onCancel?: () => void;
  } = $props();
</script>

<AlertDialog.Root
  bind:open
  onOpenChange={(next) => {
    if (!next) onCancel?.();
  }}
>
  <AlertDialog.Portal>
    <AlertDialog.Overlay class="confirm-overlay" />
    <AlertDialog.Content
      class="confirm-content"
      onOpenAutoFocus={(event) => {
        // The safe choice first: Enter right after opening cancels instead of widening a rule.
        event.preventDefault();
        cancelButton?.focus();
      }}
    >
      <AlertDialog.Title class="confirm-title">{title}</AlertDialog.Title>
      <AlertDialog.Description class="confirm-body">
        <strong class="confirm-summary">{summary}</strong>
        {#if detail}<span class="confirm-detail">{detail}</span>{/if}
      </AlertDialog.Description>
      <div class="confirm-actions">
        <AlertDialog.Cancel class="btn" bind:ref={cancelButton}
          >Cancel</AlertDialog.Cancel
        >
        <AlertDialog.Action
          class="btn {tone}"
          onclick={() => {
            // Action does not close the dialog by itself, unlike Cancel.
            open = false;
            onConfirm();
          }}>{confirmLabel}</AlertDialog.Action
        >
      </div>
    </AlertDialog.Content>
  </AlertDialog.Portal>
</AlertDialog.Root>

<style>
  :global(.confirm-body) {
    display: grid;
    gap: var(--space-2);
    margin: 0;
  }
  :global(.confirm-summary) {
    overflow-wrap: anywhere;
  }
  :global(.confirm-actions) {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
