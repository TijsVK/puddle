<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { Dialog } from "bits-ui";
  import "#lib/theme/controls.css";

  // A modal with a title and a form. Esc and the Cancel button close it; focus goes to the first
  // field (or the element named by `initialFocus`) and returns to where it came from.
  let {
    open = $bindable(false),
    title,
    description,
    children,
    onClose,
    returnFocusTo,
  }: {
    open?: boolean;
    title: string;
    description?: string;
    children: Snippet;
    onClose?: () => void;
    /** Where focus goes on close, when the dialog was not opened from a control that will take it back. */
    returnFocusTo?: () => HTMLElement | null | undefined;
  } = $props();
</script>

<Dialog.Root
  bind:open
  onOpenChange={(next) => {
    if (!next) onClose?.();
  }}
>
  <Dialog.Portal>
    <Dialog.Overlay class="confirm-overlay" />
    <Dialog.Content
      class="confirm-content form-dialog"
      onCloseAutoFocus={(event) => {
        const target = returnFocusTo?.();
        if (target) {
          event.preventDefault();
          target.focus();
        }
      }}
    >
      <Dialog.Title class="confirm-title">{title}</Dialog.Title>
      {#if description}
        <Dialog.Description class="confirm-detail"
          >{description}</Dialog.Description
        >
      {:else}
        <Dialog.Description class="visually-hidden">{title}</Dialog.Description>
      {/if}
      {@render children()}
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>

<style>
  :global(.form-dialog form) {
    display: grid;
    gap: var(--space-4);
  }
  :global(.form-dialog fieldset) {
    display: grid;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    border: 0;
  }
  :global(.form-dialog legend) {
    padding: 0;
    margin-bottom: var(--space-1);
    font-weight: 600;
  }
  :global(.form-dialog .field) {
    display: grid;
    gap: var(--space-1);
  }
  :global(.form-dialog .field > label),
  :global(.form-dialog .choice) {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  :global(.form-dialog .field > label) {
    font-weight: 600;
  }
  :global(.form-dialog input[type="text"]),
  :global(.form-dialog select) {
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  :global(.form-dialog input[aria-invalid="true"]) {
    border-color: var(--color-danger);
  }
  :global(.form-dialog .hint) {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  :global(.form-dialog .error) {
    margin: 0;
    color: var(--color-danger);
    font-size: var(--text-sm);
  }
  :global(.form-dialog .actions) {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
