<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    toasts as defaultToasts,
    type ToastQueue,
  } from "#lib/stores/toasts.svelte.ts";
  import "#lib/theme/controls.css";

  let { queue = defaultToasts }: { queue?: ToastQueue } = $props();
</script>

<div class="toasts" role="region" aria-label="Notifications">
  <div aria-live="polite" role="status" class="toast-list">
    {#each queue.items as toast (toast.id)}
      <div
        class="toast"
        class:error={toast.tone === "error"}
        role="presentation"
        onmouseenter={() => queue.hold(toast.id)}
        onmouseleave={() => queue.resume(toast.id)}
        onfocusin={() => queue.hold(toast.id)}
        onfocusout={() => queue.resume(toast.id)}
      >
        <span class="message">{toast.message}</span>
        {#if toast.action}
          <button
            type="button"
            class="btn"
            onclick={() => void queue.act(toast.id)}
            >{toast.action.label}</button
          >
        {/if}
        <button
          type="button"
          class="btn close"
          aria-label="Dismiss"
          onclick={() => queue.dismiss(toast.id)}>&times;</button
        >
      </div>
    {/each}
  </div>
</div>

<style>
  .toasts {
    position: fixed;
    inset-inline: var(--space-4);
    bottom: var(--space-4);
    z-index: 40;
    display: flex;
    justify-content: center;
    pointer-events: none;
  }
  .toast-list {
    display: grid;
    gap: var(--space-2);
    max-width: 40rem;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
  }
  .toast.error {
    border-color: var(--color-danger);
  }
  .message {
    overflow-wrap: anywhere;
  }
  .close {
    border-color: transparent;
    background: transparent;
  }
</style>
