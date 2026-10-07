<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import type { Progress } from "#lib/stores/workspaces.svelte.ts";
  import {
    operationLabel,
    stepLabel,
    stepPosition,
    type Operation,
  } from "#lib/workspaces/model.ts";

  let {
    busy,
    progress,
    onDismiss,
  }: {
    /** What the record says is running, if anything. */
    busy: Operation | null;
    /** What the stream last said. */
    progress: Progress | undefined;
    onDismiss?: () => void;
  } = $props();

  const operation = $derived(busy ?? progress?.operation ?? null);
  const position = $derived(
    operation && progress && !progress.failed
      ? stepPosition(operation, progress.step)
      : null,
  );
</script>

{#if progress?.failed}
  <div class="line failed" role="alert">
    <TriangleAlert aria-hidden="true" size={16} />
    <span class="text">
      <b>{operation ? `${operationLabel(operation)} failed` : "That failed"}.</b
      >
      {#if progress.detail}<span class="detail">{progress.detail}</span>{/if}
    </span>
    {#if onDismiss}
      <button type="button" class="btn" onclick={onDismiss}>Dismiss</button>
    {/if}
  </div>
{:else if busy || progress}
  <p class="line" role="status">
    <LoaderCircle class="spin" aria-hidden="true" size={16} />
    <span class="text">
      <b
        >{progress
          ? stepLabel(progress.step)
          : busy
            ? operationLabel(busy)
            : ""}</b
      >
      {#if position}<span class="muted"
          >step {position.index} of {position.of}</span
        >{/if}
      {#if progress?.detail}<span class="detail">{progress.detail}</span>{/if}
    </span>
  </p>
{/if}

<style>
  .line {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    margin: 0;
    font-size: var(--text-sm);
  }
  .text {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .detail {
    display: block;
    font-family: var(--font-mono);
    color: var(--color-text-muted);
  }
  .failed {
    color: var(--color-danger);
  }
  .failed .detail {
    color: inherit;
  }
  :global(.spin) {
    flex: none;
    margin-top: 0.15rem;
    animation: spin 1.2s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
