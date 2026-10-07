<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import Bell from "@lucide/svelte/icons/bell";
  import "#lib/theme/controls.css";

  let {
    count,
    latest,
  }: {
    count: number;
    /** The newest waiting request, to say what is asking. */
    latest?: { workspace: string; host: string; port: number } | undefined;
  } = $props();
</script>

{#if count > 0}
  <div class="strip" role="status">
    <Bell aria-hidden="true" size={18} />
    <p>
      <b>{count} {count === 1 ? "request" : "requests"} waiting.</b>
      {#if latest}
        Latest: <span class="mono">{latest.workspace}</span> wants
        <span class="mono">{latest.host}:{latest.port}</span>.
      {/if}
    </p>
    <a class="btn primary" href="/inbox">Review</a>
  </div>
{/if}

<style>
  .strip {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-md);
  }
  p {
    flex: 1;
    min-width: 0;
    margin: 0;
    overflow-wrap: anywhere;
  }
  .btn.primary {
    color: var(--color-accent-contrast);
  }
</style>
