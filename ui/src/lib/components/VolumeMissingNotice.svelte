<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  let { name, detail = false }: { name: string; detail?: boolean } = $props();
</script>

<p class="notice" role="status">
  <b>Its disk is gone, so it can't start.</b>
  {#if detail}
    Restore the volume <span class="mono">ws-{name}</span> and start it again, or
    delete the workspace below; nothing is lost by deleting it.
  {:else}
    Restore the volume <span class="mono">ws-{name}</span> and start it again, or
    open Details to delete it.
  {/if}
</p>

<style>
  .notice {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-md);
    overflow-wrap: anywhere;
  }
</style>
