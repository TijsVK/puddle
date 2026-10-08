<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  /** Fields in a stored settings document that this puddle doesn't know (dotted paths). */
  let { fields }: { fields: readonly string[] } = $props();
</script>

{#if fields.length > 0}
  <p class="unknown" role="status">
    The stored settings contain fields this puddle doesn't know:
    <span class="mono">{fields.join(", ")}</span>. They are kept but have no
    effect. A misspelt name is the usual cause; a newer puddle may have written
    them.
  </p>
{/if}

<style>
  .unknown {
    margin: 0 0 var(--space-3);
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-subtle);
    border-inline-start: 3px solid var(--color-accent);
    background: var(--color-surface-raised);
  }
</style>
