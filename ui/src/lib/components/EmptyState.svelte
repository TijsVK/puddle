<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, children }: { title: string; children?: Snippet } = $props();
</script>

<section class="empty">
  <h1>{title}</h1>
  <p>
    {#if children}{@render children()}{:else}Nothing here yet.{/if}
  </p>
</section>

<style>
  .empty {
    max-width: 40rem;
  }
  h1 {
    font-size: var(--text-xl);
    margin-bottom: var(--space-2);
  }
  p {
    margin: 0;
    color: var(--color-text-muted);
  }
</style>
