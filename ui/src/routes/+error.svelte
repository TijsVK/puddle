<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { page } from "$app/state";
  import EmptyState from "#lib/components/EmptyState.svelte";
</script>

<EmptyState
  title={page.status === 404 ? "Page not found" : "Something went wrong"}
>
  {#if page.status === 404}
    There is nothing at this address. Use the menu to go to a section.
  {:else}
    {page.error?.message ?? "Unknown error."}
  {/if}
</EmptyState>
