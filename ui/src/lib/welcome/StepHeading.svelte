<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";

  // The heading of a step. A step is a page of its own, so focus goes to it when the step opens:
  // a screen reader starts reading at the new step, a keyboard user starts above its controls.
  let { title, lead }: { title: string; lead?: string } = $props();

  let heading: HTMLHeadingElement;
  onMount(() => heading.focus());
</script>

<h1 tabindex="-1" bind:this={heading}>{title}</h1>
{#if lead}<p class="lead">{lead}</p>{/if}

<style>
  h1 {
    margin: 0;
    font-size: var(--text-xl);
  }
  h1:focus {
    outline: none;
  }
  .lead {
    margin: var(--space-2) 0 0;
    color: var(--color-text-muted);
  }
</style>
