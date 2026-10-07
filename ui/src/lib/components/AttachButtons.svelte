<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import Code from "@lucide/svelte/icons/code";
  import Globe from "@lucide/svelte/icons/globe";
  import Play from "@lucide/svelte/icons/play";
  import Square from "@lucide/svelte/icons/square";
  import {
    canAttach,
    canStart,
    canStop,
    isDown,
    type Workspace,
  } from "#lib/workspaces/model.ts";
  import "#lib/theme/controls.css";

  let {
    workspace,
    onStart,
    onStop,
    onAttach,
  }: {
    workspace: Workspace;
    onStart: (w: Workspace) => void;
    onStop: (w: Workspace) => void;
    /** Open it in desktop VS Code: one click (the first-connect notice, once, is the caller's). */
    onAttach: (w: Workspace) => void;
  } = $props();

  const down = $derived(isDown(workspace.status));
  const hint = $derived(`browser-hint-${workspace.id}`);
</script>

{#if down}
  <button
    type="button"
    class="btn primary"
    disabled={!canStart(workspace)}
    onclick={() => onStart(workspace)}
  >
    <Play aria-hidden="true" size={16} />Start
    <span class="visually-hidden">{workspace.name}</span>
  </button>
{:else}
  <button
    type="button"
    class="btn primary"
    disabled={!canAttach(workspace)}
    onclick={() => onAttach(workspace)}
  >
    <Code aria-hidden="true" size={16} />Open in VS Code
    <span class="visually-hidden"> ({workspace.name})</span>
  </button>
  <button
    type="button"
    class="btn"
    disabled
    aria-describedby={hint}
    title="Browser VS Code is not available yet"
  >
    <Globe aria-hidden="true" size={16} />Browser
    <span class="visually-hidden"> ({workspace.name})</span>
  </button>
  <span id={hint} class="visually-hidden"
    >Browser VS Code is not available yet.</span
  >
  <button
    type="button"
    class="btn"
    disabled={!canStop(workspace)}
    onclick={() => onStop(workspace)}
  >
    <Square aria-hidden="true" size={16} />Stop
    <span class="visually-hidden">{workspace.name}</span>
  </button>
{/if}

<style>
  .btn:disabled {
    cursor: default;
    opacity: 0.6;
  }
</style>
