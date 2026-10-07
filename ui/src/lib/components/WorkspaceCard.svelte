<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import AttachButtons from "./AttachButtons.svelte";
  import ProgressLine from "./ProgressLine.svelte";
  import StatusChip from "./StatusChip.svelte";
  import { relativeTime } from "#lib/format/relative-time.ts";
  import type { OomEvent, Progress } from "#lib/stores/workspaces.svelte.ts";
  import {
    diskLabel,
    formatMib,
    type Workspace,
  } from "#lib/workspaces/model.ts";
  import "#lib/theme/controls.css";

  let {
    workspace,
    now,
    waiting = 0,
    progress,
    oom,
    onStart,
    onStop,
    onAttach,
    onDismiss,
  }: {
    workspace: Workspace;
    now: number;
    /** Requests from this workspace waiting for a decision. */
    waiting?: number;
    progress?: Progress | undefined;
    oom?: OomEvent | undefined;
    onStart: (w: Workspace) => void;
    onStop: (w: Workspace) => void;
    onAttach: (w: Workspace) => void;
    onDismiss: (w: Workspace) => void;
  } = $props();

  const titleId = $derived(`ws-${workspace.name}`);
</script>

<article class="card" aria-labelledby={titleId}>
  <header>
    <div class="who">
      <h2 id={titleId}>
        <a href="/workspaces/{encodeURIComponent(workspace.id)}"
          >{workspace.name}</a
        >
      </h2>
      <p class="repo">{workspace.repo_url}</p>
    </div>
    <StatusChip status={workspace.status} busy={workspace.busy} />
  </header>
  <p class="meta">
    <span>{formatMib(workspace.memory_mib)} memory</span>
    <span>{diskLabel(workspace)}</span>
    <span>
      Created
      <time datetime={new Date(workspace.created_at).toISOString()}
        >{relativeTime(workspace.created_at, now)}</time
      >
    </span>
    {#if waiting > 0}
      <a
        class="flag"
        href="/workspaces/{encodeURIComponent(workspace.id)}/network"
        >{waiting} waiting</a
      >
    {/if}
    {#if oom}
      <span class="flag warn">Out of memory {relativeTime(oom.at, now)}</span>
    {/if}
  </p>
  <ProgressLine
    busy={workspace.busy}
    {progress}
    onDismiss={() => onDismiss(workspace)}
  />
  <div class="acts">
    <AttachButtons {workspace} {onStart} {onStop} {onAttach} />
    <a class="btn details" href="/workspaces/{encodeURIComponent(workspace.id)}"
      >Details <span class="visually-hidden">of {workspace.name}</span></a
    >
  </div>
</article>

<style>
  .card {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  header {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
  }
  .who {
    flex: 1;
    min-width: 0;
  }
  h2 {
    font-size: var(--text-lg);
    overflow-wrap: anywhere;
  }
  h2 a {
    color: var(--color-text);
  }
  .repo {
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    overflow-wrap: anywhere;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1) var(--space-4);
    margin: 0;
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .flag {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    color: var(--color-text);
  }
  .flag.warn {
    border-color: var(--color-warning);
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .details {
    margin-inline-start: auto;
  }
</style>
