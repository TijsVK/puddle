<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import Plus from "@lucide/svelte/icons/plus";
  import PendingStrip from "#lib/components/PendingStrip.svelte";
  import WorkspaceCard from "#lib/components/WorkspaceCard.svelte";
  import { pending } from "#lib/stores/pending.svelte.ts";
  import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import "#lib/theme/controls.css";

  let now = $state(Date.now());

  onMount(() => {
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => clearInterval(clock);
  });

  const waitingBy = $derived.by(() => {
    const counts: Record<string, number> = {};
    for (const row of pending.rows)
      counts[row.request.workspace] = (counts[row.request.workspace] ?? 0) + 1;
    return counts;
  });
  const latest = $derived.by(() => {
    const newest = [...pending.rows].sort(
      (a, b) => b.request.first_seen - a.request.first_seen,
    )[0]?.request;
    return newest
      ? { workspace: newest.workspace, host: newest.host, port: newest.port }
      : undefined;
  });
</script>

<PendingStrip count={pending.count} {latest} />

<div class="head">
  <div>
    <h1>Workspaces</h1>
    {#if workspaces.status === "ready"}
      <p class="sub">
        {workspaces.list.length}
        {workspaces.list.length === 1 ? "workspace" : "workspaces"}
      </p>
    {/if}
  </div>
  <button type="button" class="btn primary" onclick={actions.openCreate}>
    <Plus aria-hidden="true" size={16} />New workspace
  </button>
</div>

{#if workspaces.status === "loading"}
  <p class="muted">Loading workspaces&hellip;</p>
{:else if workspaces.status === "failed"}
  <p class="muted">Couldn't read the workspaces yet. Trying again.</p>
{:else if workspaces.list.length === 0}
  <section class="empty">
    <h2>No workspaces yet</h2>
    <p>
      A workspace is an isolated copy of a repository where you and your tools
      work. Create one to get started.
    </p>
    <button type="button" class="btn primary" onclick={actions.openCreate}>
      <Plus aria-hidden="true" size={16} />New workspace
    </button>
  </section>
{:else}
  <ul class="grid" aria-label="Workspaces">
    {#each workspaces.list as workspace (workspace.id)}
      <li>
        <WorkspaceCard
          {workspace}
          {now}
          waiting={waitingBy[workspace.name] ?? 0}
          progress={workspaces.progress[workspace.name]}
          oom={workspaces.oom[workspace.name]}
          onStart={actions.start}
          onStop={actions.stop}
          onConnect={actions.connect}
          onDismiss={actions.dismissProgress}
        />
      </li>
    {/each}
  </ul>
{/if}

<style>
  .head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }
  h1 {
    font-size: var(--text-xl);
  }
  .sub,
  .muted {
    margin: 0;
    color: var(--color-text-muted);
  }
  .empty {
    display: grid;
    gap: var(--space-3);
    justify-items: start;
    max-width: 40rem;
    padding: var(--space-6);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .empty h2,
  .empty p {
    margin: 0;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(22rem, 1fr));
    gap: var(--space-4);
    list-style: none;
    margin: 0;
    padding: 0;
  }
</style>
