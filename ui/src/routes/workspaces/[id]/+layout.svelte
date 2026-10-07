<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import AttachButtons from "#lib/components/AttachButtons.svelte";
  import ProgressLine from "#lib/components/ProgressLine.svelte";
  import StatusChip from "#lib/components/StatusChip.svelte";
  import { pending } from "#lib/stores/pending.svelte.ts";
  import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import { activeTab, TABS, tabHref } from "#lib/workspaces/tabs.ts";

  let { children } = $props();

  const id = $derived(page.params["id"] ?? "");
  const workspace = $derived(workspaces.list.find((w) => w.id === id));
  const current = $derived(activeTab(page.url.pathname, id));
  const waiting = $derived(
    pending.rows.filter((r) => r.request.sandbox === workspace?.name).length,
  );

  // A workspace that was here and is gone (deleted, here or elsewhere) takes you back to the list.
  let seen = false;
  $effect(() => {
    if (workspace) seen = true;
    else if (seen && workspaces.status === "ready") void goto("/workspaces");
  });
</script>

{#if workspace}
  <div class="head">
    <div class="title">
      <p class="crumb"><a href="/workspaces">Workspaces</a> /</p>
      <h1>{workspace.name}</h1>
    </div>
    <StatusChip status={workspace.status} busy={workspace.busy} />
    <div class="acts">
      <AttachButtons
        {workspace}
        onStart={actions.start}
        onStop={actions.stop}
        onAttach={actions.attach}
      />
    </div>
  </div>
  <ProgressLine
    busy={workspace.busy}
    progress={workspaces.progress[workspace.name]}
    onDismiss={() => actions.dismissProgress(workspace)}
  />
  <nav class="tabs" aria-label="Workspace sections">
    {#each TABS as tab (tab.slug)}
      <a
        href={tabHref(workspace.id, tab.slug)}
        aria-current={current === tab.slug ? "page" : undefined}
      >
        {tab.label}
        {#if tab.slug === "network" && waiting > 0}
          <span class="badge">
            <span aria-hidden="true">{waiting}</span>
            <span class="visually-hidden">{waiting} waiting</span>
          </span>
        {/if}
      </a>
    {/each}
  </nav>
  {@render children()}
{:else if workspaces.status === "ready"}
  <h1>No such workspace</h1>
  <p class="muted">
    There is no workspace called <span class="mono">{id}</span>.
    <a href="/workspaces">Back to the workspaces</a>.
  </p>
{:else if workspaces.status === "failed"}
  <p class="muted">Couldn't read the workspace yet. Trying again.</p>
{:else}
  <p class="muted">Loading workspace&hellip;</p>
{/if}

<style>
  .head {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }
  .title {
    min-width: 0;
  }
  .crumb {
    margin: 0;
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  h1 {
    font-size: var(--text-xl);
    overflow-wrap: anywhere;
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin-inline-start: auto;
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: var(--space-4) 0;
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .tabs a {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-bottom: 3px solid transparent;
    color: var(--color-text);
    text-decoration: none;
  }
  .tabs a:hover {
    background: var(--color-surface-raised);
  }
  .tabs a[aria-current="page"] {
    border-bottom-color: var(--color-accent);
    font-weight: 600;
  }
  .badge {
    min-width: 1.5rem;
    padding: 0 var(--space-2);
    border-radius: var(--radius-pill);
    background: var(--color-accent);
    color: var(--color-accent-contrast);
    font-size: var(--text-sm);
    text-align: center;
  }
  .muted {
    color: var(--color-text-muted);
  }
</style>
