<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import Trash2 from "@lucide/svelte/icons/trash-2";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import { page } from "$app/state";
  import StatusChip from "#lib/components/StatusChip.svelte";
  import { api } from "#lib/api/client.ts";
  import { absoluteTime, relativeTime } from "#lib/format/relative-time.ts";
  import { isExpired, workspaceOf } from "#lib/rules/model.ts";
  import { pending } from "#lib/stores/pending.svelte.ts";
  import { rulesStore } from "#lib/stores/rules.svelte.ts";
  import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import {
    canDelete,
    canReclaim,
    diskLabel,
    formatMib,
  } from "#lib/workspaces/model.ts";
  import { tabHref } from "#lib/workspaces/tabs.ts";
  import "#lib/theme/controls.css";

  const id = $derived(page.params["id"] ?? "");
  const workspace = $derived(workspaces.list.find((w) => w.id === id));
  const oom = $derived(workspace ? workspaces.oom[workspace.name] : undefined);

  let now = $state(Date.now());
  let dismissedOom = $state<number | null>(null);
  let memorySource = $state<"sandbox" | "global" | "default" | null>(null);

  onMount(() => {
    const stopRules = rulesStore.start();
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => {
      stopRules();
      clearInterval(clock);
    };
  });

  // Where the memory figure comes from, so "workspace override" and "global default" say true.
  const name = $derived(workspace?.name);
  const memoryMib = $derived(workspace?.memory_mib);
  $effect(() => {
    if (!name) return;
    void memoryMib; // read again when the figure changes
    void (async () => {
      try {
        const { data } = await api.GET("/api/settings/sandboxes/{sandbox}", {
          params: { path: { sandbox: name } },
        });
        memorySource = data?.effective.memory.source ?? null;
      } catch {
        memorySource = null;
      }
    })();
  });

  const waiting = $derived(
    pending.rows.filter((r) => r.request.sandbox === workspace?.name).length,
  );
  const ruleCounts = $derived.by(() => {
    const active = rulesStore.rules.filter((r) => !isExpired(r, now));
    return {
      workspace: active.filter((r) => workspaceOf(r) === workspace?.name)
        .length,
      global: active.filter((r) => workspaceOf(r) === null).length,
    };
  });
  const plural = (n: number, one: string, many: string) =>
    `${n} ${n === 1 ? one : many}`;
  const networkSummary = $derived(
    [
      `${waiting} waiting`,
      plural(ruleCounts.workspace, "workspace rule", "workspace rules"),
      plural(
        ruleCounts.global,
        "rule for every workspace",
        "rules for every workspace",
      ),
    ].join(" · "),
  );
</script>

{#if workspace}
  {#if oom && dismissedOom !== oom.at}
    <div class="warn" role="alert">
      <TriangleAlert aria-hidden="true" size={20} />
      <p>
        <b>Out of memory:</b> the workspace's kernel stopped
        <span class="mono">{oom.process}</span> (process {oom.pid})
        {relativeTime(oom.at, now)} because the workspace ran out of memory. The workspace
        itself is still running.
      </p>
      <a class="btn" href={tabHref(workspace.id, "settings")}>Change memory</a>
      <button
        type="button"
        class="btn"
        onclick={() => {
          dismissedOom = oom.at;
        }}>Dismiss</button
      >
    </div>
  {/if}

  <div class="grid">
    <section class="card" aria-labelledby="status-h">
      <h2 id="status-h">Status</h2>
      <dl>
        <dt>State</dt>
        <dd><StatusChip status={workspace.status} busy={workspace.busy} /></dd>
        <dt>Created</dt>
        <dd>
          <time
            datetime={new Date(workspace.created_at).toISOString()}
            title={absoluteTime(workspace.created_at)}
            >{relativeTime(workspace.created_at, now)}</time
          >
        </dd>
        <dt>Image</dt>
        <dd class="mono">{workspace.image}</dd>
        <dt>Repository</dt>
        <dd class="mono">{workspace.repo_url}</dd>
      </dl>
    </section>

    <section class="card" aria-labelledby="resources-h">
      <h2 id="resources-h">Resources</h2>
      <dl>
        <dt>Memory</dt>
        <dd>
          {formatMib(workspace.memory_mib)}
          {#if memorySource}
            <span class="chip"
              >{memorySource === "sandbox"
                ? "workspace override"
                : memorySource === "global"
                  ? "global default"
                  : "puddle's default"}</span
            >
          {/if}
        </dd>
        <dt>Disk</dt>
        <dd>{diskLabel(workspace)}</dd>
        <dt>Volume</dt>
        <dd class="mono">ws-{workspace.name}</dd>
      </dl>
      <p class="hint">
        Reclaiming space gives disk the workspace no longer uses back to your
        computer.
      </p>
      <div class="row">
        <button
          type="button"
          class="btn"
          disabled={!canReclaim(workspace)}
          onclick={() => void actions.reclaim(workspace)}>Reclaim space</button
        >
      </div>
    </section>

    <section class="card" aria-labelledby="network-h">
      <h2 id="network-h">Network</h2>
      <p>{networkSummary}</p>
      <p><a href={tabHref(workspace.id, "network")}>Open the network tab</a></p>
    </section>

    <section class="card danger" aria-labelledby="danger-h">
      <h2 id="danger-h">Delete workspace</h2>
      <p class="hint">
        Deleting removes the workspace and its disk. puddle first lists
        uncommitted changes, unpushed commits and stashes.
      </p>
      {#if !canDelete(workspace) && workspace.busy === null}
        <p class="hint">Stop the workspace before deleting it.</p>
      {/if}
      <div class="row">
        <button
          type="button"
          class="btn deny"
          disabled={!canDelete(workspace)}
          onclick={() => void actions.askDelete(workspace)}
        >
          <Trash2 aria-hidden="true" size={16} />{actions.checking ===
          workspace.name
            ? "Checking…"
            : "Delete workspace…"}
        </button>
      </div>
    </section>
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(24rem, 1fr));
    gap: var(--space-4);
    align-items: start;
  }
  .card {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .card.danger {
    border-color: var(--color-danger);
  }
  h2 {
    font-size: var(--text-md);
  }
  p {
    margin: 0;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
  }
  dt {
    color: var(--color-text-muted);
  }
  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .hint {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  .row {
    display: flex;
    gap: var(--space-2);
  }
  .chip {
    margin-inline-start: var(--space-2);
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    white-space: nowrap;
  }
  .warn {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-md);
    background: var(--color-surface-raised);
  }
  .warn p {
    flex: 1;
    min-width: 12rem;
    overflow-wrap: anywhere;
  }
  .btn:disabled {
    cursor: default;
    opacity: 0.6;
  }
</style>
