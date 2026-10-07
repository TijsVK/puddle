<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import DecisionFlow from "#lib/components/DecisionFlow.svelte";
  import RequestRow from "#lib/components/RequestRow.svelte";
  import RuleTable from "#lib/components/RuleTable.svelte";
  import WorkspaceSets from "#lib/components/WorkspaceSets.svelte";
  import { DEFAULT_SORT, isOwn, view, workspaceOf } from "#lib/rules/model.ts";
  import { pending } from "#lib/stores/pending.svelte.ts";
  import { ruleSets } from "#lib/stores/rule-sets.svelte.ts";
  import { rulesStore } from "#lib/stores/rules.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import { NO_FILTER } from "#lib/rules/model.ts";
  import "#lib/theme/controls.css";

  const id = $derived(page.params["id"] ?? "");
  const workspace = $derived(workspaces.list.find((w) => w.id === id));
  let now = $state(Date.now());
  let currentId = $state<number | null>(null);
  let heading = $state<HTMLElement>();
  let flow = $state<ReturnType<typeof DecisionFlow>>();

  onMount(() => {
    const stopRules = rulesStore.start();
    const stopSets = ruleSets.start();
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => {
      stopRules();
      stopSets();
      clearInterval(clock);
    };
  });

  const rows = $derived(
    pending.rows
      .filter((r) => r.request.sandbox === workspace?.name)
      .sort(
        (a, b) =>
          b.request.first_seen - a.request.first_seen ||
          b.request.id - a.request.id,
      ),
  );
  const rules = $derived(
    view(
      rulesStore.rules.filter((r) => {
        if (!isOwn(r)) return false;
        const owner = workspaceOf(r);
        return owner === null || owner === workspace?.name;
      }),
      NO_FILTER,
      DEFAULT_SORT,
      now,
    ),
  );
</script>

{#if workspace}
  <section class="block" aria-labelledby="waiting-h">
    <h2 id="waiting-h" tabindex="-1" bind:this={heading}>
      Waiting
      {#if rows.length > 0}<span class="count">{rows.length}</span>{/if}
    </h2>
    {#if pending.status === "loading"}
      <p class="muted pad">Loading requests&hellip;</p>
    {:else if rows.length === 0}
      <p class="muted pad">Nothing is waiting for {workspace.name}.</p>
    {:else}
      <ul>
        {#each rows as row (row.request.id)}
          <RequestRow
            {row}
            {now}
            current={row.request.id === currentId}
            blockedBy={pending.blockedBy(row.request)}
            optionsOpen={flow?.optionsOpenFor(row.request.id) ?? false}
            onMore={(r, anchor) => flow?.more(r, anchor)}
            onDecide={(r, choice) => flow?.decide(r, choice)}
            onFocusRow={(r) => {
              currentId = r.request.id;
            }}
          />
        {/each}
      </ul>
    {/if}
  </section>

  <section class="block" aria-labelledby="rules-h">
    <div class="head">
      <h2 id="rules-h">Rules that apply</h2>
      <a class="btn" href="/rules">All rules</a>
    </div>
    {#if rulesStore.status === "loading"}
      <p class="muted pad">Loading rules&hellip;</p>
    {:else if rules.length === 0}
      <p class="muted pad">
        No rule applies to {workspace.name} yet. Requests wait here until you decide.
      </p>
    {:else}
      <RuleTable {rules} sort={DEFAULT_SORT} {now} />
      <p class="muted note">
        Change or delete a rule on the <a href="/rules">Rules page</a>.
      </p>
    {/if}
  </section>

  <WorkspaceSets workspace={workspace.name} />

  <DecisionFlow bind:this={flow} heading={() => heading} />
{/if}

<style>
  .block {
    margin-bottom: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  h2 {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    font-size: var(--text-md);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  h2:focus {
    outline: none;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-inline-end: var(--space-4);
  }
  .head h2 {
    flex: 1;
    border-bottom: 0;
  }
  .count {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .muted {
    margin: 0;
    color: var(--color-text-muted);
  }
  .pad {
    padding: var(--space-4);
  }
  .note {
    padding: var(--space-2) var(--space-4) var(--space-3);
    font-size: var(--text-sm);
  }
</style>
