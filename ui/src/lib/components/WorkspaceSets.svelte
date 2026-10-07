<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    overrides,
    stateFor,
    systemFor,
    type RuleSet,
  } from "#lib/rules/sets.ts";
  import {
    ruleSets as defaultStore,
    type RuleSetsStore,
  } from "#lib/stores/rule-sets.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import SystemManagedList from "./SystemManagedList.svelte";
  import "#lib/theme/controls.css";

  // The rule sets as one workspace sees them, with a switch of its own for each, and the System
  // managed hosts that apply to it.
  let {
    store = defaultStore,
    workspace,
  }: { store?: RuleSetsStore; workspace: string } = $props();

  const id = $props.id();
  const hosts = $derived(systemFor(store.system, workspace));

  async function set(ruleSet: RuleSet, enabled: boolean | null) {
    const result = await store.switchSet(ruleSet.id, workspace, enabled);
    if (!result.ok) {
      toasts.push(result.message, { tone: "error", ms: 8000 });
      return;
    }
    const closed =
      result.value > 0
        ? `; it decided ${result.value} waiting ${result.value === 1 ? "request" : "requests"}`
        : "";
    toasts.push(
      `${ruleSet.name}: ${enabled === null ? "follows every workspace" : enabled ? "on" : "off"} in ${workspace}${closed}.`,
    );
  }
</script>

<section class="block" aria-labelledby="{id}-h">
  <div class="head">
    <h2 id="{id}-h">Rule sets</h2>
    <a class="btn" href="/rules">All rule sets</a>
  </div>
  {#if store.status === "loading"}
    <p class="muted pad">Loading rule sets&hellip;</p>
  {:else}
    <ul>
      {#each store.sets as ruleSet (ruleSet.id)}
        <li>
          <span class="name">{ruleSet.name}</span>
          <span class="muted">{stateFor(ruleSet, workspace)}</span>
          <span class="actions">
            <button
              type="button"
              class="btn"
              aria-label="Turn {ruleSet.name} on in {workspace}"
              onclick={() => void set(ruleSet, true)}>On here</button
            >
            <button
              type="button"
              class="btn"
              aria-label="Turn {ruleSet.name} off in {workspace}"
              onclick={() => void set(ruleSet, false)}>Off here</button
            >
            {#if overrides(ruleSet, workspace)}
              <button
                type="button"
                class="btn"
                aria-label="Make {ruleSet.name} in {workspace} follow every workspace"
                onclick={() => void set(ruleSet, null)}
                >Follow every workspace</button
              >
            {/if}
          </span>
        </li>
      {/each}
    </ul>
  {/if}
</section>
<SystemManagedList {hosts} />

<style>
  .block {
    margin-bottom: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3) var(--space-4);
  }
  h2 {
    margin: 0;
    font-size: var(--text-md);
  }
  ul {
    margin: 0;
    padding: 0 var(--space-4) var(--space-3);
    list-style: none;
    display: grid;
    gap: var(--space-2);
  }
  li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .name {
    font-weight: 600;
    min-width: 12rem;
  }
  .actions {
    display: inline-flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin-left: auto;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .pad {
    padding: 0 var(--space-4) var(--space-3);
    margin: 0;
  }
</style>
