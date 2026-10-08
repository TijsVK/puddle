<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { workspaceNameError } from "#lib/rules/model.ts";
  import {
    entryPattern,
    globalState,
    isOn,
    type RuleSet,
    type RuleSetEntry,
  } from "#lib/rules/sets.ts";
  import "#lib/theme/controls.css";

  // One rule set: what it is, its switch for every workspace and the workspaces that switch it
  // for themselves, and its entries. A set you made also has its own actions.
  let {
    set,
    workspaces,
    onSwitch,
    onAddEntry,
    onRename,
    onDelete,
    onDeleteEntry,
  }: {
    set: RuleSet;
    /** Workspace names to suggest for a per-workspace switch. */
    workspaces: string[];
    onSwitch: (
      set: RuleSet,
      workspace: string | null,
      enabled: boolean | null,
    ) => void;
    onAddEntry: (set: RuleSet) => void;
    onRename: (set: RuleSet) => void;
    onDelete: (set: RuleSet) => void;
    onDeleteEntry: (set: RuleSet, entry: RuleSetEntry) => void;
  } = $props();

  const id = $props.id();
  const everywhere = $derived(isOn(set, null));
  const mine = $derived(set.kind === "user");
  let workspace = $state("");
  let problem = $state<string | null>(null);

  function switchHere(enabled: boolean) {
    problem = workspaceNameError(workspace.trim());
    if (problem) return;
    onSwitch(set, workspace.trim(), enabled);
    workspace = "";
  }

  function changed(at: number): string {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
      at,
    );
  }
</script>

<article class="set" aria-labelledby="{id}-name" data-set-id={set.id}>
  <header>
    <h3 id="{id}-name">{set.name}</h3>
    <span class="chip">{mine ? "Yours" : "Built in"}</span>
    <span class="muted mono" title="The id refusals and the activity log use"
      >{set.id}</span
    >
    {#if set.changed_at !== null}
      <span class="chip warn">Updated by puddle {changed(set.changed_at)}</span>
    {/if}
  </header>
  {#if set.description !== ""}<p class="desc">{set.description}</p>{/if}

  <div class="row">
    <label class="switch">
      <input
        type="checkbox"
        role="switch"
        checked={everywhere}
        onchange={(e) => {
          const next = e.currentTarget.checked;
          e.currentTarget.checked = everywhere;
          onSwitch(set, null, next);
        }}
      />
      On for every workspace
    </label>
    <span class="muted">{globalState(set)}</span>
    {#if set.global !== null}
      <button
        type="button"
        class="btn"
        onclick={() => onSwitch(set, null, null)}
        >Back to the default ({set.default_on ? "on" : "off"})</button
      >
    {/if}
  </div>

  {#if set.overrides.length > 0}
    <ul class="overrides" aria-label="Workspaces that switch {set.name}">
      {#each set.overrides as o (o.workspace)}
        <li>
          <span><b>{o.enabled ? "On" : "Off"}</b> in <b>{o.workspace}</b></span>
          <button
            type="button"
            class="btn"
            onclick={() => onSwitch(set, o.workspace, null)}
            >Follow every workspace</button
          >
        </li>
      {/each}
    </ul>
  {/if}

  <form
    class="row"
    aria-label="Switch {set.name} for one workspace"
    onsubmit={(e) => e.preventDefault()}
    novalidate
  >
    <div class="field">
      <label for="{id}-ws">Workspace name</label>
      <input
        id="{id}-ws"
        type="text"
        list="{id}-wss"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        bind:value={workspace}
        aria-invalid={problem ? "true" : undefined}
        aria-describedby={problem ? `${id}-ws-error` : undefined}
      />
      <datalist id="{id}-wss">
        {#each workspaces as name (name)}<option value={name}></option>{/each}
      </datalist>
    </div>
    <button type="button" class="btn" onclick={() => switchHere(true)}
      >On there</button
    >
    <button type="button" class="btn" onclick={() => switchHere(false)}
      >Off there</button
    >
    {#if problem}
      <p class="error" id="{id}-ws-error" role="alert">{problem}</p>
    {/if}
  </form>

  <details>
    <summary
      >{set.entries.length}
      {set.entries.length === 1 ? "entry" : "entries"}</summary
    >
    {#if set.entries.length === 0}
      <p class="muted">
        No entries yet. Add one, or approve a request into this set from the
        Inbox.
      </p>
    {:else}
      <ul class="entries">
        {#each set.entries as entry (entry.rule_id ?? entry.pattern)}
          <li>
            <span class="chip {entry.effect}"
              >{entry.effect === "allow" ? "Allow" : "Deny"}</span
            >
            <span class="mono">{entryPattern(entry)}</span>
            {#if entry.note !== ""}<span class="muted">{entry.note}</span>{/if}
            {#if mine}
              <button
                type="button"
                class="btn"
                aria-label="Delete {entryPattern(entry)} from {set.name}"
                onclick={() => onDeleteEntry(set, entry)}>Delete</button
              >
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </details>

  {#if mine}
    <div class="row">
      <button type="button" class="btn" onclick={() => onAddEntry(set)}
        >Add entry</button
      >
      <button type="button" class="btn" onclick={() => onRename(set)}
        >Rename</button
      >
      <button type="button" class="btn deny" onclick={() => onDelete(set)}
        >Delete set</button
      >
    </div>
  {/if}
</article>

<style>
  .set {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  h3 {
    margin: 0;
    font-size: var(--text-md);
  }
  .desc,
  .muted {
    margin: 0;
    color: var(--color-text-muted);
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-2);
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: 1.75rem;
    font-weight: 600;
  }
  .field {
    display: grid;
    gap: var(--space-1);
  }
  .field label {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .field input {
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  .overrides,
  .entries {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .overrides li,
  .entries li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    min-height: 1.75rem;
  }
  .mono {
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
  .error {
    margin: 0;
    color: var(--color-danger);
  }
  summary {
    cursor: pointer;
    min-height: 1.5rem;
  }
  .chip {
    display: inline-block;
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    font-weight: 600;
  }
  .chip.allow {
    color: var(--color-success);
    border-color: var(--color-success);
  }
  .chip.deny {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }
  .chip.warn {
    color: var(--color-warning);
    border-color: var(--color-warning);
  }
</style>
