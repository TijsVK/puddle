<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import Plus from "@lucide/svelte/icons/plus";
  import {
    SETS_INTRO,
    type RuleSet,
    type RuleSetEntry,
  } from "#lib/rules/sets.ts";
  import {
    ruleSets as defaultStore,
    type RuleSetsStore,
  } from "#lib/stores/rule-sets.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import ConfirmDialog from "./ConfirmDialog.svelte";
  import RuleSetCard from "./RuleSetCard.svelte";
  import RuleSetDialog from "./RuleSetDialog.svelte";
  import "#lib/theme/controls.css";

  // The rule sets on the Rules screen: built-in ones and yours, their switches, and the dialogs
  // to make, rename and delete a set. Entries are rules: the page adds and deletes them.
  let {
    store = defaultStore,
    workspaces,
    onAddEntry,
    onDeleteEntry,
  }: {
    store?: RuleSetsStore;
    workspaces: string[];
    onAddEntry: (set: RuleSet) => void;
    onDeleteEntry: (set: RuleSet, entry: RuleSetEntry) => void;
  } = $props();

  const id = $props.id();
  let dialogOpen = $state(false);
  let dialogMode = $state<"create" | "rename">("create");
  let renaming = $state<RuleSet | null>(null);
  let switching = $state<RuleSet | null>(null);
  let switchOpen = $state(false);
  let deleting = $state<RuleSet | null>(null);
  let deleteOpen = $state(false);

  async function doSwitch(
    set: RuleSet,
    workspace: string | null,
    enabled: boolean | null,
  ) {
    const result = await store.switchSet(set.id, workspace, enabled);
    if (!result.ok) {
      toasts.push(result.message, { tone: "error", ms: 8000 });
      return;
    }
    const where = workspace === null ? "every workspace" : workspace;
    const what =
      enabled === null
        ? `${set.name} follows the next level for ${where}`
        : `${set.name} is ${enabled ? "on" : "off"} for ${where}`;
    const closed =
      result.value > 0
        ? `; it decided ${result.value} waiting ${result.value === 1 ? "request" : "requests"}`
        : "";
    toasts.push(`${what}${closed}.`);
  }

  /** Turning a set on for every workspace asks first: it widens what every workspace reaches. */
  function onSwitch(
    set: RuleSet,
    workspace: string | null,
    enabled: boolean | null,
  ) {
    const widens =
      workspace === null &&
      (enabled === true || (enabled === null && set.default_on));
    if (widens) {
      switching = set;
      switchOpen = true;
      return;
    }
    void doSwitch(set, workspace, enabled);
  }

  function confirmSwitch() {
    const set = switching;
    switching = null;
    if (set) void doSwitch(set, null, true);
  }

  async function submitDialog(name: string, description: string) {
    const result =
      dialogMode === "create"
        ? await store.create(name, description)
        : await store.rename(renaming?.id ?? "", name, description);
    if (!result.ok) return result.message;
    toasts.push(
      dialogMode === "create"
        ? `Made rule set ${result.value.name}.`
        : `Renamed to ${result.value.name}.`,
    );
    return null;
  }

  async function confirmDelete() {
    const set = deleting;
    deleting = null;
    if (!set) return;
    const result = await store.remove(set.id);
    toasts.push(
      result.ok ? `Deleted rule set ${set.name}.` : result.message,
      result.ok ? {} : { tone: "error", ms: 8000 },
    );
  }
</script>

<section aria-labelledby="{id}-title" class="sets">
  <div class="head">
    <div>
      <h2 id="{id}-title">Rule sets</h2>
      <p class="sub">{SETS_INTRO}</p>
    </div>
    <button
      type="button"
      class="btn"
      onclick={() => {
        dialogMode = "create";
        renaming = null;
        dialogOpen = true;
      }}><Plus aria-hidden="true" size={16} />New rule set</button
    >
  </div>
  {#if store.status === "loading"}
    <p class="sub">Loading rule sets&hellip;</p>
  {:else if store.status === "failed"}
    <p class="sub">Couldn't read the rule sets yet. Trying again.</p>
  {:else}
    {#each store.sets as set (set.id)}
      <RuleSetCard
        {set}
        {workspaces}
        {onSwitch}
        {onAddEntry}
        {onDeleteEntry}
        onRename={(s) => {
          dialogMode = "rename";
          renaming = s;
          dialogOpen = true;
        }}
        onDelete={(s) => {
          deleting = s;
          deleteOpen = true;
        }}
      />
    {/each}
  {/if}
</section>

<RuleSetDialog
  bind:open={dialogOpen}
  mode={dialogMode}
  initialName={renaming?.name ?? ""}
  initialDescription={renaming?.description ?? ""}
  onSubmit={submitDialog}
/>
<ConfirmDialog
  bind:open={switchOpen}
  title="Turn on for every workspace?"
  summary={switching
    ? `${switching.name}: allow its ${switching.entries.length} ${switching.entries.length === 1 ? "entry" : "entries"} in every workspace`
    : ""}
  detail="This covers every workspace you have now and any you create later, except those you switch off. Your own rules still decide first."
  confirmLabel="Turn on everywhere"
  onConfirm={confirmSwitch}
  onCancel={() => {
    switching = null;
  }}
/>
<ConfirmDialog
  bind:open={deleteOpen}
  title="Delete this rule set?"
  summary={deleting
    ? `${deleting.name} and its ${deleting.entries.length} ${deleting.entries.length === 1 ? "entry" : "entries"}`
    : ""}
  detail="Requests its entries allowed or denied are decided anew the next time a workspace asks. Connections that are already open stay open."
  confirmLabel="Delete rule set"
  tone="deny"
  onConfirm={() => void confirmDelete()}
  onCancel={() => {
    deleting = null;
  }}
/>

<style>
  .sets {
    display: grid;
    gap: var(--space-3);
    margin-top: var(--space-6);
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
  }
  .sub {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
    max-width: 52rem;
  }
</style>
