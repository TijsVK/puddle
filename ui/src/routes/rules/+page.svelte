<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount, tick } from "svelte";
  import Plus from "@lucide/svelte/icons/plus";
  import AddRuleDialog from "#lib/components/AddRuleDialog.svelte";
  import ConfirmDialog from "#lib/components/ConfirmDialog.svelte";
  import ExpiryDialog from "#lib/components/ExpiryDialog.svelte";
  import RuleSetsSection from "#lib/components/RuleSetsSection.svelte";
  import RuleTable from "#lib/components/RuleTable.svelte";
  import SystemManagedList from "#lib/components/SystemManagedList.svelte";
  import Toast from "#lib/components/Toast.svelte";
  import {
    DEFAULT_SORT,
    NO_FILTER,
    isOwn,
    PRECEDENCE,
    patternLabel,
    ruleName,
    view,
    workspacesIn,
    type Filter,
    type Rule,
    type Sort,
    type SortKey,
  } from "#lib/rules/model.ts";
  import {
    rulesStore as store,
    type NewRule,
    type ServerError,
  } from "#lib/stores/rules.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import {
    entryPattern,
    isOn,
    userSetNumber,
    type RuleSet,
    type RuleSetEntry,
  } from "#lib/rules/sets.ts";
  import { ruleSets } from "#lib/stores/rule-sets.svelte.ts";
  import "#lib/theme/controls.css";

  let now = $state(Date.now());
  let filter = $state<Filter>({ ...NO_FILTER });
  let sort = $state<Sort>({ ...DEFAULT_SORT });
  let heading = $state<HTMLElement>();
  let addOpen = $state(false);
  let addError = $state<ServerError | null>(null);
  let addDialog = $state<{
    clear: () => void;
    intoSet: (set: number) => void;
  }>();
  let draft = $state<NewRule | null>(null);
  let confirmGlobalOpen = $state(false);
  let expiryRule = $state<Rule | null>(null);
  let expiryOpen = $state(false);
  let deleting = $state<Rule | null>(null);
  let deleteOpen = $state(false);

  const own = $derived(store.rules.filter(isOwn));
  const shown = $derived(view(own, filter, sort, now));
  const workspaces = $derived(workspacesIn(store.rules));
  const setChoices = $derived(
    ruleSets.sets
      .filter((s) => s.kind === "user")
      .map((s) => ({
        id: userSetNumber(s) ?? 0,
        name: s.name,
        everywhere: isOn(s, null),
      })),
  );
  const filtered = $derived(
    filter.host.trim() !== "" ||
      filter.scope !== "any" ||
      filter.effect !== "any" ||
      filter.state !== "any",
  );

  onMount(() => {
    const stop = store.start();
    const stopSets = ruleSets.start();
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => {
      stop();
      stopSets();
      clearInterval(clock);
    };
  });

  function sortBy(key: SortKey) {
    sort =
      sort.key === key
        ? { key, direction: sort.direction === "asc" ? "desc" : "asc" }
        : {
            key,
            direction: key === "created" || key === "expires" ? "desc" : "asc",
          };
  }

  // Where focus goes when the row it was on is gone: the next row's delete button, else the
  // heading. The dialog gives focus back to its trigger as it closes, so wait for that first.
  async function settleFocus(ids: number[]) {
    for (let frame = 0; frame < 30; frame += 1) {
      await tick();
      if (!document.querySelector('[role="alertdialog"], [role="dialog"]'))
        break;
      await new Promise((resolve) => requestAnimationFrame(resolve));
    }
    await tick();
    const active = document.activeElement;
    if (active && active !== document.body && document.contains(active)) return;
    for (const id of ids) {
      const button = document.querySelector<HTMLElement>(
        `[data-rule-id="${id}"] button`,
      );
      if (button) {
        button.focus();
        return;
      }
    }
    heading?.focus();
  }

  /** Every workspace, or a set that is on for every workspace: asks first. */
  function widens(rule: NewRule): boolean {
    const scope = rule.scope;
    if (scope.type === "global") return true;
    if (scope.type !== "set") return false;
    return setChoices.some((s) => s.id === scope.set && s.everywhere);
  }

  /** "every workspace", or "rule set Client X". */
  function draftWhere(rule: NewRule): string {
    const scope = rule.scope;
    if (scope.type !== "set") return "for every workspace";
    const name = setChoices.find((s) => s.id === scope.set)?.name ?? "?";
    return `in rule set ${name}, which is on for every workspace`;
  }

  function addEntry(set: RuleSet) {
    const number = userSetNumber(set);
    if (number === null) return;
    addDialog?.intoSet(number);
    addOpen = true;
  }

  async function deleteEntry(set: RuleSet, entry: RuleSetEntry) {
    if (entry.rule_id === null) return;
    const result = await store.remove(entry.rule_id);
    await ruleSets.refresh();
    toasts.push(
      result.ok
        ? `Deleted ${entryPattern(entry)} from ${set.name}.`
        : result.message,
      result.ok ? {} : { tone: "error", ms: 8000 },
    );
  }

  async function create(rule: NewRule): Promise<ServerError | null> {
    if (widens(rule)) {
      draft = rule;
      addOpen = false;
      confirmGlobalOpen = true;
      return null;
    }
    return finishAdd(rule);
  }

  async function finishAdd(rule: NewRule): Promise<ServerError | null> {
    const result = await store.add(rule);
    if (!result.ok) return { field: result.field, message: result.message };
    addOpen = false;
    addDialog?.clear();
    if (result.rule.scope.type === "set") await ruleSets.refresh();
    toasts.push(`Added: ${ruleName(result.rule)}.`);
    return null;
  }

  async function confirmGlobal() {
    const rule = draft;
    draft = null;
    if (!rule) return;
    const refusal = await finishAdd(rule);
    if (refusal) {
      addError = refusal;
      addOpen = true;
    }
  }

  function cancelGlobal() {
    draft = null;
    addOpen = true;
  }

  function changeExpiry(rule: Rule) {
    expiryRule = rule;
    expiryOpen = true;
  }

  async function saveExpiry(rule: Rule, expiresAt: number | null) {
    const result = await store.setExpiry(rule.id, expiresAt);
    if (!result.ok) return result.message;
    toasts.push(
      expiresAt === null
        ? `${patternLabel(rule)} never expires now.`
        : `Changed the expiry of ${patternLabel(rule)}.`,
    );
    return null;
  }

  function askDelete(rule: Rule) {
    deleting = rule;
    deleteOpen = true;
  }

  async function confirmDelete() {
    const rule = deleting;
    deleting = null;
    if (!rule) return;
    const index = shown.findIndex((r) => r.id === rule.id);
    const neighbours = [shown[index + 1], shown[index - 1]]
      .filter((r): r is Rule => r !== undefined)
      .map((r) => r.id);
    const result = await store.remove(rule.id);
    toasts.push(
      result.ok ? `Deleted: ${ruleName(rule)}.` : result.message,
      result.ok ? {} : { tone: "error", ms: 8000 },
    );
    await settleFocus(neighbours);
  }

  const deleteSummary = $derived(deleting ? ruleName(deleting) : "");
</script>

<div class="head">
  <div>
    <h1 tabindex="-1" bind:this={heading}>Rules</h1>
    <p class="sub">
      What each workspace may reach. Anything without a rule waits in the Inbox.
    </p>
    <p class="sub" id="precedence">{PRECEDENCE}</p>
  </div>
  <button
    type="button"
    class="btn primary"
    onclick={() => {
      addDialog?.clear();
      addOpen = true;
    }}
  >
    <Plus aria-hidden="true" size={16} />Add rule
  </button>
</div>

{#if store.status === "loading"}
  <p class="muted">Loading rules&hellip;</p>
{:else if store.status === "failed"}
  <p class="muted">Couldn't read the rules yet. Trying again.</p>
{:else}
  {#if own.length > 0}
    <form
      class="filters"
      role="search"
      aria-label="Filter rules"
      onsubmit={(e) => e.preventDefault()}
    >
      <div class="field">
        <label for="f-host">Host contains</label>
        <input
          id="f-host"
          type="search"
          autocomplete="off"
          bind:value={filter.host}
        />
      </div>
      <div class="field">
        <label for="f-scope">Workspace</label>
        <select id="f-scope" bind:value={filter.scope}>
          <option value="any">Any</option>
          <option value="global">Every workspace</option>
          {#each workspaces as name (name)}<option value={name}>{name}</option
            >{/each}
        </select>
      </div>
      <div class="field">
        <label for="f-effect">Effect</label>
        <select id="f-effect" bind:value={filter.effect}>
          <option value="any">Any</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
      </div>
      <div class="field">
        <label for="f-state">State</label>
        <select id="f-state" bind:value={filter.state}>
          <option value="any">Any</option>
          <option value="active">Active</option>
          <option value="expired">Expired</option>
        </select>
      </div>
      {#if filtered}
        <button
          type="button"
          class="btn"
          onclick={() => (filter = { ...NO_FILTER })}
        >
          Clear filters
        </button>
      {/if}
    </form>
    <p class="count" aria-live="polite">
      {shown.length === own.length
        ? `${own.length} ${own.length === 1 ? "rule" : "rules"}`
        : `${shown.length} of ${own.length} rules`}
    </p>
  {/if}

  {#if own.length === 0}
    <section class="empty">
      <h2>No rules yet</h2>
      <p>
        Nothing is allowed or denied in advance. Requests wait in the
        <a href="/inbox">Inbox</a> until you decide, or add a rule here.
      </p>
    </section>
  {:else if shown.length === 0}
    <section class="empty">
      <h2>No rule matches</h2>
      <p>Change the filters to see more.</p>
    </section>
  {:else}
    <RuleTable
      rules={shown}
      {sort}
      {now}
      onSort={sortBy}
      onExpiry={changeExpiry}
      onDelete={askDelete}
    />
  {/if}
{/if}

<RuleSetsSection
  store={ruleSets}
  {workspaces}
  onAddEntry={addEntry}
  onDeleteEntry={(set, entry) => void deleteEntry(set, entry)}
/>
<SystemManagedList hosts={ruleSets.system} />

<AddRuleDialog
  bind:this={addDialog}
  bind:open={addOpen}
  bind:error={addError}
  {workspaces}
  sets={setChoices}
  now={() => Date.now()}
  onSubmit={create}
/>
<ExpiryDialog
  bind:open={expiryOpen}
  rule={expiryRule}
  now={() => Date.now()}
  onSave={saveExpiry}
/>
<ConfirmDialog
  bind:open={deleteOpen}
  title="Delete this rule?"
  summary={deleteSummary}
  detail="Requests it allowed or denied are decided anew the next time a workspace asks. Connections that are already open stay open."
  confirmLabel="Delete rule"
  tone="deny"
  onConfirm={() => void confirmDelete()}
  onCancel={() => {
    deleting = null;
  }}
/>
<ConfirmDialog
  bind:open={confirmGlobalOpen}
  title={draft?.effect === "deny"
    ? "Deny for every workspace?"
    : "Allow for every workspace?"}
  summary={draft
    ? `${draft.effect === "deny" ? "Deny" : "Allow"} ${draft.pattern} ${draftWhere(draft)}`
    : ""}
  detail="This covers every workspace you have now and any you create later. You can delete the rule here."
  confirmLabel={draft?.effect === "deny"
    ? "Deny in every workspace"
    : "Allow in every workspace"}
  tone={draft?.effect === "deny" ? "deny" : "allow"}
  onConfirm={() => void confirmGlobal()}
  onCancel={cancelGlobal}
/>
<Toast />

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }
  h1 {
    font-size: var(--text-xl);
  }
  h1:focus {
    outline: none;
  }
  .sub,
  .muted,
  .count {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
  }
  .sub {
    max-width: 52rem;
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-3);
    margin-bottom: var(--space-2);
  }
  .field {
    display: grid;
    gap: var(--space-1);
  }
  .field label {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .field input,
  .field select {
    min-height: 2rem;
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  .count {
    margin-bottom: var(--space-2);
    font-size: var(--text-sm);
  }
  .empty {
    padding: var(--space-6);
    max-width: 64rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .empty h2,
  .empty p {
    margin: 0 0 var(--space-2);
  }
</style>
