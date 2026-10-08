<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import { replaceState } from "$app/navigation";
  import Download from "@lucide/svelte/icons/download";
  import AuditTable from "#lib/components/AuditTable.svelte";
  import {
    NO_FILTER,
    OUTCOMES,
    RANGES,
    TYPES,
    exportName,
    fromSearch,
    isFiltered,
    isNarrowed,
    toSearch,
    type Filter,
  } from "#lib/audit/model.ts";
  import { auditStore as store } from "#lib/stores/audit.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import Toast from "#lib/components/Toast.svelte";
  import "#lib/theme/controls.css";

  /** How long typing in "Host contains" waits before the log is read again. */
  const TYPING_MS = 250;

  let now = $state(Date.now());
  let filter = $state<Filter>({ ...NO_FILTER });
  let heading = $state<HTMLElement>();
  let table = $state<{ scrollToTop: () => void }>();
  let typing: ReturnType<typeof setTimeout> | undefined;
  let exporting = $state(false);
  let exported = $state(0);
  let cancelExport = false;

  const workspaces = $derived(
    filter.workspace !== "" && !store.workspaces.includes(filter.workspace)
      ? [...store.workspaces, filter.workspace].sort()
      : store.workspaces,
  );
  const filtered = $derived(isFiltered(filter));
  const narrowed = $derived(isNarrowed(filter));
  const rangeLabel = $derived(
    RANGES.find((r) => r.key === filter.range)?.label.toLowerCase() ?? "",
  );
  const total = $derived(store.entries.length);
  const countText = $derived(
    `${total.toLocaleString()} ${total === 1 ? "record" : "records"}${
      store.hasMore ? " loaded; older ones load as you scroll" : ""
    }`,
  );

  onMount(() => {
    filter = fromSearch(window.location.search);
    void store.load(filter);
    const stop = store.start();
    const clock = setInterval(() => {
      now = Date.now();
    }, 60_000);
    return () => {
      stop();
      clearInterval(clock);
      clearTimeout(typing);
      store.setFollowing(true);
    };
  });

  /** Reads the log for the current filter and keeps the address in step. */
  function apply() {
    clearTimeout(typing);
    now = Date.now();
    void store.load(filter);
    try {
      replaceState(`${window.location.pathname}${toSearch(filter)}`, {});
    } catch {
      // Before the router is up (a test, an early event): the address catches up on the next change.
    }
  }

  function typed() {
    clearTimeout(typing);
    typing = setTimeout(apply, TYPING_MS);
  }

  function clear() {
    filter = { ...NO_FILTER };
    apply();
  }

  function showNew() {
    table?.scrollToTop();
    store.setFollowing(true);
  }

  async function save() {
    if (exporting) return;
    exporting = true;
    exported = 0;
    cancelExport = false;
    const result = await store.export({
      filter,
      onProgress: (n) => {
        exported = n;
      },
      cancelled: () => cancelExport,
    });
    exporting = false;
    if (!result.ok) {
      if (!("cancelled" in result)) {
        toasts.push(result.message, { tone: "error", ms: 8000 });
      } else {
        toasts.push("Export cancelled.");
      }
      return;
    }
    if (result.records === 0) {
      toasts.push("Nothing to export: no records match these filters.");
      return;
    }
    const name = exportName(Date.now());
    const url = URL.createObjectURL(
      new Blob(result.lines, { type: "application/x-ndjson" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    toasts.push(
      `Saved ${result.records.toLocaleString()} ${result.records === 1 ? "record" : "records"} as ${name}.`,
    );
  }
</script>

<div class="head">
  <div>
    <h1 tabindex="-1" bind:this={heading}>Activity</h1>
    <p class="sub">
      Every connection, decision and rule change, newest first. This is what
      your workspaces actually reached.
    </p>
  </div>
  <div class="actions">
    <label class="live">
      <input
        type="checkbox"
        checked={store.live}
        onchange={(e) => store.setLive(e.currentTarget.checked)}
      />
      Live
    </label>
    <button type="button" class="btn" disabled={exporting} onclick={save}>
      <Download aria-hidden="true" size={16} />Export JSON lines
    </button>
  </div>
</div>

<form
  class="filters"
  role="search"
  aria-label="Filter activity"
  onsubmit={(e) => {
    e.preventDefault();
    apply();
  }}
>
  <div class="field">
    <label for="f-host">Host contains</label>
    <input
      id="f-host"
      type="search"
      autocomplete="off"
      bind:value={filter.host}
      oninput={typed}
    />
  </div>
  <div class="field">
    <label for="f-workspace">Workspace</label>
    <select id="f-workspace" bind:value={filter.workspace} onchange={apply}>
      <option value="">All workspaces</option>
      {#each workspaces as name (name)}<option value={name}>{name}</option
        >{/each}
    </select>
  </div>
  <div class="field">
    <label for="f-type">Type</label>
    <select id="f-type" bind:value={filter.type} onchange={apply}>
      <option value="">All types</option>
      {#each TYPES as t (t.value)}<option value={t.value}>{t.label}</option
        >{/each}
    </select>
  </div>
  <div class="field">
    <label for="f-outcome">Outcome</label>
    <select id="f-outcome" bind:value={filter.outcome} onchange={apply}>
      <option value="">Any outcome</option>
      {#each OUTCOMES as o (o.value)}<option value={o.value}>{o.label}</option
        >{/each}
    </select>
  </div>
  <div class="field">
    <label for="f-range">Time range</label>
    <select id="f-range" bind:value={filter.range} onchange={apply}>
      {#each RANGES as r (r.key)}<option value={r.key}>{r.label}</option>{/each}
    </select>
  </div>
  {#if filtered}
    <button type="button" class="btn" onclick={clear}>Clear filters</button>
  {/if}
</form>

<div class="status">
  <p class="count" aria-busy={store.reloading}>
    {#if store.status === "ready"}{countText}{/if}
  </p>
  {#if exporting}
    <p class="exporting" role="status">
      Exporting&hellip; {exported.toLocaleString()} records
      <button
        type="button"
        class="btn"
        onclick={() => {
          cancelExport = true;
        }}>Cancel</button
      >
    </p>
  {/if}
  {#if store.held.length > 0}
    <p class="new" role="status">
      <button type="button" class="btn" onclick={showNew}>
        {store.held.length.toLocaleString()} new
        {store.held.length === 1 ? "record" : "records"}: show
      </button>
    </p>
  {/if}
</div>

{#if store.status === "loading"}
  <p class="muted">Loading activity&hellip;</p>
{:else if store.status === "failed"}
  <p class="muted">
    Couldn't read the activity log.
    <button type="button" class="btn" onclick={apply}>Try again</button>
  </p>
{:else if total === 0}
  <section class="empty">
    {#if narrowed}
      <h2>No records match</h2>
      <p>
        Nothing in {rangeLabel} matches these filters. Change them, or pick a longer
        time range.
      </p>
    {:else}
      <h2>Nothing recorded yet</h2>
      <p>Connections, decisions and rule changes appear here as they happen.</p>
    {/if}
  </section>
{:else}
  {#key store.epoch}
    <AuditTable
      bind:this={table}
      entries={store.entries}
      hasMore={store.hasMore}
      {now}
      onTop={(atTop) => store.setFollowing(atTop)}
      onNearEnd={() => void store.loadMore()}
    />
  {/key}
{/if}
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
  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .live input {
    width: 1.5rem;
    height: 1.5rem;
  }
  .live {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--control-size);
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
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  .status {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-4);
    min-height: calc(var(--control-size) + 0.25rem);
    margin-bottom: var(--space-2);
  }
  .status p {
    margin: 0;
  }
  .count {
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
