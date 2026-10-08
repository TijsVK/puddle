<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import { describe, rawJson, type AuditEntry } from "#lib/audit/model.ts";
  import {
    DETAIL_HEIGHT,
    ROW_HEIGHT,
    visibleRange,
  } from "#lib/audit/window.ts";
  import { absoluteTime } from "#lib/format/relative-time.ts";
  import { clockTime, startOfDay } from "#lib/format/clock-time.ts";
  import "#lib/theme/controls.css";

  const OVERSCAN = 8;
  /** Rows from the end of the loaded list at which the next page is asked for. */
  const NEAR_END = 40;
  const AT_TOP = 8;

  let {
    entries,
    hasMore = false,
    now,
    onTop,
    onNearEnd,
  }: {
    /** Newest first. */
    entries: AuditEntry[];
    hasMore?: boolean;
    /** Epoch ms; decides which times print without a date. */
    now: number;
    /** The user is (or is no longer) at the top of the list. */
    onTop?: (atTop: boolean) => void;
    /** The user is close to the last loaded row and more exist. */
    onNearEnd?: () => void;
  } = $props();

  let box = $state<HTMLElement>();
  let viewport = $state(0);
  let scrollTop = $state(0);
  let openId = $state<number | null>(null);
  let frame = 0;

  const dayStart = $derived(startOfDay(now));
  const openIndex = $derived(
    openId === null ? -1 : entries.findIndex((e) => e.id === openId),
  );
  // jsdom and a hidden tab measure nothing: draw a screenful anyway.
  const height = $derived(viewport > 0 ? viewport : 600);
  const range = $derived(
    visibleRange({
      scrollTop,
      viewportHeight: height,
      rowCount: entries.length,
      rowHeight: ROW_HEIGHT,
      overscan: OVERSCAN,
      openIndex,
      detailHeight: DETAIL_HEIGHT,
    }),
  );
  const drawn = $derived(entries.slice(range.start, range.end));

  $effect(() => {
    if (hasMore && range.end >= entries.length - NEAR_END) onNearEnd?.();
  });

  // The tail follows only while the list is at the top. That is decided on the event itself, not a
  // frame later, so a record that arrives right after a scroll is held back, not shoved in.
  let atTop = true;
  function report(top: number) {
    const now = top <= AT_TOP;
    if (now === atTop) return;
    atTop = now;
    onTop?.(now);
  }

  function onScroll() {
    report(box?.scrollTop ?? 0);
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      scrollTop = box?.scrollTop ?? 0;
    });
  }

  /** Back to the newest record. */
  export function scrollToTop(): void {
    if (box) box.scrollTop = 0;
    scrollTop = 0;
    report(0);
  }

  function toggle(id: number) {
    openId = openId === id ? null : id;
  }
</script>

<!-- A long log is drawn a window at a time (see lib/audit/window.ts); the scroll area is focusable
     so the keyboard can scroll it. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div
  class="wrap"
  role="region"
  aria-label="Activity records"
  tabindex="0"
  bind:this={box}
  bind:clientHeight={viewport}
  onscroll={onScroll}
>
  <table aria-rowcount={hasMore ? -1 : entries.length + 1}>
    <caption class="visually-hidden">Activity</caption>
    <colgroup>
      <col class="c-time" />
      <col class="c-ws" />
      <col class="c-type" />
      <col class="c-dest" />
      <col class="c-out" />
      <col class="c-detail" />
    </colgroup>
    <thead>
      <tr aria-rowindex="1">
        <th scope="col">Time</th>
        <th scope="col">Workspace</th>
        <th scope="col">Type</th>
        <th scope="col">Destination</th>
        <th scope="col">Outcome</th>
        <th scope="col">Detail</th>
      </tr>
    </thead>
    <tbody>
      {#if range.padTop > 0}
        <tr class="pad" aria-hidden="true" style:height="{range.padTop}px"
          ><td colspan="6"></td></tr
        >
      {/if}
      {#each drawn as entry, i (entry.id)}
        {@const row = describe(entry.record)}
        {@const open = entry.id === openId}
        <!-- The toggle button is the keyboard route; the row click is for the pointer. -->
        <tr
          class="row"
          class:open
          data-id={entry.id}
          aria-rowindex={range.start + i + 2}
          onclick={() => toggle(entry.id)}
        >
          <td class="time">
            <button
              type="button"
              class="toggle"
              aria-expanded={open}
              aria-controls="raw-{entry.id}"
              aria-label="{open ? 'Hide' : 'Show'} the raw record of {row.type}"
              onclick={(e) => {
                e.stopPropagation();
                toggle(entry.id);
              }}
            >
              {#if open}<ChevronDown
                  aria-hidden="true"
                  size={14}
                />{:else}<ChevronRight aria-hidden="true" size={14} />{/if}
              <time
                datetime={new Date(row.ts).toISOString()}
                title={absoluteTime(row.ts)}>{clockTime(row.ts, dayStart)}</time
              >
            </button>
          </td>
          <td class="mono" title={row.workspace ?? undefined}>
            {#if row.workspace === null}<span class="muted">puddle</span
              >{:else}{row.workspace}{/if}
          </td>
          <td>{row.type}</td>
          <td class="mono" title={row.destination ?? undefined}
            >{row.destination ?? ""}</td
          >
          <td>
            {#if row.outcome}
              <span class="chip {row.outcome.tone}">{row.outcome.label}</span>
            {/if}
          </td>
          <td class="muted" title={row.detail}>{row.detail}</td>
        </tr>
        {#if open}
          <tr class="detail" aria-rowindex={range.start + i + 2}>
            <td colspan="6">
              <div class="raw" id="raw-{entry.id}">
                <pre tabindex="0" aria-label="Raw record {entry.id}">{rawJson(
                    entry.record,
                  )}</pre>
              </div>
            </td>
          </tr>
        {/if}
      {/each}
      {#if range.padBottom > 0}
        <tr class="pad" aria-hidden="true" style:height="{range.padBottom}px"
          ><td colspan="6"></td></tr
        >
      {/if}
    </tbody>
  </table>
</div>

<style>
  .wrap {
    --row-h: 36px;
    --detail-h: 280px;
    overflow: auto;
    overflow-anchor: none;
    height: calc(100vh - 19rem);
    min-height: 16rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  table {
    width: 100%;
    min-width: 56rem;
    table-layout: fixed;
    border-collapse: separate;
    border-spacing: 0;
    font-size: var(--text-sm);
  }
  .c-time {
    width: 11rem;
  }
  .c-ws {
    width: 9rem;
  }
  .c-type {
    width: 10rem;
  }
  .c-dest {
    width: 22rem;
  }
  .c-out {
    width: 6.5rem;
  }
  th {
    position: sticky;
    top: 0;
    z-index: 1;
    height: var(--control-size);
    padding: 0 var(--space-3);
    text-align: start;
    background: var(--color-surface-raised);
    border-bottom: 1px solid var(--color-border-subtle);
    color: var(--color-text-muted);
    font-weight: 600;
  }
  tr.row {
    height: var(--row-h);
    cursor: pointer;
  }
  tr.row:hover td,
  tr.row.open td {
    background: var(--color-surface-raised);
  }
  tr.row td {
    box-sizing: border-box;
    height: var(--row-h);
    padding: 0 var(--space-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    border-bottom: 1px solid var(--color-border-subtle);
  }
  tr.row td.time {
    padding-inline: var(--space-1);
  }
  tr.pad td {
    padding: 0;
    border: 0;
  }
  tr.detail td {
    box-sizing: border-box;
    height: var(--detail-h);
    padding: 0;
    vertical-align: top;
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .raw {
    box-sizing: border-box;
    height: calc(var(--detail-h) - 1px);
    padding: var(--space-2) var(--space-3);
  }
  pre {
    box-sizing: border-box;
    height: 100%;
    margin: 0;
    padding: var(--space-2) var(--space-3);
    overflow: auto;
    background: var(--color-bg);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    min-height: 1.75rem;
    padding: 0 var(--space-1);
    border: 0;
    background: transparent;
    color: var(--color-text);
    font: inherit;
    font-family: var(--font-mono);
    cursor: pointer;
  }
  .muted {
    color: var(--color-text-muted);
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
