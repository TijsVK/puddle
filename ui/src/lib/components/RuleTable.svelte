<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import ArrowDown from "@lucide/svelte/icons/arrow-down";
  import ArrowUp from "@lucide/svelte/icons/arrow-up";
  import Clock from "@lucide/svelte/icons/clock";
  import Trash2 from "@lucide/svelte/icons/trash-2";
  import { absoluteTime, relativeTime } from "#lib/format/relative-time.ts";
  import {
    isExpired,
    patternLabel,
    ruleName,
    scopeLabel,
    workspaceOf,
    type Rule,
    type Sort,
    type SortKey,
  } from "#lib/rules/model.ts";
  import "#lib/theme/controls.css";

  let {
    rules,
    sort,
    now,
    onSort,
    onExpiry,
    onDelete,
  }: {
    rules: Rule[];
    sort: Sort;
    now: number;
    onSort: (key: SortKey) => void;
    onExpiry: (rule: Rule, anchor: HTMLElement) => void;
    onDelete: (rule: Rule, anchor: HTMLElement) => void;
  } = $props();

  const columns: { key: SortKey; label: string }[] = [
    { key: "pattern", label: "Host" },
    { key: "effect", label: "Effect" },
    { key: "scope", label: "Workspace" },
    { key: "expires", label: "Expires" },
    { key: "created", label: "Created" },
  ];

  const ariaSort = (key: SortKey) =>
    sort.key !== key
      ? undefined
      : sort.direction === "asc"
        ? "ascending"
        : "descending";
</script>

<div class="wrap">
  <table>
    <caption class="visually-hidden">Rules</caption>
    <thead>
      <tr>
        {#each columns as column (column.key)}
          <th scope="col" aria-sort={ariaSort(column.key)}>
            <button
              type="button"
              class="sort"
              onclick={() => onSort(column.key)}
              aria-label="Sort by {column.label.toLowerCase()}"
            >
              {column.label}
              {#if sort.key === column.key}
                {#if sort.direction === "asc"}
                  <ArrowUp aria-hidden="true" size={14} />
                {:else}
                  <ArrowDown aria-hidden="true" size={14} />
                {/if}
              {/if}
            </button>
          </th>
        {/each}
        <th scope="col"><span class="visually-hidden">Actions</span></th>
      </tr>
    </thead>
    <tbody>
      {#each rules as rule (rule.id)}
        {@const expired = isExpired(rule, now)}
        <tr data-rule-id={rule.id} class:expired>
          <td class="host">
            <span class="mono">{patternLabel(rule)}</span>
            {#if rule.pattern_kind === "suffix"}
              <span class="chip">and subdomains</span>
            {/if}
          </td>
          <td>
            <span class="chip {rule.effect}"
              >{rule.effect === "allow" ? "Allow" : "Deny"}</span
            >
          </td>
          <td>
            {#if workspaceOf(rule) === null}
              {scopeLabel(rule)}
            {:else}
              <span class="mono">{scopeLabel(rule)}</span>
            {/if}
          </td>
          <td>
            {#if rule.expires_at === null}
              <span class="muted">Never</span>
            {:else}
              <time
                datetime={new Date(rule.expires_at).toISOString()}
                title={absoluteTime(rule.expires_at)}
                >{expired
                  ? "Expired"
                  : relativeTime(rule.expires_at, now)}</time
              >
              {#if expired}<span class="chip">no longer applies</span>{/if}
            {/if}
          </td>
          <td>
            <time
              datetime={new Date(rule.created_at).toISOString()}
              title="{absoluteTime(rule.created_at)} by {rule.created_by}"
              >{relativeTime(rule.created_at, now)}</time
            >
          </td>
          <td class="actions">
            <button
              type="button"
              class="btn"
              aria-label="Change expiry: {ruleName(rule)}"
              onclick={(e) => onExpiry(rule, e.currentTarget)}
            >
              <Clock aria-hidden="true" size={16} />Expiry
            </button>
            <button
              type="button"
              class="btn deny"
              aria-label="Delete rule: {ruleName(rule)}"
              onclick={(e) => onDelete(rule, e.currentTarget)}
            >
              <Trash2 aria-hidden="true" size={16} />Delete
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .wrap {
    overflow-x: auto;
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
  }
  th,
  td {
    padding: var(--space-1) var(--space-3);
    text-align: start;
    border-bottom: 1px solid var(--color-border-subtle);
    vertical-align: middle;
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  .sort {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    min-height: 1.5rem;
    padding: 0 var(--space-1);
    border: 0;
    background: transparent;
    color: var(--color-text-muted);
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  .host {
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--color-text-muted);
  }
  tr.expired td:not(.actions) {
    color: var(--color-text-muted);
  }
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    white-space: nowrap;
  }
  .chip.allow {
    color: var(--color-success);
    border-color: var(--color-success);
  }
  .chip.deny {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }
  .actions {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    white-space: nowrap;
  }
</style>
