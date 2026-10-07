<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount, tick } from "svelte";
  import Undo2 from "@lucide/svelte/icons/undo-2";
  import ConfirmDialog from "#lib/components/ConfirmDialog.svelte";
  import OptionsPopover from "#lib/components/OptionsPopover.svelte";
  import RequestRow from "#lib/components/RequestRow.svelte";
  import Toast from "#lib/components/Toast.svelte";
  import {
    decidedPattern,
    decidedSentence,
    type Decided,
  } from "#lib/decision/decided.ts";
  import { LOCAL_LABELS, localCategory } from "#lib/decision/local.ts";
  import {
    describe,
    narrowest,
    needsConfirm,
    type Choice,
    type Effect,
  } from "#lib/decision/model.ts";
  import { relativeTime } from "#lib/format/relative-time.ts";
  import {
    limitGroups,
    pending,
    type Row,
  } from "#lib/stores/pending.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import "#lib/theme/controls.css";

  let now = $state(Date.now());
  let currentId = $state<number | null>(null);
  // The options popover is one instance for the whole list; `shown` keeps its row and anchor
  // through the close, so focus can return to the chevron.
  let shown = $state<{ id: number; anchor: HTMLElement } | null>(null);
  let optionsOpen = $state(false);
  let confirming = $state<{ row: Row; choice: Choice } | null>(null);
  let confirmOpen = $state(false);
  let heading = $state<HTMLElement>();

  // A long list is drawn in slices, so the first rows are on screen at once: the first slice,
  // then the rest a frame at a time.
  const FIRST_SLICE = 60;
  const NEXT_SLICE = 120;
  let limit = $state(FIRST_SLICE);
  const shownGroups = $derived(limitGroups(pending.groups, limit));
  const flat = $derived(shownGroups.flatMap((g) => g.rows));
  const activeId = $derived(
    flat.some((r) => r.request.id === currentId)
      ? currentId
      : (flat[0]?.request.id ?? null),
  );
  const held = $derived(
    Object.values(pending.suppression)
      .filter((s) => s.active)
      .sort((a, b) => a.sandbox.localeCompare(b.sandbox)),
  );

  onMount(() => {
    const stop = pending.start();
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    return () => {
      stop();
      clearInterval(clock);
    };
  });

  // For the e2e speed bar: the store marks when the data arrived; this marks when the first
  // slice of rows has been rendered and painted, and when the last one has.
  const afterPaint = (run: () => void) =>
    requestAnimationFrame(() => setTimeout(run, 0));
  let markedFirst = false;
  let markedAll = false;
  $effect(() => {
    if (pending.status !== "ready") return;
    if (!markedFirst) {
      markedFirst = true;
      afterPaint(() => performance.mark("puddle:inbox-painted"));
    }
    if (limit < pending.count) {
      const frame = requestAnimationFrame(() => {
        limit += NEXT_SLICE;
      });
      return () => cancelAnimationFrame(frame);
    }
    if (!markedAll) {
      markedAll = true;
      afterPaint(() => performance.mark("puddle:inbox-all-painted"));
    }
  });

  const rowElement = (id: number) =>
    document.querySelector<HTMLElement>(`[data-request-id="${id}"]`);

  function request(id: number | null): Row | undefined {
    return pending.rows.find((r) => r.request.id === id);
  }

  async function settleFocus(nextId: number | null) {
    await tick();
    const active = document.activeElement;
    if (active && active !== document.body && document.contains(active)) return;
    if (nextId !== null) rowElement(nextId)?.focus();
    else heading?.focus();
  }

  async function submit(row: Row, choice: Choice, confirmed: boolean) {
    const index = flat.indexOf(row);
    const neighbour = flat[index + 1] ?? flat[index - 1];
    const nextId = neighbour ? neighbour.request.id : null;
    const result = await pending.decide(row, choice, confirmed);
    if (!result.ok) {
      toasts.push(result.message, { tone: "error", ms: 8000 });
      if (result.reason === "stale") await settleFocus(nextId);
      return;
    }
    const d = result.decided;
    const extra =
      d.alsoClosed > 0
        ? `; also closed ${d.alsoClosed} other ${d.alsoClosed === 1 ? "request" : "requests"}`
        : "";
    toasts.push(`${decidedSentence(d)}${extra}.`, {
      action: { label: "Undo", run: () => undo(d) },
    });
    await settleFocus(nextId);
  }

  async function undo(d: Decided) {
    const result = await pending.undo(d);
    toasts.push(
      result.ok
        ? `Undone: ${decidedSentence(d)}. It asks again the next time the workspace retries.`
        : result.message,
      { ms: result.ok ? 5000 : 8000, tone: result.ok ? "info" : "error" },
    );
  }

  const optionsRow = $derived(request(shown?.id ?? null));

  function openOptions(row: Row, anchor: HTMLElement) {
    if (optionsOpen && shown?.id === row.request.id) {
      optionsOpen = false;
      return;
    }
    shown = { id: row.request.id, anchor };
    optionsOpen = true;
  }

  function decide(row: Row, choice: Choice) {
    optionsOpen = false;
    if (needsConfirm(choice)) {
      confirming = { row, choice };
      confirmOpen = true;
      return;
    }
    void submit(row, choice, false);
  }

  function confirmed() {
    const pendingChoice = confirming;
    confirming = null;
    if (pendingChoice)
      void submit(pendingChoice.row, pendingChoice.choice, true);
  }

  const confirmText = $derived(
    confirming
      ? describe(
          confirming.choice,
          {
            host: confirming.row.request.host,
            registrableDomain: confirming.row.domain,
          },
          confirming.row.request.sandbox,
        )
      : "",
  );

  function quick(effect: Effect) {
    const row = request(activeId);
    if (!row) return;
    const blocked = pending.blockedBy(row.request);
    if (effect === "allow" && blocked) {
      toasts.push(
        `Can't allow ${row.request.host} yet: ${LOCAL_LABELS[blocked]} destinations are switched off in Settings.`,
        { tone: "error", ms: 8000 },
      );
      return;
    }
    decide(row, narrowest(effect));
  }

  function move(step: 1 | -1) {
    if (flat.length === 0) return;
    const index = flat.findIndex((r) => r.request.id === activeId);
    const next = flat[Math.min(Math.max(index + step, 0), flat.length - 1)];
    if (!next) return;
    currentId = next.request.id;
    rowElement(next.request.id)?.focus();
  }

  function onKeydown(event: KeyboardEvent) {
    if (
      event.defaultPrevented ||
      event.ctrlKey ||
      event.metaKey ||
      event.altKey
    )
      return;
    const target = event.target instanceof HTMLElement ? event.target : null;
    if (target?.closest("input, textarea, select, [contenteditable='true']"))
      return;
    if (document.querySelector('[role="dialog"], [role="alertdialog"]')) return;
    switch (event.key) {
      case "a":
      case "A":
        event.preventDefault();
        quick("allow");
        return;
      case "d":
      case "D":
        event.preventDefault();
        quick("deny");
        return;
      case "j":
      case "J":
        event.preventDefault();
        move(1);
        return;
      case "k":
      case "K":
        event.preventDefault();
        move(-1);
        return;
      case "Enter": {
        // Enter on a button or link keeps its own meaning; on a row (or nowhere) it opens options.
        const onRow =
          target === null ||
          target === document.body ||
          target.matches("li.req");
        const row = request(activeId);
        if (onRow && row && pending.blockedBy(row.request) === null) {
          event.preventDefault();
          const anchor = rowElement(row.request.id)?.querySelector<HTMLElement>(
            "[data-more]",
          );
          if (anchor) openOptions(row, anchor);
        }
        return;
      }
    }
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="head">
  <h1 tabindex="-1" bind:this={heading}>Inbox</h1>
  <p class="sub">
    Requests that matched no rule. The workspace waits until you decide.
  </p>
  <p class="keys">
    <span class="kbd">A</span> allow · <span class="kbd">D</span> deny ·
    <span class="kbd">J</span>/<span class="kbd">K</span> move ·
    <span class="kbd">Enter</span> more choices
  </p>
</div>

{#each held as s (s.sandbox)}
  <p class="held">
    <b
      >{s.count} more {s.count === 1 ? "request" : "requests"} from
      <span class="mono">{s.sandbox}</span>
      {s.count === 1 ? "was" : "were"} held back</b
    >
    because it asked for many new hosts at once. They show up again when it retries.
  </p>
{/each}

{#if pending.status === "loading"}
  <p class="muted">Loading requests&hellip;</p>
{:else if pending.status === "failed"}
  <p class="muted">Couldn't read the requests yet. Trying again.</p>
{:else if pending.groups.length === 0}
  <section class="empty">
    <h2>All quiet</h2>
    <p>Nothing is waiting. New requests from your workspaces appear here.</p>
  </section>
{:else}
  {#each shownGroups as group (group.domain)}
    <section class="group" aria-labelledby="group-{group.domain}">
      <div class="group-head">
        <h2 id="group-{group.domain}" class="domain">{group.domain}</h2>
        <span class="chip">{group.total} waiting</span>
      </div>
      <ul>
        {#each group.rows as row (row.request.id)}
          <RequestRow
            {row}
            {now}
            current={row.request.id === activeId}
            blockedBy={pending.blockedBy(row.request)}
            optionsOpen={optionsOpen && shown?.id === row.request.id}
            onMore={openOptions}
            onDecide={decide}
            onFocusRow={(r) => {
              currentId = r.request.id;
            }}
          />
        {/each}
      </ul>
    </section>
  {/each}
{/if}

{#if pending.decided.length > 0}
  <section class="decided" aria-labelledby="decided-h">
    <h2 id="decided-h">Decided just now</h2>
    <ul>
      {#each pending.decided as d (d.ruleId)}
        <li>
          <span class="chip {d.effect}"
            >{d.effect === "allow" ? "allowed" : "denied"}</span
          >
          <span class="what">
            <span class="mono">{decidedPattern(d)}</span>
            for {d.workspace === null
              ? "every workspace"
              : `workspace ${d.workspace}`},
            {d.expiresAt === null
              ? "permanently"
              : `until ${relativeTime(d.expiresAt, now)}`}
            {#if d.alsoClosed > 0}<span class="muted"
                >· also closed {d.alsoClosed} other</span
              >{/if}
          </span>
          <button
            type="button"
            class="btn"
            aria-label="Undo: {decidedSentence(d)}"
            onclick={() => void undo(d)}
          >
            <Undo2 aria-hidden="true" size={16} />Undo
          </button>
        </li>
      {/each}
    </ul>
  </section>
{/if}

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirming?.choice.effect === "deny"
    ? "Deny for every workspace?"
    : "Allow for every workspace?"}
  summary={confirmText}
  detail="This covers every workspace you have now and any you create later. You can undo it right after, or delete the rule on the Rules page."
  confirmLabel={confirming?.choice.effect === "deny"
    ? "Deny in every workspace"
    : "Allow in every workspace"}
  tone={confirming?.choice.effect === "deny" ? "deny" : "allow"}
  onConfirm={confirmed}
  onCancel={() => {
    confirming = null;
  }}
/>
{#if optionsRow}
  <OptionsPopover
    open={optionsOpen}
    target={{
      host: optionsRow.request.host,
      registrableDomain: optionsRow.domain,
    }}
    workspace={optionsRow.request.sandbox}
    anchor={shown?.anchor ?? null}
    exactOnly={localCategory(optionsRow.request.host) !== null}
    onDecide={(choice) => decide(optionsRow, choice)}
    onClose={() => {
      optionsOpen = false;
    }}
  />
{/if}
<Toast />

<style>
  .head {
    display: grid;
    gap: var(--space-1);
    margin-bottom: var(--space-4);
  }
  h1 {
    font-size: var(--text-xl);
  }
  h1:focus {
    outline: none;
  }
  .sub,
  .keys,
  .muted {
    margin: 0;
    color: var(--color-text-muted);
  }
  .keys {
    font-size: var(--text-sm);
  }
  .held {
    margin: 0 0 var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .group,
  .decided,
  .empty {
    margin-bottom: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    max-width: 64rem;
  }
  .empty {
    padding: var(--space-6);
  }
  .empty h2,
  .empty p {
    margin: 0 0 var(--space-2);
  }
  .group-head {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .domain {
    font-family: var(--font-mono);
    font-size: var(--text-md);
    overflow-wrap: anywhere;
  }
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    color: var(--color-text);
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
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .decided h2 {
    padding: var(--space-3) var(--space-4);
    font-size: var(--text-md);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .decided li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-4);
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .decided li:last-child {
    border-bottom: 0;
  }
  .decided .what {
    flex: 1;
    min-width: 0;
    overflow-wrap: anywhere;
  }
</style>
