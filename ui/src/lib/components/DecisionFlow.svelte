<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { tick } from "svelte";
  import ConfirmDialog from "./ConfirmDialog.svelte";
  import OptionsPopover from "./OptionsPopover.svelte";
  import { decidedSentence, type Decided } from "#lib/decision/decided.ts";
  import { localCategory } from "#lib/decision/local.ts";
  import { describe, needsConfirm, type Choice } from "#lib/decision/model.ts";
  import { pending as defaultStore } from "#lib/stores/pending.svelte.ts";
  import type { PendingStore, Row } from "#lib/stores/pending.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";

  // Everything that happens when someone decides a request, wherever the list is drawn: the
  // "more choices" popover, the confirm for every workspace, the toast with its undo, and where
  // focus goes when the row is gone. The list draws rows (`RequestRow`) and calls `decide` and
  // `more`; this draws the rest.
  let {
    store = defaultStore,
    heading,
  }: {
    store?: PendingStore;
    /** Where focus goes when no row is left. */
    heading: () => HTMLElement | undefined;
  } = $props();

  // The options popover is one instance for the whole list; `shown` keeps its row and anchor
  // through the close, so focus can return to the chevron.
  let shown = $state<{ id: number; anchor: HTMLElement } | null>(null);
  let optionsOpen = $state(false);
  let confirming = $state<{ row: Row; choice: Choice } | null>(null);
  let confirmOpen = $state(false);

  const optionsRow = $derived(
    store.rows.find((r) => r.request.id === shown?.id),
  );
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

  const rowElement = (id: number) =>
    document.querySelector<HTMLElement>(`[data-request-id="${id}"]`);

  /** The id of the row after (else before) this one, in the order the page shows them. */
  function neighbourOf(id: number): number | null {
    const ids = [
      ...document.querySelectorAll<HTMLElement>("[data-request-id]"),
    ].map((el) => Number(el.dataset["requestId"]));
    const at = ids.indexOf(id);
    return at < 0 ? null : (ids[at + 1] ?? ids[at - 1] ?? null);
  }

  async function settleFocus(nextId: number | null) {
    await tick();
    const active = document.activeElement;
    if (active && active !== document.body && document.contains(active)) return;
    if (nextId !== null) rowElement(nextId)?.focus();
    else heading()?.focus();
  }

  async function submit(row: Row, choice: Choice, confirmed: boolean) {
    const nextId = neighbourOf(row.request.id);
    const result = await store.decide(row, choice, confirmed);
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

  /** Deletes the rule a decision created. */
  export async function undo(d: Decided) {
    const result = await store.undo(d);
    toasts.push(
      result.ok
        ? `Undone: ${decidedSentence(d)}. It asks again the next time the workspace retries.`
        : result.message,
      { ms: result.ok ? 5000 : 8000, tone: result.ok ? "info" : "error" },
    );
  }

  /** Opens the more-choices popover on a row's chevron, or closes it if it is open there. */
  export function more(row: Row, anchor: HTMLElement) {
    if (optionsOpen && shown?.id === row.request.id) {
      optionsOpen = false;
      return;
    }
    shown = { id: row.request.id, anchor };
    optionsOpen = true;
  }

  /** Whether the popover is open on this row. */
  export function optionsOpenFor(id: number): boolean {
    return optionsOpen && shown?.id === id;
  }

  /** Decides now, or asks first when the choice covers every workspace. */
  export function decide(row: Row, choice: Choice) {
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
</script>

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
