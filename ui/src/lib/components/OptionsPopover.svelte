<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { Popover } from "bits-ui";
  import Check from "@lucide/svelte/icons/check";
  import X from "@lucide/svelte/icons/x";
  import {
    DURATIONS,
    suffixFor,
    type Choice,
    type Effect,
    type Match,
    type RuleSetChoice,
    type Target,
  } from "#lib/decision/model.ts";
  import "#lib/theme/controls.css";

  // The "more choices": every workspace, subdomains, duration. One instance serves the whole
  // list, anchored to the chevron of the row it was opened from (500 rows, one popover).
  let {
    open = false,
    target,
    workspace,
    anchor,
    exactOnly = false,
    sets = [],
    onDecide,
    onClose,
  }: {
    open?: boolean;
    target: Target;
    workspace: string;
    /** The chevron button it hangs from, and gives focus back to. */
    anchor: HTMLElement | null;
    /** Local destinations: only an exact rule counts (R-14), so no subdomain choice. */
    exactOnly?: boolean;
    /** Your rule sets that are on for this workspace: the rule can go into one of them. */
    sets?: readonly RuleSetChoice[];
    onDecide: (choice: Choice) => void;
    onClose: () => void;
  } = $props();

  // "workspace", "global", or "set:<id>".
  let who = $state("workspace");
  let match = $state<Match>("exact");
  let duration = $state("0");

  const suffix = $derived(exactOnly ? null : suffixFor(target));
  const durationSecs = $derived(duration === "0" ? null : Number(duration));
  const id = $props.id();

  $effect(() => {
    // Every time it opens it starts from the narrowest choice (R-15).
    if (open) {
      who = "workspace";
      match = "exact";
      duration = "0";
    }
  });

  function decide(effect: Effect) {
    const ruleSet = sets.find((s) => `set:${s.id}` === who) ?? null;
    const scope = who === "global" ? "global" : "workspace";
    onDecide({ effect, scope, ruleSet, match, durationSecs });
  }
</script>

<Popover.Root
  {open}
  onOpenChange={(next) => {
    if (!next) onClose();
  }}
>
  <Popover.Portal>
    <!-- It hangs over the rows beside it. Its right edge sits 4px past the chevron column, in the
         gap before Deny: flush with the chevrons it would leave a sub-pixel strip of the chevron
         of the row above or below uncovered (the browser rounds the two edges differently), and
         that strip counts as a target under 24px (WCAG 2.5.8). -->
    <Popover.Content
      class="options"
      role="dialog"
      align="end"
      sideOffset={6}
      alignOffset={-4}
      customAnchor={anchor}
      aria-label="Choices for {target.host}"
      onInteractOutside={(event) => {
        // A click on the chevron toggles; it must not close here and reopen there.
        if (event.target instanceof Node && anchor?.contains(event.target)) {
          event.preventDefault();
        }
      }}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        if (anchor?.isConnected) anchor.focus();
      }}
    >
      <fieldset>
        <legend>Who</legend>
        <label>
          <input
            type="radio"
            name="{id}-scope"
            value="workspace"
            bind:group={who}
          />
          Only <b class="mono">{workspace}</b>
        </label>
        <label>
          <input
            type="radio"
            name="{id}-scope"
            value="global"
            bind:group={who}
          />
          Every workspace <span class="hint">(asks to confirm)</span>
        </label>
        {#each sets as set (set.id)}
          <label>
            <input
              type="radio"
              name="{id}-scope"
              value="set:{set.id}"
              bind:group={who}
            />
            Into rule set <b>{set.name}</b>
            {#if set.everywhere}<span class="hint">(on everywhere; asks)</span
              >{/if}
          </label>
        {/each}
      </fieldset>
      <fieldset>
        <legend>Which hosts</legend>
        <label>
          <input
            type="radio"
            name="{id}-match"
            value="exact"
            bind:group={match}
          />
          Only <span class="mono">{target.host}</span>
        </label>
        {#if suffix}
          <label>
            <input
              type="radio"
              name="{id}-match"
              value="suffix"
              bind:group={match}
            />
            Everything under <span class="mono">{suffix.slice(1)}</span>
          </label>
        {/if}
      </fieldset>
      <div class="field">
        <label for="{id}-duration">How long</label>
        <select id="{id}-duration" bind:value={duration}>
          {#each DURATIONS as option (option.secs)}
            <option value={String(option.secs ?? 0)}>{option.label}</option>
          {/each}
        </select>
      </div>
      <div class="actions">
        <Popover.Close class="btn">Cancel</Popover.Close>
        <button type="button" class="btn deny" onclick={() => decide("deny")}>
          <X aria-hidden="true" size={16} />Deny
        </button>
        <button type="button" class="btn allow" onclick={() => decide("allow")}>
          <Check aria-hidden="true" size={16} />Allow
        </button>
      </div>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.options) {
    z-index: 30;
    width: min(22rem, calc(100vw - 2 * var(--space-4)));
    padding: var(--space-4);
    display: grid;
    gap: var(--space-3);
    background: var(--color-surface);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
  }
  :global(.options fieldset) {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    border: 0;
  }
  :global(.options legend) {
    padding: 0;
    margin-bottom: var(--space-1);
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--color-text-muted);
  }
  :global(.options label) {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: 1.5rem;
    overflow-wrap: anywhere;
  }
  :global(.options .field) {
    display: grid;
    gap: var(--space-1);
  }
  :global(.options .field label) {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--color-text-muted);
  }
  :global(.options select) {
    min-height: 2rem;
    padding: var(--space-1) var(--space-2);
    font: inherit;
    color: var(--color-text);
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
  }
  :global(.options input[type="radio"]) {
    width: 1.25rem;
    height: 1.25rem;
    margin: 0;
  }
  :global(.options .hint) {
    color: var(--color-text-muted);
  }
  :global(.options .actions) {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
