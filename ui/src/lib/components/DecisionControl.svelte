<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  import { narrowest, type Choice, type Target } from "#lib/decision/model.ts";
  import "#lib/theme/controls.css";

  // Allow and Deny one click for this workspace, the exact host,
  // permanently; the chevron asks for the rest (every workspace, subdomains, duration), which
  // OptionsPopover shows. The choice is a plain `Choice`; what happens with it (confirm, API
  // call) is the parent's.
  let {
    target,
    workspace,
    denyOnly = false,
    optionsOpen = false,
    onDecide,
    onMore,
  }: {
    target: Target;
    workspace: string;
    /** The destination can't be approved yet; only Deny is offered. */
    denyOnly?: boolean;
    /** Whether the options are open for this row, for the chevron's `aria-expanded`. */
    optionsOpen?: boolean;
    onDecide: (choice: Choice) => void;
    /** The chevron was used; the element is where the options hang from. */
    onMore: (anchor: HTMLElement) => void;
  } = $props();
</script>

<div class="control">
  {#if !denyOnly}
    <div class="split">
      <button
        type="button"
        class="btn allow main"
        aria-label="Allow {target.host} for {workspace}"
        title="Allow for {workspace}, this host only, permanently (A)"
        onclick={() => onDecide(narrowest("allow"))}
      >
        Allow
      </button>
      <button
        type="button"
        class="btn allow chevron"
        data-more
        aria-label="More choices for {target.host}"
        aria-haspopup="dialog"
        aria-expanded={optionsOpen}
        title="More choices (Enter)"
        onclick={(event) => onMore(event.currentTarget)}
      >
        <ChevronDown aria-hidden="true" size={16} />
      </button>
    </div>
  {/if}
  <button
    type="button"
    class="btn deny"
    aria-label="Deny {target.host} for {workspace}"
    title="Deny for {workspace}, this host only, permanently (D)"
    onclick={() => onDecide(narrowest("deny"))}
  >
    Deny
  </button>
</div>

<style>
  .control {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    justify-content: flex-end;
  }
  .split {
    display: inline-flex;
  }
  .split .main {
    border-start-end-radius: 0;
    border-end-end-radius: 0;
  }
  .split .chevron {
    border-start-start-radius: 0;
    border-end-start-radius: 0;
    border-inline-start-width: 0;
    padding-inline: var(--space-2);
  }
</style>
