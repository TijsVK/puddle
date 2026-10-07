<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    operationLabel,
    statusLabel,
    statusTone,
    type Operation,
    type Status,
  } from "#lib/workspaces/model.ts";

  let { status, busy = null }: { status: Status; busy?: Operation | null } =
    $props();

  const label = $derived(busy ? operationLabel(busy) : statusLabel(status));
  const tone = $derived(busy ? "busy" : statusTone(status));
</script>

<!-- The word carries the meaning; the dot's colour only repeats it. -->
<span class="chip {tone}" data-status={status}>
  <span class="dot" aria-hidden="true"></span>{label}
</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    white-space: nowrap;
  }
  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: var(--radius-pill);
    background: var(--color-text-muted);
  }
  .ok .dot {
    background: var(--color-success);
  }
  .busy .dot {
    background: var(--color-accent);
  }
  .warn .dot {
    background: var(--color-warning);
  }
  .bad {
    border-color: var(--color-danger);
  }
  .bad .dot {
    background: var(--color-danger);
  }
</style>
