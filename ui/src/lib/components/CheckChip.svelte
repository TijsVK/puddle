<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { statusWord, type Check } from "#lib/identities/model.ts";

  // What the last check of a credential came to. The word carries the meaning; the colour only
  // repeats it.
  let { check }: { check: Check } = $props();

  const tone = $derived(
    check.state === "ok"
      ? "ok"
      : check.state === "problem"
        ? check.needsSignIn
          ? "warn"
          : "bad"
        : "plain",
  );
</script>

<span class="chip {tone}" data-check={check.state}>{statusWord(check)}</span>

<style>
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    white-space: nowrap;
  }
  .ok {
    color: var(--color-success);
    border-color: var(--color-success);
  }
  .warn {
    color: var(--color-warning);
    border-color: var(--color-warning);
  }
  .bad {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }
  .plain {
    color: var(--color-text-muted);
  }
</style>
