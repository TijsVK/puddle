<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    EXPIRY_OPTIONS,
    expiryFrom,
    ruleName,
    type Rule,
  } from "#lib/rules/model.ts";
  import { absoluteTime } from "#lib/format/relative-time.ts";
  import FormDialog from "./FormDialog.svelte";

  let {
    open = $bindable(false),
    rule,
    now,
    onSave,
  }: {
    open?: boolean;
    rule: Rule | null;
    now: () => number;
    /** Resolves to the refusal's text, or `null` when the change was made. */
    onSave: (rule: Rule, expiresAt: number | null) => Promise<string | null>;
  } = $props();

  const id = $props.id();
  let choice = $state("");
  let problem = $state<string | null>(null);
  let busy = $state(false);

  $effect(() => {
    if (open) {
      choice = "";
      problem = null;
    }
  });

  const current = $derived(
    rule === null
      ? ""
      : rule.expires_at === null
        ? "It never expires now."
        : `It now ends ${absoluteTime(rule.expires_at)}.`,
  );

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!rule) return;
    if (choice === "") {
      problem = "Choose when the rule should end.";
      return;
    }
    busy = true;
    try {
      const secs = choice === "0" ? null : Number(choice);
      problem = await onSave(rule, expiryFrom(now(), secs));
      if (problem === null) open = false;
    } finally {
      busy = false;
    }
  }
</script>

<FormDialog
  bind:open
  title="Change expiry"
  description={rule ? `${ruleName(rule)}. ${current}` : ""}
>
  <form onsubmit={submit} novalidate>
    <div class="field">
      <label for="{id}-expiry">Ends</label>
      <select
        id="{id}-expiry"
        bind:value={choice}
        aria-invalid={problem ? "true" : undefined}
        aria-describedby={problem ? `${id}-error` : undefined}
      >
        <option value="">Choose&hellip;</option>
        {#each EXPIRY_OPTIONS as option (option.secs)}
          <option value={String(option.secs ?? 0)}>{option.label}</option>
        {/each}
      </select>
      {#if problem}
        <p class="error" id="{id}-error" role="alert">{problem}</p>
      {/if}
    </div>
    <div class="actions">
      <button type="button" class="btn" onclick={() => (open = false)}
        >Cancel</button
      >
      <button type="submit" class="btn primary" disabled={busy}>Save</button>
    </div>
  </form>
</FormDialog>
