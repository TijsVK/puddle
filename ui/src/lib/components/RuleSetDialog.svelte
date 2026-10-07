<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { setNameError } from "#lib/rules/sets.ts";
  import FormDialog from "./FormDialog.svelte";

  // Makes a rule set or renames one. `onSubmit` returns the server's refusal as text, or `null`
  // when it went through (the dialog then closes).
  let {
    open = $bindable(false),
    mode,
    initialName = "",
    initialDescription = "",
    onSubmit,
  }: {
    open?: boolean;
    mode: "create" | "rename";
    initialName?: string;
    initialDescription?: string;
    onSubmit: (name: string, description: string) => Promise<string | null>;
  } = $props();

  const id = $props.id();
  let name = $state("");
  let description = $state("");
  let problem = $state<string | null>(null);
  let busy = $state(false);

  $effect(() => {
    if (open) {
      name = initialName;
      description = initialDescription;
      problem = null;
    }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    problem = setNameError(name);
    if (problem) return;
    busy = true;
    try {
      problem = await onSubmit(name.trim(), description.trim());
      if (problem === null) open = false;
    } finally {
      busy = false;
    }
  }
</script>

<FormDialog
  bind:open
  title={mode === "create" ? "New rule set" : "Rename rule set"}
  description={mode === "create"
    ? "A set starts empty and on for every workspace. Add entries to it here, or approve requests into it from the Inbox."
    : "The name shows on the Rules screen and in the Inbox."}
>
  <form onsubmit={submit} novalidate>
    <div class="field">
      <label for="{id}-name">Name</label>
      <input
        id="{id}-name"
        type="text"
        autocomplete="off"
        maxlength="64"
        bind:value={name}
        aria-invalid={problem ? "true" : undefined}
        aria-describedby={problem ? `${id}-error` : undefined}
      />
      {#if problem}
        <p class="error" id="{id}-error" role="alert">{problem}</p>
      {/if}
    </div>
    <div class="field">
      <label for="{id}-description">Description (optional)</label>
      <input
        id="{id}-description"
        type="text"
        autocomplete="off"
        maxlength="500"
        bind:value={description}
      />
    </div>
    <div class="actions">
      <button type="button" class="btn" onclick={() => (open = false)}
        >Cancel</button
      >
      <button type="submit" class="btn primary" disabled={busy}
        >{mode === "create" ? "Make rule set" : "Save"}</button
      >
    </div>
  </form>
</FormDialog>
