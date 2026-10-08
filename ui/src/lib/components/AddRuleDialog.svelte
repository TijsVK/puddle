<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    EXPIRY_OPTIONS,
    expiryFrom,
    workspaceNameError,
  } from "#lib/rules/model.ts";
  import type { RuleSetChoice } from "#lib/decision/model.ts";
  import type { NewRule, ServerError } from "#lib/stores/rules.svelte.ts";
  import FormDialog from "./FormDialog.svelte";

  // The form keeps what was typed while it is closed, so a refused rule (or a cancelled confirm)
  // can be corrected instead of retyped. `onSubmit` gets a complete request; it returns `null` when
  // it has taken over (the confirm step) and the refusal otherwise.
  let {
    open = $bindable(false),
    workspaces,
    sets = [],
    now,
    error = $bindable(null),
    onSubmit,
  }: {
    open?: boolean;
    /** Workspaces the rules already name, offered as suggestions. */
    workspaces: string[];
    /** Your rule sets: the rule can go into one of them instead. */
    sets?: readonly RuleSetChoice[];
    now: () => number;
    error?: ServerError | null;
    onSubmit: (rule: NewRule) => Promise<ServerError | null>;
  } = $props();

  const id = $props.id();
  let pattern = $state("");
  let effect = $state<"allow" | "deny">("allow");
  // "workspace", "global", or "set:<id>".
  let scope = $state("workspace");
  let workspace = $state("");
  let duration = $state("0");
  let busy = $state(false);
  let patternProblem = $state<string | null>(null);
  let workspaceProblem = $state<string | null>(null);

  const patternMessage = $derived(
    patternProblem ?? (error?.field === "pattern" ? error.message : null),
  );
  const formMessage = $derived(error?.field === "form" ? error.message : null);

  function reset() {
    pattern = "";
    effect = "allow";
    scope = "workspace";
    workspace = "";
    duration = "0";
    patternProblem = null;
    workspaceProblem = null;
    error = null;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    patternProblem =
      pattern.trim() === ""
        ? "Enter a host, such as example.com or *.example.com."
        : null;
    workspaceProblem =
      scope === "workspace" ? workspaceNameError(workspace.trim()) : null;
    if (patternProblem || workspaceProblem) return;
    const secs = duration === "0" ? null : Number(duration);
    const expires = expiryFrom(now(), secs);
    busy = true;
    try {
      const refusal = await onSubmit({
        effect,
        pattern: pattern.trim(),
        scope: scopeOf(scope),
        expires_at: expires,
      });
      if (refusal) error = refusal;
    } finally {
      busy = false;
    }
  }

  function scopeOf(choice: string): NewRule["scope"] {
    const set = sets.find((s) => `set:${s.id}` === choice);
    if (set) return { type: "set", set: set.id };
    if (choice === "global") return { type: "global" };
    return { type: "workspace", workspace: workspace.trim() as never };
  }

  /** Empties the form and puts the rule into this set; the page calls it from a set's card. */
  export function intoSet(set: number): void {
    reset();
    scope = `set:${set}`;
  }

  /** Empties the form; the page calls it after a rule was added. */
  export function clear(): void {
    reset();
  }
</script>

<FormDialog
  bind:open
  title="Add a rule"
  description="Rules decide what a workspace may reach. A new rule applies to the next request and closes any waiting request it decides."
>
  <form onsubmit={submit} novalidate>
    <div class="field">
      <label for="{id}-pattern">Host</label>
      <input
        id="{id}-pattern"
        type="text"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        placeholder="example.com or *.example.com"
        bind:value={pattern}
        aria-invalid={patternMessage ? "true" : undefined}
        aria-describedby="{id}-pattern-hint{patternMessage
          ? ` ${id}-pattern-error`
          : ''}"
      />
      <p class="hint" id="{id}-pattern-hint">
        <span class="mono">*.example.com</span> covers every name under
        example.com, not example.com itself. A whole top-level domain such as
        <span class="mono">*.com</span> is refused.
      </p>
      {#if patternMessage}
        <p class="error" id="{id}-pattern-error" role="alert">
          {patternMessage}
        </p>
      {/if}
    </div>
    <fieldset>
      <legend>Effect</legend>
      <label class="choice">
        <input
          type="radio"
          name="{id}-effect"
          value="allow"
          bind:group={effect}
        />
        Allow
      </label>
      <label class="choice">
        <input
          type="radio"
          name="{id}-effect"
          value="deny"
          bind:group={effect}
        />
        Deny
      </label>
    </fieldset>
    <fieldset>
      <legend>Who</legend>
      <label class="choice">
        <input
          type="radio"
          name="{id}-scope"
          value="workspace"
          bind:group={scope}
        />
        One workspace
      </label>
      <label class="choice">
        <input
          type="radio"
          name="{id}-scope"
          value="global"
          bind:group={scope}
        />
        Every workspace <span class="hint">(asks to confirm)</span>
      </label>
      {#each sets as set (set.id)}
        <label class="choice">
          <input
            type="radio"
            name="{id}-scope"
            value="set:{set.id}"
            bind:group={scope}
          />
          In rule set <b>{set.name}</b>
          {#if set.everywhere}<span class="hint">(on everywhere; asks)</span
            >{/if}
        </label>
      {/each}
      {#if scope === "workspace"}
        <div class="field">
          <label for="{id}-workspace">Workspace name</label>
          <input
            id="{id}-workspace"
            type="text"
            list="{id}-workspaces"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            bind:value={workspace}
            aria-invalid={workspaceProblem ? "true" : undefined}
            aria-describedby={workspaceProblem
              ? `${id}-workspace-error`
              : undefined}
          />
          <datalist id="{id}-workspaces">
            {#each workspaces as name (name)}<option value={name}
              ></option>{/each}
          </datalist>
          {#if workspaceProblem}
            <p class="error" id="{id}-workspace-error" role="alert">
              {workspaceProblem}
            </p>
          {/if}
        </div>
      {/if}
    </fieldset>
    <div class="field">
      <label for="{id}-duration">Expires</label>
      <select id="{id}-duration" bind:value={duration}>
        {#each EXPIRY_OPTIONS as option (option.secs)}
          <option value={String(option.secs ?? 0)}>{option.label}</option>
        {/each}
      </select>
    </div>
    {#if formMessage}
      <p class="error" role="alert">{formMessage}</p>
    {/if}
    <div class="actions">
      <button
        type="button"
        class="btn"
        onclick={() => {
          open = false;
          reset();
        }}>Cancel</button
      >
      <button type="submit" class="btn primary" disabled={busy}>Add rule</button
      >
    </div>
  </form>
</FormDialog>
