<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { tick } from "svelte";
  import Trash2 from "@lucide/svelte/icons/trash-2";
  import {
    credentialChip,
    describeSource,
    identityProblem,
    type Credential,
    type Identity,
    type Source,
  } from "#lib/identities/model.ts";
  import type { IdentitiesStore } from "#lib/stores/identities.svelte.ts";
  import CredentialEditor from "./CredentialEditor.svelte";
  import FormDialog from "./FormDialog.svelte";

  // Makes an identity or changes one: its name, the author Git writes into commits and its
  // credentials. Nothing reaches the service until Save; a token pasted while the dialog is open
  // is kept at once (it has to go somewhere) and removed again if the identity is not saved.
  let {
    open = $bindable(false),
    mode,
    identity = null,
    store,
    onSaved,
  }: {
    open?: boolean;
    mode: "create" | "edit";
    identity?: Identity | null;
    store: IdentitiesStore;
    onSaved: (identity: Identity) => void;
  } = $props();

  const id = $props.id();
  let label = $state("");
  let name = $state("");
  let email = $state("");
  let credentials = $state.raw<Credential[]>([]);
  let adding = $state(false);
  let problem = $state<{
    field: "label" | "name" | "email" | "form";
    message: string;
  } | null>(null);
  let busy = $state(false);
  let saved = false;
  /** Tokens pasted since the dialog opened, by the line that names them. */
  let pasted = $state.raw<Source[]>([]);

  $effect(() => {
    if (open) {
      label = identity?.label ?? "";
      name = identity?.author.name ?? "";
      email = identity?.author.email ?? "";
      credentials = identity?.credentials ?? [];
      adding = false;
      problem = null;
      pasted = [];
      saved = false;
    }
  });

  // A dialog closed any other way than Save takes back the tokens it kept.
  $effect(() => {
    if (!open && !saved && pasted.length > 0) {
      const leftover = pasted;
      pasted = [];
      for (const source of leftover) void store.forgetToken(source);
    }
  });

  function remove(credential: Credential) {
    credentials = credentials.filter((c) => c !== credential);
    const line = describeSource(credential.source);
    const mine = pasted.find((s) => describeSource(s) === line);
    if (mine) {
      pasted = pasted.filter((s) => s !== mine);
      void store.forgetToken(mine);
    }
  }

  function added(credential: Credential, stored: Source | null) {
    credentials = [...credentials, credential];
    if (stored) pasted = [...pasted, stored];
    adding = false;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const others = store.identities
      .filter((i) => i.id !== identity?.id)
      .map((i) => i.label);
    const found = identityProblem({ label, name, email }, others);
    problem = found;
    if (found) {
      await tick();
      document.getElementById(`${id}-${found.field}`)?.focus();
      return;
    }
    busy = true;
    try {
      const request = {
        label: label.trim(),
        author: { name: name.trim(), email: email.trim() },
        credentials,
      };
      const result =
        mode === "edit" && identity
          ? await store.update(identity.id, request)
          : await store.create(request);
      if (!result.ok) {
        problem = { field: "form", message: result.message };
        return;
      }
      saved = true;
      // Tokens of credentials this edit took away are no longer referenced.
      const kept = new Set(credentials.map((c) => describeSource(c.source)));
      for (const old of identity?.credentials ?? []) {
        if (!kept.has(describeSource(old.source)))
          void store.forgetToken(old.source);
      }
      open = false;
      onSaved(result.value);
    } finally {
      busy = false;
    }
  }
</script>

<FormDialog
  bind:open
  title={mode === "create" ? "Add identity" : "Edit identity"}
  description="An identity is who commits and signs in: the author Git writes into commits, and the credentials puddle adds to Git requests as they leave a workspace. The secrets stay on this computer."
>
  <form id="{id}-form" onsubmit={submit} novalidate>
    <div class="field">
      <label for="{id}-label">Identity name</label>
      <input
        id="{id}-label"
        type="text"
        autocomplete="off"
        maxlength="64"
        placeholder="Work"
        bind:value={label}
        aria-invalid={problem?.field === "label" ? "true" : undefined}
        aria-describedby={problem?.field === "label"
          ? `${id}-error`
          : undefined}
      />
    </div>
    <fieldset>
      <legend>Commit author</legend>
      <div class="field">
        <label for="{id}-name">Author name</label>
        <input
          id="{id}-name"
          type="text"
          autocomplete="off"
          bind:value={name}
          aria-invalid={problem?.field === "name" ? "true" : undefined}
          aria-describedby={problem?.field === "name"
            ? `${id}-error`
            : undefined}
        />
      </div>
      <div class="field">
        <label for="{id}-email">Author email</label>
        <input
          id="{id}-email"
          type="text"
          inputmode="email"
          autocomplete="off"
          bind:value={email}
          aria-invalid={problem?.field === "email" ? "true" : undefined}
          aria-describedby={problem?.field === "email"
            ? `${id}-error`
            : undefined}
        />
      </div>
    </fieldset>
  </form>

  <section class="creds" aria-labelledby="{id}-creds">
    <h3 id="{id}-creds">Credentials</h3>
    {#if credentials.length === 0}
      <p class="hint">
        None yet. Without one, Git requests from a workspace go out without a
        sign-in, which works for public repositories.
      </p>
    {:else}
      <ul>
        {#each credentials as credential (describeSource(credential.source))}
          <li>
            <span>{credentialChip(credential)}</span>
            <button
              type="button"
              class="btn"
              aria-label="Remove {credentialChip(credential)}"
              onclick={() => remove(credential)}
            >
              <Trash2 aria-hidden="true" size={14} />Remove
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    {#if adding}
      <CredentialEditor
        {store}
        existing={credentials}
        onAdd={added}
        onCancel={() => (adding = false)}
      />
    {:else}
      <div>
        <button type="button" class="btn" onclick={() => (adding = true)}
          >Add a credential</button
        >
      </div>
    {/if}
  </section>

  {#if problem}
    <p class="error" id="{id}-error" role="alert">{problem.message}</p>
  {/if}
  <div class="actions">
    <button type="button" class="btn" onclick={() => (open = false)}
      >Cancel</button
    >
    <button type="submit" form="{id}-form" class="btn primary" disabled={busy}
      >{mode === "create" ? "Add identity" : "Save"}</button
    >
  </div>
</FormDialog>

<style>
  .creds {
    display: grid;
    gap: var(--space-2);
  }
  h3 {
    font-size: var(--text-md);
  }
  ul {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
    padding: var(--space-1) var(--space-2);
    background: var(--color-surface-raised);
    border-radius: var(--radius-md);
    overflow-wrap: anywhere;
  }
  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  .error {
    margin: 0;
    color: var(--color-danger);
    font-size: var(--text-sm);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
