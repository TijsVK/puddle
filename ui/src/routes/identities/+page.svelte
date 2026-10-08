<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount, tick } from "svelte";
  import ArrowDown from "@lucide/svelte/icons/arrow-down";
  import ArrowUp from "@lucide/svelte/icons/arrow-up";
  import Plus from "@lucide/svelte/icons/plus";
  import CheckChip from "#lib/components/CheckChip.svelte";
  import ConfirmDialog from "#lib/components/ConfirmDialog.svelte";
  import IdentityDialog from "#lib/components/IdentityDialog.svelte";
  import Toast from "#lib/components/Toast.svelte";
  import {
    credentialChip,
    identityStatus,
    moved,
    usedBy,
    type Identity,
  } from "#lib/identities/model.ts";
  import { identities as store } from "#lib/stores/identities.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import "#lib/theme/controls.css";

  let heading = $state<HTMLElement>();
  let addOpen = $state(false);
  let deleting = $state<Identity | null>(null);
  let deleteOpen = $state(false);
  let testing = $state(false);

  const ids = $derived(store.identities.map((i) => i.id));

  onMount(() => store.start());

  async function showError(message: string) {
    toasts.push(message, { tone: "error" });
    await tick();
  }

  async function makeDefault(identity: Identity) {
    const result = await store.makeDefault(identity.id);
    if (result.ok) toasts.push(`${identity.label} is now the default.`);
    else await showError(result.message);
  }

  async function move(identity: Identity, by: -1 | 1) {
    const result = await store.reorder(moved(ids, identity.id, by));
    if (!result.ok) await showError(result.message);
    await tick();
    // A button that became disabled (the identity reached an end) hands focus to its sibling.
    const active = document.activeElement;
    if (
      !active ||
      active === document.body ||
      (active instanceof HTMLButtonElement && active.disabled)
    ) {
      document
        .querySelector(`[data-identity-id="${identity.id}"]`)
        ?.querySelector<HTMLElement>("[data-move]:not(:disabled)")
        ?.focus();
    }
  }

  async function testAll() {
    testing = true;
    try {
      await store.checkAll();
    } finally {
      testing = false;
    }
  }

  function askDelete(identity: Identity) {
    deleting = identity;
    deleteOpen = true;
  }

  async function confirmDelete() {
    const identity = deleting;
    if (!identity) return;
    const result = await store.remove(identity.id);
    if (!result.ok) return showError(result.message);
    for (const credential of identity.credentials) {
      await store.forgetToken(credential.source);
    }
    const left = result.value;
    toasts.push(
      left.length === 0
        ? `Deleted ${identity.label}.`
        : `Deleted ${identity.label}; it was taken off ${left.join(", ")}.`,
    );
    await focusHeading();
  }

  // The row the dialog was opened from is gone, so focus goes to the heading once the dialog has
  // finished giving it back.
  async function focusHeading() {
    for (let frame = 0; frame < 30; frame += 1) {
      await tick();
      if (!document.querySelector('[role="alertdialog"], [role="dialog"]'))
        break;
      await new Promise((resolve) => requestAnimationFrame(resolve));
    }
    await tick();
    heading?.focus();
  }

  function deleteDetail(identity: Identity): string {
    const names = identity.workspaces;
    return names.length === 0
      ? "No workspace uses it. Pasted tokens it holds are removed from your operating system's credential store."
      : `${names.join(", ")} will lose it and go without its credentials and author. Pasted tokens it holds are removed from your operating system's credential store.`;
  }
</script>

<div class="head">
  <div>
    <h1 tabindex="-1" bind:this={heading}>Identities</h1>
    <p class="sub">
      Who commits and signs in. An identity is a commit author plus the
      credentials puddle adds to Git requests as they leave a workspace; the
      secrets stay on this computer and never enter a workspace. A new workspace
      gets the identity that covers its repository, else the default.
    </p>
  </div>
  <div class="acts">
    <button
      type="button"
      class="btn"
      disabled={testing || store.identities.length === 0}
      onclick={testAll}>{testing ? "Testing…" : "Test all"}</button
    >
    <button type="button" class="btn primary" onclick={() => (addOpen = true)}>
      <Plus aria-hidden="true" size={16} />Add identity
    </button>
  </div>
</div>

{#if store.status === "loading"}
  <p class="muted">Loading identities&hellip;</p>
{:else if store.status === "failed"}
  <p class="muted">Couldn't read the identities yet. Trying again.</p>
{:else if store.identities.length === 0}
  <section class="empty">
    <h2>No identities yet</h2>
    <p>
      Add one to commit under your name in a workspace and to let it clone and
      push private repositories. Without one, a workspace can still read public
      repositories.
    </p>
  </section>
{:else}
  <ul class="rows" aria-label="Identities, in your order">
    {#each store.identities as identity, index (identity.id)}
      {@const status = identityStatus(
        identity.credentials.map((c) => store.checkOf(c)),
      )}
      <li class="row" data-identity-id={identity.id}>
        <div class="main">
          <div class="titleline">
            <h2><a href="/identities/{identity.id}">{identity.label}</a></h2>
            {#if identity.is_default}<span class="chip default">Default</span
              >{/if}
            {#if identity.credentials.length > 0}<CheckChip
                check={status}
              />{/if}
          </div>
          <p class="author">
            {identity.author.name} &lt;{identity.author.email}&gt;
          </p>
          {#if identity.credentials.length === 0}
            <p class="muted">No credentials: commits only.</p>
          {:else}
            <ul class="chips" aria-label="Credentials of {identity.label}">
              {#each identity.credentials as credential (credentialChip(credential))}
                <li class="chip">{credentialChip(credential)}</li>
              {/each}
            </ul>
          {/if}
          <p class="muted">{usedBy(identity)}</p>
        </div>
        <div class="acts">
          {#if !identity.is_default}
            <button
              type="button"
              class="btn"
              onclick={() => makeDefault(identity)}
              >Set {identity.label} as default</button
            >
          {/if}
          <button
            type="button"
            class="btn"
            data-move="up"
            aria-label="Move {identity.label} up"
            disabled={index === 0}
            onclick={() => move(identity, -1)}
          >
            <ArrowUp aria-hidden="true" size={16} />
          </button>
          <button
            type="button"
            class="btn"
            data-move="down"
            aria-label="Move {identity.label} down"
            disabled={index === store.identities.length - 1}
            onclick={() => move(identity, 1)}
          >
            <ArrowDown aria-hidden="true" size={16} />
          </button>
          <button
            type="button"
            class="btn deny"
            aria-label="Delete {identity.label}"
            onclick={() => askDelete(identity)}>Delete</button
          >
        </div>
      </li>
    {/each}
  </ul>
{/if}

<IdentityDialog
  bind:open={addOpen}
  mode="create"
  {store}
  onSaved={(made) => toasts.push(`Added ${made.label}.`)}
/>

{#if deleting}
  <ConfirmDialog
    bind:open={deleteOpen}
    title="Delete identity"
    summary="Delete {deleting.label}?"
    detail={deleteDetail(deleting)}
    confirmLabel="Delete {deleting.label}"
    tone="deny"
    onConfirm={confirmDelete}
  />
{/if}
<Toast />

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }
  h1 {
    font-size: var(--text-xl);
  }
  h1:focus {
    outline: none;
  }
  h2 {
    font-size: var(--text-lg);
  }
  .sub,
  .muted,
  .author {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
  }
  .sub {
    max-width: 52rem;
  }
  .author {
    color: var(--color-text);
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-2);
  }
  .rows {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .main {
    min-width: 0;
    flex: 1 1 24rem;
  }
  .titleline {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: var(--space-2) 0 0;
    padding: 0;
    list-style: none;
  }
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
  }
  .chip.default {
    color: var(--color-accent);
    border-color: var(--color-accent);
  }
  .empty {
    max-width: 40rem;
    padding: var(--space-6);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .empty p {
    margin: var(--space-2) 0 0;
    color: var(--color-text-muted);
  }
</style>
