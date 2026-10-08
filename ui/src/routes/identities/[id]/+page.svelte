<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { onMount, tick } from "svelte";
  import CheckChip from "#lib/components/CheckChip.svelte";
  import ConfirmDialog from "#lib/components/ConfirmDialog.svelte";
  import IdentityDialog from "#lib/components/IdentityDialog.svelte";
  import SignInDialog from "#lib/components/SignInDialog.svelte";
  import Toast from "#lib/components/Toast.svelte";
  import {
    coverageText,
    describeSource,
    sourceLabel,
    usedBy,
    type Credential,
  } from "#lib/identities/model.ts";
  import {
    identities as store,
    type SignInStart,
  } from "#lib/stores/identities.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import "#lib/theme/controls.css";

  const identity = $derived(
    store.byId(Number.parseInt(page.params["id"] ?? "", 10)),
  );
  let heading = $state<HTMLElement>();
  let editOpen = $state(false);
  let deleteOpen = $state(false);
  let signInOpen = $state(false);
  let signingIn = $state<Credential | null>(null);
  let started = $state<SignInStart | null>(null);
  let startError = $state<string | null>(null);

  // An identity that was here and is gone (deleted here or elsewhere) takes you back to the list.
  let seen = false;
  $effect(() => {
    if (identity) seen = true;
    else if (seen && store.status === "ready") void goto("/identities");
  });

  onMount(() => store.start());

  async function test(credential: Credential) {
    await store.check(credential);
  }

  // The click on Sign in is what starts it; nothing else does.
  async function signIn(credential: Credential) {
    signingIn = credential;
    started = null;
    startError = null;
    signInOpen = true;
    const result = await store.signIn(credential.source);
    if (result.ok) started = result.value;
    else startError = result.message;
  }

  async function makeDefault() {
    if (!identity) return;
    const result = await store.makeDefault(identity.id);
    toasts.push(
      result.ok ? `${identity.label} is now the default.` : result.message,
      result.ok ? {} : { tone: "error" },
    );
  }

  async function confirmDelete() {
    if (!identity) return;
    const gone = identity;
    const result = await store.remove(gone.id);
    if (!result.ok) {
      toasts.push(result.message, { tone: "error" });
      return;
    }
    for (const credential of gone.credentials) {
      await store.forgetToken(credential.source);
    }
    toasts.push(`Deleted ${gone.label}.`);
    await goto("/identities");
  }

  async function afterSave() {
    await tick();
    heading?.focus();
  }
</script>

{#if identity}
  <div class="head">
    <div>
      <p class="crumb"><a href="/identities">Identities</a> /</p>
      <h1 tabindex="-1" bind:this={heading}>{identity.label}</h1>
      <p class="muted">
        {#if identity.is_default}Default &middot;
        {/if}{usedBy(identity)}
      </p>
    </div>
    <div class="acts">
      {#if !identity.is_default}
        <button type="button" class="btn" onclick={makeDefault}
          >Set as default</button
        >
      {/if}
      <button type="button" class="btn" onclick={() => (editOpen = true)}
        >Edit</button
      >
      <button type="button" class="btn deny" onclick={() => (deleteOpen = true)}
        >Delete</button
      >
    </div>
  </div>

  <section aria-labelledby="author">
    <h2 id="author">Commit author</h2>
    <p>{identity.author.name} &lt;{identity.author.email}&gt;</p>
  </section>

  <section aria-labelledby="credentials">
    <h2 id="credentials">Credentials</h2>
    {#if identity.credentials.length === 0}
      <p class="muted">
        None. Git requests from this identity's workspaces go out without a
        sign-in. Edit the identity to add one.
      </p>
    {:else}
      <ul class="creds">
        {#each identity.credentials as credential (describeSource(credential.source))}
          {@const check = store.checkOf(credential)}
          <li class="cred" data-credential={describeSource(credential.source)}>
            <div class="what">
              <p class="line">
                <b>{sourceLabel(credential.source)}</b>
                <span class="mono">{credential.host}</span>
                <CheckChip {check} />
              </p>
              <p class="muted">
                Covers {coverageText(credential.covers, credential.host)}
              </p>
              {#if check.state === "problem"}
                <p class="problem" role="status">{check.message}</p>
              {:else if check.state === "ok"}
                <p class="muted" role="status">
                  puddle can read it. (It checks that a token comes back, and
                  never shows it.)
                </p>
              {/if}
            </div>
            <div class="acts">
              <button
                type="button"
                class="btn"
                disabled={check.state === "checking"}
                aria-label="Test {sourceLabel(
                  credential.source,
                )} on {credential.host}"
                onclick={() => test(credential)}>Test</button
              >
              {#if credential.source.kind !== "stored" && check.state === "problem" && check.needsSignIn}
                <button
                  type="button"
                  class="btn primary"
                  aria-label="Sign in to {sourceLabel(
                    credential.source,
                  )} on {credential.host}"
                  onclick={() => signIn(credential)}>Sign in&hellip;</button
                >
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <!-- A later task lists the repositories this identity can reach here, with "Create a workspace
       for this" on each row; the section is its place. -->
  <section aria-labelledby="repos" id="repos" data-testid="identity-repos">
    <h2 id="repos">Repos it can reach</h2>
    <p class="muted">This list is not available yet.</p>
  </section>

  <section aria-labelledby="workspaces">
    <h2 id="workspaces">Workspaces that use it</h2>
    {#if identity.workspaces.length === 0}
      <p class="muted">None yet.</p>
    {:else}
      <ul class="plain">
        {#each identity.workspaces as name (name)}
          <li>
            <a href="/workspaces/{encodeURIComponent(name)}/git">{name}</a>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <IdentityDialog
    bind:open={editOpen}
    mode="edit"
    {identity}
    {store}
    onSaved={() => {
      toasts.push(`Saved ${identity.label}.`);
      void afterSave();
    }}
  />
  <ConfirmDialog
    bind:open={deleteOpen}
    title="Delete identity"
    summary="Delete {identity.label}?"
    detail={identity.workspaces.length === 0
      ? "No workspace uses it. Pasted tokens it holds are removed from your operating system's credential store."
      : `${identity.workspaces.join(", ")} will lose it and go without its credentials and author. Pasted tokens it holds are removed from your operating system's credential store.`}
    confirmLabel="Delete {identity.label}"
    tone="deny"
    onConfirm={confirmDelete}
  />
  <SignInDialog
    bind:open={signInOpen}
    credential={signingIn}
    start={started}
    error={startError}
    {store}
  />
{:else if store.status === "ready"}
  <h1>No such identity</h1>
  <p class="muted">
    There is no identity with that number. <a href="/identities"
      >Back to the identities</a
    >.
  </p>
{:else if store.status === "failed"}
  <p class="muted">Couldn't read the identity yet. Trying again.</p>
{:else}
  <p class="muted">Loading identity&hellip;</p>
{/if}
<Toast />

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }
  .crumb {
    margin: 0;
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  h1 {
    font-size: var(--text-xl);
    overflow-wrap: anywhere;
  }
  h1:focus {
    outline: none;
  }
  h2 {
    font-size: var(--text-lg);
    margin-bottom: var(--space-2);
  }
  section {
    margin-bottom: var(--space-6);
  }
  p {
    margin: 0;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-2);
  }
  .creds,
  .plain {
    display: grid;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .cred {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .what {
    display: grid;
    gap: var(--space-1);
    min-width: 0;
    flex: 1 1 20rem;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .problem {
    color: var(--color-danger);
  }
</style>
