<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import type { Identity } from "#lib/identities/model.ts";
  import {
    credentialOf,
    freshness,
    retryText,
    sourceTitle,
    type RepoSource,
  } from "#lib/repos/model.ts";
  import "#lib/theme/controls.css";

  // How current one credential's list is, and what it leaves out or why it failed. The host's
  // notes and problem text is untrusted: it is rendered as text only. The state is a word, so the
  // colour only repeats it.
  let {
    source,
    identity,
    now,
    onSignIn,
  }: {
    source: RepoSource;
    identity: Identity | undefined;
    now: number;
    /** Starts the credential's sign-in (the identity page's own button); left out where there is none. */
    onSignIn?: ((credentialIndex: number) => void) | undefined;
  } = $props();

  const WORDS = {
    ok: "Up to date",
    stale: "Old list",
    failed: "Not read",
    unavailable: "Can't be listed",
  } as const;

  const title = $derived(sourceTitle(source, identity));
  const waiting = $derived(retryText(source, now));
  const canSignIn = $derived(
    source.problem?.needs_sign_in === true &&
      onSignIn !== undefined &&
      credentialOf(source, identity)?.source.kind !== "stored",
  );
</script>

<li class="source" data-list-state={source.state}>
  <p class="line">
    <b>{title}</b>
    <span class="state {source.state}">{WORDS[source.state]}</span>
  </p>
  <p class="muted">
    {freshness(source, now)}
    {#if waiting}{waiting}{/if}
  </p>
  {#if source.problem}
    <p class="problem">
      {source.problem.message}
      {#if canSignIn}
        <button
          type="button"
          class="btn"
          aria-label="Sign in to {title}"
          onclick={() => onSignIn?.(source.credential)}>Sign in&hellip;</button
        >
      {/if}
    </p>
  {/if}
  {#each source.notes as note (note.code)}
    <p class="note">{note.message}</p>
  {/each}
</li>

<style>
  .source {
    display: grid;
    gap: var(--space-1);
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    list-style: none;
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .muted,
  .note {
    color: var(--color-text-muted);
  }
  .problem {
    color: var(--color-danger);
  }
  .state {
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
  .stale {
    color: var(--color-warning);
    border-color: var(--color-warning);
  }
  .failed,
  .unavailable {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }
</style>
