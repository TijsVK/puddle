<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import RefreshCw from "@lucide/svelte/icons/refresh-cw";
  import RepoSourceStatus from "./RepoSourceStatus.svelte";
  import type { Identity } from "#lib/identities/model.ts";
  import {
    roleWord,
    tableCannotHold,
    TABLE_CANNOT_HOLD,
    traits,
    type RepoView,
  } from "#lib/repos/model.ts";
  import type { RepoLists } from "#lib/stores/repos.svelte.ts";
  import "#lib/theme/controls.css";

  // The repositories one identity's credentials reach, with a button on each row that opens the
  // create form for it. The lists are read on the host; a list that is slow shows progress, a list
  // that failed says why and what to do, and what a list leaves out is written beside it.
  let {
    identity,
    store,
    onCreate,
    onSignIn,
  }: {
    identity: Identity;
    store: RepoLists;
    onCreate: (repo: RepoView) => void;
    onSignIn?: ((credentialIndex: number) => void) | undefined;
  } = $props();

  let search = $state("");
  let typing: ReturnType<typeof setTimeout> | undefined;

  onMount(() => {
    void store.load({ identity: identity.id });
    return () => {
      clearTimeout(typing);
      store.stop();
    };
  });

  function onSearch() {
    clearTimeout(typing);
    typing = setTimeout(() => {
      void store.load({ identity: identity.id, query: search.trim() }, true);
    }, 250);
  }

  const listing = $derived(store.listing);
  const sources = $derived(listing?.sources ?? []);
  const repos = $derived(listing?.repos ?? []);
  const noCredentials = $derived(
    store.status === "ready" && sources.length === 0,
  );
  // Every list was read and holds nothing: say so, so an empty table is never a silent answer.
  const empty = $derived(
    store.status === "ready" &&
      sources.length > 0 &&
      listing?.total === 0 &&
      search.trim() === "" &&
      sources.every((s) => s.state === "ok" || s.state === "stale"),
  );
  const summary = $derived.by(() => {
    if (store.status === "loading" && listing === null) {
      return store.slow
        ? "Still asking your Git hosts for these lists. A long list can take half a minute."
        : "Reading the lists from your Git hosts…";
    }
    if (store.refreshing) return "Reading the lists again…";
    if (listing === null) return "";
    if (listing.total === 0) {
      return search.trim() === ""
        ? ""
        : `No repository matches “${search.trim()}”.`;
    }
    return `${listing.total} ${listing.total === 1 ? "repository" : "repositories"}${search.trim() === "" ? "" : ` match “${search.trim()}”`}.`;
  });
</script>

<div class="head">
  <p class="muted">
    puddle asks each Git host with this identity's own sign-ins, on this
    computer. Nothing is sent to a workspace.
  </p>
  <button
    type="button"
    class="btn"
    disabled={store.refreshing || store.status === "loading"}
    onclick={() => store.refresh(identity.id)}
  >
    <RefreshCw size={14} aria-hidden="true" />Refresh
  </button>
</div>

<p class="summary" role="status" data-testid="repo-summary">{summary}</p>

{#if store.message}
  <p class="problem" role="alert">
    {store.message}
    {#if listing !== null}The list below is from the last read.{/if}
  </p>
{/if}

{#if sources.length > 0}
  <ul class="sources" aria-label="How current each list is">
    {#each sources as source (`${source.credential}|${source.organisation}`)}
      <RepoSourceStatus {source} {identity} now={store.now} {onSignIn} />
    {/each}
  </ul>
{/if}

{#if noCredentials}
  <p class="muted" data-testid="repo-no-credentials">
    This identity has no credential, so there is nothing to list. Edit the
    identity and add a sign-in or a token.
  </p>
{:else if empty}
  <p class="muted" data-testid="repo-empty">
    This identity's account reaches no repository. If you expected some, check
    that the sign-in belongs to the right account (Test, above), or that the
    organisation has approved it.
  </p>
{:else if listing !== null && (listing.total > 0 || search.trim() !== "")}
  <div class="search">
    <label for="repo-search">Search these repositories</label>
    <input
      id="repo-search"
      type="search"
      autocomplete="off"
      spellcheck="false"
      placeholder="Part of a name, such as acme web"
      bind:value={search}
      oninput={onSearch}
    />
  </div>
  {#if repos.length > 0}
    <table aria-label="Repositories {identity.label} can reach">
      <thead>
        <tr>
          <th scope="col">Repository</th>
          <th scope="col">Your role</th>
          <th scope="col"><span class="visually-hidden">Create</span></th>
        </tr>
      </thead>
      <tbody>
        {#each repos as repo (repo.url)}
          <tr data-repo={repo.full_name}>
            <td>
              <span class="name mono">{repo.full_name}</span>
              <span class="traits">
                {#each traits(repo) as trait (trait)}<span class="trait"
                    >{trait}</span
                  >{/each}
              </span>
              {#if tableCannotHold(repo.url)}
                <span class="warn" data-testid="repo-table-warning"
                  >{TABLE_CANNOT_HOLD}</span
                >
              {/if}
            </td>
            <td class="muted">{roleWord(repo.role)}</td>
            <td class="act">
              <button
                type="button"
                class="btn primary"
                aria-label="Create a workspace for {repo.full_name}"
                onclick={() => onCreate(repo)}
                >Create a workspace for this</button
              >
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if listing.repos.length < listing.total}
      <button
        type="button"
        class="btn more"
        disabled={store.loadingMore}
        onclick={() => store.more()}
        >Show more ({listing.total - listing.repos.length} left)</button
      >
    {/if}
  {/if}
{/if}

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-3);
    margin-bottom: var(--space-2);
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .head p {
    flex: 1 1 20rem;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .summary {
    min-height: 1.5em;
    color: var(--color-text-muted);
  }
  .problem {
    color: var(--color-danger);
    margin-bottom: var(--space-2);
  }
  .sources {
    display: grid;
    gap: var(--space-2);
    margin: var(--space-2) 0 var(--space-4);
    padding: 0;
  }
  .search {
    display: grid;
    gap: var(--space-1);
    max-width: 28rem;
    margin-bottom: var(--space-3);
  }
  input {
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th {
    text-align: left;
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    padding: var(--space-1) var(--space-2);
  }
  td {
    padding: var(--space-2);
    border-top: 1px solid var(--color-border-subtle);
    vertical-align: top;
  }
  td:first-child {
    display: grid;
    gap: var(--space-1);
    overflow-wrap: anywhere;
  }
  .traits {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
  }
  .trait {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .warn {
    font-size: var(--text-sm);
    color: var(--color-warning);
  }
  .act {
    text-align: right;
  }
  .more {
    margin-top: var(--space-3);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  .btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
