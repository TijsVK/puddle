<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import RepoSourceStatus from "./RepoSourceStatus.svelte";
  import type { Identity } from "#lib/identities/model.ts";
  import {
    roleWord,
    tableCannotHold,
    traits,
    type RepoView,
  } from "#lib/repos/model.ts";
  import { RepoLists } from "#lib/stores/repos.svelte.ts";
  import "#lib/theme/controls.css";

  // The create form's list of repositories you can reach: a search over every identity's lists,
  // under the address field. Picking a repository fills the address and tells the form which
  // identity listed it. A typed address still works without it.
  let {
    identities,
    onPick,
    store = new RepoLists(),
  }: {
    identities: readonly Identity[];
    onPick: (repo: RepoView, listedBy: number | null) => void;
    store?: RepoLists;
  } = $props();

  let opened = $state(false);
  let search = $state("");
  let typing: ReturnType<typeof setTimeout> | undefined;

  function toggled(event: Event) {
    opened = (event.currentTarget as HTMLDetailsElement).open;
    if (opened && store.status === "idle") void store.load({ limit: 20 });
    if (!opened) {
      clearTimeout(typing);
      store.stop();
    }
  }

  function onSearch() {
    clearTimeout(typing);
    typing = setTimeout(() => {
      void store.load({ query: search.trim(), limit: 20 }, true);
    }, 250);
  }

  $effect(() => () => {
    clearTimeout(typing);
    store.stop();
  });

  const listing = $derived(store.listing);
  const sources = $derived(listing?.sources ?? []);
  const repos = $derived(listing?.repos ?? []);
  const label = (id: number) =>
    identities.find((i) => i.id === id)?.label ?? `Identity ${id}`;
  const summary = $derived.by(() => {
    if (store.status === "loading" && listing === null) {
      return store.slow
        ? "Still asking your Git hosts. A long list can take half a minute."
        : "Reading the lists from your Git hosts…";
    }
    if (listing === null) return "";
    if (listing.total === 0) {
      return search.trim() === ""
        ? "None of your identities reaches a repository yet."
        : `No repository matches “${search.trim()}”.`;
    }
    return listing.total > repos.length
      ? `Showing ${repos.length} of ${listing.total}. Type more of the name to narrow it.`
      : `${listing.total} ${listing.total === 1 ? "repository" : "repositories"}.`;
  });
  const trouble = $derived(
    sources.filter(
      (s) => s.problem !== null || s.notes.length > 0 || s.state !== "ok",
    ),
  );
</script>

<details class="picker" ontoggle={toggled}>
  <summary>Choose from your repositories</summary>
  {#if opened}
    <div class="body">
      <div class="field">
        <label for="repo-pick-search">Search your repositories</label>
        <input
          id="repo-pick-search"
          type="search"
          autocomplete="off"
          spellcheck="false"
          placeholder="Part of a name, such as acme web"
          bind:value={search}
          oninput={onSearch}
        />
      </div>
      <p class="summary" role="status">{summary}</p>
      {#if store.message}
        <p class="problem" role="alert">{store.message}</p>
      {/if}
      {#if repos.length > 0}
        <ul class="repos" aria-label="Your repositories">
          {#each repos as repo (repo.url)}
            <li>
              <button
                type="button"
                class="pick"
                onclick={() => onPick(repo, repo.identities[0] ?? null)}
              >
                <span class="name mono">{repo.full_name}</span>
                <span class="meta">
                  {[
                    ...traits(repo),
                    roleWord(repo.role),
                    `listed by ${repo.identities.map(label).join(", ")}`,
                  ]
                    .filter((word) => word !== "")
                    .join(" · ")}
                </span>
                {#if tableCannotHold(repo.url)}
                  <span class="meta warn"
                    >Its project name has a space: you can still make a
                    workspace, but its repository table can't hold it.</span
                  >
                {/if}
              </button>
            </li>
          {/each}
        </ul>
      {/if}
      {#if trouble.length > 0}
        <ul class="sources" aria-label="How current each list is">
          {#each trouble as source (`${source.identity_id}|${source.credential}|${source.organisation}`)}
            <RepoSourceStatus
              {source}
              identity={identities.find((i) => i.id === source.identity_id)}
              now={store.now}
            />
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</details>

<style>
  .picker {
    display: grid;
    gap: var(--space-2);
  }
  summary {
    cursor: pointer;
    font-weight: 600;
  }
  .body {
    display: grid;
    gap: var(--space-2);
    margin-top: var(--space-2);
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .summary {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  .problem {
    color: var(--color-danger);
  }
  .repos,
  .sources {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .repos {
    max-height: 14rem;
    overflow-y: auto;
  }
  .pick {
    display: grid;
    gap: 0;
    width: 100%;
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-3);
    text-align: left;
    background: var(--color-surface);
    color: var(--color-text);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
    font: inherit;
    cursor: pointer;
    overflow-wrap: anywhere;
  }
  .pick:hover {
    background: var(--color-surface-raised);
  }
  .meta {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .warn {
    color: var(--color-warning);
  }
</style>
