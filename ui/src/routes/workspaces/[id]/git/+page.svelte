<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount, tick } from "svelte";
  import { page } from "$app/state";
  import ArrowDown from "@lucide/svelte/icons/arrow-down";
  import ArrowUp from "@lucide/svelte/icons/arrow-up";
  import {
    coverageText,
    covering,
    moved,
    type Identity,
  } from "#lib/identities/model.ts";
  import { parseRepoUrl, repoName } from "#lib/identities/repo.ts";
  import { identities } from "#lib/stores/identities.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import {
    WorkspaceGitStore,
    type RepoRow,
  } from "#lib/stores/workspace-git.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import "#lib/theme/controls.css";

  const id = $derived(page.params["id"] ?? "");
  const workspace = $derived(workspaces.list.find((w) => w.id === id));
  const name = $derived(workspace?.name);
  const store = new WorkspaceGitStore();
  const fid = $props.id();

  let attachChoice = $state("");
  let identityProblem = $state<string | null>(null);
  let repoUrl = $state("");
  let newPull = $state(true);
  let newPush = $state(true);
  let repoProblem = $state<string | null>(null);
  let switchProblem = $state<string | null>(null);
  let rowProblem = $state<string | null>(null);
  let repoHeading = $state<HTMLElement>();

  onMount(() => identities.start());
  $effect(() => {
    if (name) return store.start(name);
  });

  const git = $derived(store.git);
  const attachedIds = $derived(git?.identities.map((i) => i.id) ?? []);
  const available = $derived(
    identities.identities.filter((i) => !attachedIds.includes(i.id)),
  );
  // The workspace's own repository, and whether any identity on it covers that host and owner.
  const own = $derived(workspace ? parseRepoUrl(workspace.repo_url) : null);
  const uncovered = $derived(
    git && own?.ok && covering(git.identities, own.host, own.owner) === null
      ? own
      : null,
  );

  async function attach(event: SubmitEvent) {
    event.preventDefault();
    identityProblem = null;
    const chosen = Number.parseInt(attachChoice, 10);
    if (Number.isNaN(chosen)) {
      identityProblem = "Pick an identity to add.";
      return;
    }
    const result = await store.attach(chosen);
    if (!result.ok) identityProblem = result.message;
    else attachChoice = "";
  }

  async function detach(identity: Identity) {
    identityProblem = null;
    const result = await store.detach(identity.id);
    if (!result.ok) identityProblem = result.message;
  }

  async function move(identity: Identity, by: -1 | 1) {
    identityProblem = null;
    const result = await store.setIdentities(
      moved(attachedIds, identity.id, by),
    );
    if (!result.ok) identityProblem = result.message;
    await tick();
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

  async function setSwitch(
    which: "only_push_listed" | "only_pull_listed",
    on: boolean,
  ) {
    switchProblem = null;
    const result = await store.setSwitches({ [which]: on });
    if (!result.ok) switchProblem = result.message;
  }

  async function toggle(row: RepoRow, pull: boolean, push: boolean) {
    rowProblem = null;
    const result = await store.setToggles(row, pull, push);
    if (!result.ok) rowProblem = result.message;
  }

  async function removeRow(row: RepoRow) {
    rowProblem = null;
    const result = await store.removeRepo(row);
    if (!result.ok) {
      rowProblem = result.message;
      return;
    }
    toasts.push(`Removed ${repoName(row)} from the list.`);
    await tick();
    repoHeading?.focus();
  }

  async function addRepo(event: SubmitEvent) {
    event.preventDefault();
    repoProblem = null;
    const parsed = parseRepoUrl(repoUrl);
    if (!parsed.ok) {
      repoProblem = parsed.message;
      document.getElementById(`${fid}-url`)?.focus();
      return;
    }
    const result = await store.addRepo({
      host: parsed.host,
      owner: parsed.owner,
      repo: parsed.repo,
      pull: newPull,
      push: newPush,
    });
    if (!result.ok) {
      repoProblem = result.message;
      document.getElementById(`${fid}-url`)?.focus();
      return;
    }
    toasts.push(`Listed ${repoName(parsed)}.`);
    repoUrl = "";
  }
</script>

{#if git && workspace}
  <section aria-labelledby="{fid}-ids">
    <h2 id="{fid}-ids">Identities</h2>
    <p class="muted">
      Git requests from this workspace use the credential of the identity that
      covers the repository's owner. When a repository's remotes match several
      identities, the first one here is the commit author.
    </p>
    {#if uncovered}
      <p class="warn" role="status">
        No identity here covers {uncovered.host}/{uncovered.owner}, so a private
        clone or push of this workspace's repository will fail. Add one that
        covers it, or give an identity on the
        <a href="/identities">Identities page</a> that coverage.
      </p>
    {/if}
    {#if git.identities.length === 0}
      <p class="muted">
        No identity yet. Git requests go out without a sign-in, which works for
        public repositories only.
      </p>
    {:else}
      <ol class="ids" aria-label="Identities of {workspace.name}, in order">
        {#each git.identities as identity, index (identity.id)}
          <li data-identity-id={identity.id}>
            <div class="what">
              <b><a href="/identities/{identity.id}">{identity.label}</a></b>
              <span class="muted"
                >{identity.author.name} &lt;{identity.author.email}&gt;</span
              >
              <span class="muted">
                {#if identity.credentials.length === 0}No credentials{:else}
                  {identity.credentials
                    .map((c) => `${c.host}: ${coverageText(c.covers, c.host)}`)
                    .join("; ")}{/if}
              </span>
            </div>
            <div class="acts">
              <button
                type="button"
                class="btn"
                data-move="up"
                aria-label="Move {identity.label} up"
                disabled={index === 0}
                onclick={() => move(identity, -1)}
                ><ArrowUp aria-hidden="true" size={16} /></button
              >
              <button
                type="button"
                class="btn"
                data-move="down"
                aria-label="Move {identity.label} down"
                disabled={index === git.identities.length - 1}
                onclick={() => move(identity, 1)}
                ><ArrowDown aria-hidden="true" size={16} /></button
              >
              <button
                type="button"
                class="btn"
                aria-label="Remove {identity.label} from {workspace.name}"
                onclick={() => detach(identity)}>Remove</button
              >
            </div>
          </li>
        {/each}
      </ol>
    {/if}
    <form class="attach" onsubmit={attach} novalidate>
      <div class="field">
        <label for="{fid}-attach">Add an identity</label>
        <select
          id="{fid}-attach"
          disabled={available.length === 0}
          onchange={(e) => (attachChoice = e.currentTarget.value)}
          aria-describedby={identityProblem ? `${fid}-ids-error` : undefined}
        >
          <option value="" selected={attachChoice === ""}>
            {available.length === 0
              ? identities.identities.length === 0
                ? "No identities yet"
                : "Every identity is on this workspace"
              : "Choose\u2026"}
          </option>
          {#each available as identity (identity.id)}
            <option
              value={String(identity.id)}
              selected={attachChoice === String(identity.id)}
              >{identity.label}</option
            >
          {/each}
        </select>
      </div>
      <button type="submit" class="btn" disabled={available.length === 0}
        >Add identity</button
      >
      {#if identities.identities.length === 0}
        <a href="/identities">Make an identity</a>
      {/if}
    </form>
    {#if identityProblem}
      <p class="error" id="{fid}-ids-error" role="alert">{identityProblem}</p>
    {/if}
  </section>

  <section aria-labelledby="{fid}-repos">
    <h2 id="{fid}-repos" tabindex="-1" bind:this={repoHeading}>Repositories</h2>
    <div class="switches">
      <div class="switch">
        <label>
          <input
            type="checkbox"
            role="switch"
            checked={git.only_push_listed}
            onchange={(e) => {
              const next = e.currentTarget.checked;
              e.currentTarget.checked = git.only_push_listed;
              void setSwitch("only_push_listed", next);
            }}
          />
          Only push to listed repos
        </label>
        <p class="muted">
          {git.only_push_listed
            ? "A push is allowed only to a repository whose Push box is ticked."
            : "Off: a push may go to any repository the credential can write to, and the Push boxes change nothing."}
        </p>
      </div>
      <div class="switch">
        <label>
          <input
            type="checkbox"
            role="switch"
            checked={git.only_pull_listed}
            onchange={(e) => {
              const next = e.currentTarget.checked;
              e.currentTarget.checked = git.only_pull_listed;
              void setSwitch("only_pull_listed", next);
            }}
          />
          Only pull from listed repos
        </label>
        <p class="muted">
          {git.only_pull_listed
            ? "A fetch is allowed only from a repository whose Pull box is ticked."
            : "Off: a fetch may go to any repository the credential can read, and the Pull boxes change nothing."}
        </p>
      </div>
    </div>
    {#if switchProblem}
      <p class="error" role="alert">{switchProblem}</p>
    {/if}

    {#if git.repos.length === 0}
      <p class="muted">
        No repository is listed.{git.only_push_listed
          ? " With Only push to listed repos on, nothing can be pushed."
          : ""}
      </p>
    {:else}
      <div class="wrap">
        <table aria-label="Repositories of {workspace.name}">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col" class:inactive={!git.only_pull_listed}>Pull</th>
              <th scope="col" class:inactive={!git.only_push_listed}>Push</th>
              <th scope="col"><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {#each git.repos as row (row.id)}
              <tr data-repo-id={row.id}>
                <td class="mono name">{repoName(row)}</td>
                <td>
                  <input
                    type="checkbox"
                    aria-label="Pull {repoName(row)}"
                    checked={row.pull}
                    onchange={(e) => {
                      const next = e.currentTarget.checked;
                      e.currentTarget.checked = row.pull;
                      void toggle(row, next, row.push);
                    }}
                  />
                </td>
                <td>
                  <input
                    type="checkbox"
                    aria-label="Push {repoName(row)}"
                    checked={row.push}
                    onchange={(e) => {
                      const next = e.currentTarget.checked;
                      e.currentTarget.checked = row.push;
                      void toggle(row, row.pull, next);
                    }}
                  />
                </td>
                <td class="actions">
                  <button
                    type="button"
                    class="btn"
                    aria-label="Remove {repoName(row)} from the list"
                    onclick={() => removeRow(row)}>Remove</button
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#if rowProblem}
      <p class="error" role="alert">{rowProblem}</p>
    {/if}

    <form class="add" onsubmit={addRepo} novalidate>
      <div class="field grow">
        <label for="{fid}-url">Add a repository</label>
        <input
          id="{fid}-url"
          type="text"
          inputmode="url"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          placeholder="https://github.com/owner/repo"
          bind:value={repoUrl}
          aria-invalid={repoProblem ? "true" : undefined}
          aria-describedby={repoProblem ? `${fid}-url-error` : undefined}
        />
      </div>
      <label class="choice"
        ><input type="checkbox" bind:checked={newPull} />Pull</label
      >
      <label class="choice"
        ><input type="checkbox" bind:checked={newPush} />Push</label
      >
      <button type="submit" class="btn">Add repository</button>
    </form>
    {#if repoProblem}
      <p class="error" id="{fid}-url-error" role="alert">{repoProblem}</p>
    {/if}
  </section>

  <p class="muted note">
    Credentials stay on this computer: puddle adds them to Git requests as they
    leave the workspace, and the workspace never holds them. Opening the
    workspace in desktop VS Code is different: code in it can then read the
    editor's own secrets, including a signed-in GitHub token, so only attach
    workspaces you trust. The browser editor keeps the workspace isolated.
  </p>
{:else if store.status === "failed"}
  <p class="muted">Couldn't read the Git settings yet. Trying again.</p>
{:else}
  <p class="muted">Loading Git settings&hellip;</p>
{/if}

<style>
  section {
    display: grid;
    gap: var(--space-3);
    margin-bottom: var(--space-6);
    max-width: 60rem;
  }
  h2 {
    font-size: var(--text-lg);
  }
  h2:focus {
    outline: none;
  }
  p {
    margin: 0;
  }
  .muted {
    color: var(--color-text-muted);
  }
  .note {
    max-width: 60rem;
    font-size: var(--text-sm);
  }
  .warn {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-md);
    color: var(--color-text);
  }
  .error {
    color: var(--color-danger);
    font-size: var(--text-sm);
  }
  .ids {
    display: grid;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .ids li {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .what {
    display: grid;
    gap: var(--space-1);
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-2);
  }
  .attach,
  .add {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-3);
  }
  .field {
    display: grid;
    gap: var(--space-1);
  }
  .field.grow {
    flex: 1 1 20rem;
  }
  .field label {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }
  .field input,
  .field select {
    min-height: var(--control-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  .field input[aria-invalid="true"] {
    border-color: var(--color-danger);
  }
  .choice {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--control-size);
  }
  .switches {
    display: grid;
    gap: var(--space-3);
  }
  .switch label {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: 600;
  }
  .wrap {
    overflow-x: auto;
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
  }
  th,
  td {
    padding: var(--space-1) var(--space-3);
    text-align: start;
    border-bottom: 1px solid var(--color-border-subtle);
    vertical-align: middle;
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  th.inactive {
    color: var(--color-text-muted);
    font-weight: 400;
  }
  .name {
    overflow-wrap: anywhere;
  }
  .actions {
    text-align: end;
  }
</style>
