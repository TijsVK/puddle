<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import FormDialog from "./FormDialog.svelte";
  import RepoPicker from "./RepoPicker.svelte";
  import { useIdentities } from "#lib/identities/attach.ts";
  import { covering, type Identity } from "#lib/identities/model.ts";
  import { parseRepoUrl } from "#lib/identities/repo.ts";
  import {
    matchingUrl,
    tableCannotHold,
    TABLE_CANNOT_HOLD,
  } from "#lib/repos/model.ts";
  import {
    identities as identityStore,
    type IdentitiesStore,
  } from "#lib/stores/identities.svelte.ts";
  import { toasts } from "#lib/stores/toasts.svelte.ts";
  import {
    workspaces,
    type Field,
    type NewWorkspace,
    type WorkspaceStore,
  } from "#lib/stores/workspaces.svelte.ts";
  import {
    nameProblem,
    parseMemoryGib,
    repoUrlProblem,
    suggestName,
    type Workspace,
  } from "#lib/workspaces/model.ts";
  import "#lib/theme/controls.css";

  let {
    open = $bindable(false),
    store = workspaces,
    identities = identityStore,
    prefill = null,
    onCreated,
  }: {
    open?: boolean;
    store?: Pick<WorkspaceStore, "create">;
    /** The identities to offer; the screens' own store unless a test brings one. */
    identities?: Pick<IdentitiesStore, "identities" | "ensureLoaded">;
    /**
     * A repository to start from, as "Create a workspace for this" gives it: its address and the
     * identity that listed it. Give a new object each time the form should take one.
     */
    prefill?: { url: string; identity: number | null } | null;
    /** Called with the new workspace (still being created) once the service accepted it. */
    onCreated?: (workspace: Workspace) => void;
  } = $props();

  let repoUrl = $state("");
  let name = $state("");
  let nameTouched = $state(false);
  let image = $state("");
  let memoryGib = $state("");
  let errors = $state<Partial<Record<Field, string>>>({});
  let working = $state(false);
  /** The identity that listed the repository in the field, when it came from a list. */
  let listedBy = $state<number | null>(null);
  /** The identities ticked by hand for this address; `null` while the form chooses. */
  let ticked = $state<number[] | null>(null);
  let taken: typeof prefill = null;

  // Reads the identities when the form opens, so the ones that cover an address can be offered.
  $effect(() => {
    if (open) void identities.ensureLoaded();
  });

  // A repository handed in by "Create a workspace for this" fills the address once.
  $effect(() => {
    if (open && prefill && prefill !== taken) {
      taken = prefill;
      repoUrl = prefill.url;
      listedBy = prefill.identity;
      ticked = null;
    }
  });

  const offered = $derived(
    matchingUrl(identities.identities, repoUrl, listedBy),
  );
  // What the form chooses itself: the identity that listed the repository, else the one that
  // covers its owner best (as the host does when none is chosen).
  const chosenForYou = $derived.by(() => {
    const parsed = parseRepoUrl(repoUrl);
    if (!parsed.ok || offered.length === 0) return [];
    const listed = offered.find((i) => i.id === listedBy);
    const best = listed ?? covering(offered, parsed.host, parsed.owner);
    return best ? [best.id] : [];
  });
  const chosen = $derived(ticked ?? chosenForYou);

  function tick(identity: Identity, on: boolean) {
    const kept = chosen.filter((id) => id !== identity.id);
    const now = on ? [...kept, identity.id] : kept;
    ticked = offered.filter((i) => now.includes(i.id)).map((i) => i.id);
  }

  function picked(repo: { url: string }, by: number | null) {
    repoUrl = repo.url;
    listedBy = by;
    ticked = null;
    document.getElementById("new-ws-name")?.focus();
  }

  // Until the user types a name, it follows the repository.
  $effect(() => {
    if (!nameTouched) name = suggestName(repoUrl);
  });

  function reset() {
    repoUrl = "";
    name = "";
    nameTouched = false;
    image = "";
    memoryGib = "";
    errors = {};
    working = false;
    listedBy = null;
    ticked = null;
    taken = null;
  }

  function check(): Partial<Record<Field, string>> {
    const found: Partial<Record<Field, string>> = {};
    const repo = repoUrlProblem(repoUrl);
    if (repo) found.repo_url = repo;
    const label = nameProblem(name);
    if (label) found.name = label;
    const memory = parseMemoryGib(memoryGib);
    if (!memory.ok) found.memory_mib = memory.message;
    return found;
  }

  /** The host attaches one identity itself; this puts the chosen ones on the new workspace. */
  async function giveIdentities(id: string, wanted: number[]) {
    const label = (n: number) =>
      identities.identities.find((i) => i.id === n)?.label ?? `Identity ${n}`;
    const result = await useIdentities(id, wanted, label);
    if (!result.ok) {
      toasts.push(
        `The workspace was made, but its identities were not set: ${result.message} Change them on its Git tab.`,
        { tone: "error", ms: 10_000 },
      );
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (working) return;
    errors = check();
    if (Object.keys(errors).length > 0) {
      const first = (["repo_url", "name", "memory_mib"] as const).find(
        (f) => errors[f],
      );
      document.getElementById(`new-ws-${first ?? "repo_url"}`)?.focus();
      return;
    }
    const memory = parseMemoryGib(memoryGib);
    const body: NewWorkspace = {
      name,
      repo_url: repoUrl.trim(),
      ...(image.trim() === "" ? {} : { image: image.trim() }),
      ...(memory.ok && memory.mib !== null ? { memory_mib: memory.mib } : {}),
    };
    working = true;
    const result = await store.create(body);
    working = false;
    if (result.ok) {
      const identitiesWanted = [...chosen];
      const forAddress = offered.length > 0;
      open = false;
      reset();
      const warning = result.value.identity?.warning;
      if (warning) {
        // Nothing covers the repository: say which identity the workspace got and what that
        // means, and offer the tab where it is changed. The toast stays long enough to read.
        const id = result.value.id;
        toasts.push(warning, {
          tone: "error",
          ms: 20_000,
          action: {
            label: "Open Git tab",
            run: () => goto(`/workspaces/${encodeURIComponent(id)}/git`),
          },
        });
      }
      onCreated?.(result.value);
      if (forAddress) void giveIdentities(result.value.id, identitiesWanted);
      return;
    }
    const field = result.field ?? "form";
    errors = { [field]: result.message };
    if (field !== "form") document.getElementById(`new-ws-${field}`)?.focus();
  }
</script>

<FormDialog
  bind:open
  title="New workspace"
  description="puddle clones the repository into a fresh workspace with its own disk."
  onClose={reset}
>
  <form onsubmit={submit} novalidate>
    <div class="field">
      <label for="new-ws-repo_url">Git repository (HTTPS)</label>
      <input
        id="new-ws-repo_url"
        type="text"
        inputmode="url"
        autocomplete="off"
        spellcheck="false"
        placeholder="https://github.com/you/project.git"
        bind:value={repoUrl}
        oninput={() => {
          listedBy = null;
          ticked = null;
        }}
        aria-invalid={errors.repo_url ? "true" : undefined}
        aria-describedby={errors.repo_url
          ? "new-ws-repo_url-error"
          : "new-ws-repo_url-hint"}
      />
      {#if errors.repo_url}
        <p class="error" id="new-ws-repo_url-error" role="alert">
          {errors.repo_url}
        </p>
      {:else}
        <p class="hint" id="new-ws-repo_url-hint">
          SSH addresses aren't supported yet: use the HTTPS URL.
        </p>
      {/if}
    </div>

    <RepoPicker identities={identities.identities} onPick={picked} />

    {#if tableCannotHold(repoUrl)}
      <p class="hint warn" data-testid="table-cannot-hold">
        {TABLE_CANNOT_HOLD}
      </p>
    {/if}

    <div class="field">
      <label for="new-ws-name">Name</label>
      <input
        id="new-ws-name"
        type="text"
        autocomplete="off"
        spellcheck="false"
        bind:value={name}
        oninput={() => {
          nameTouched = true;
        }}
        aria-invalid={errors.name ? "true" : undefined}
        aria-describedby={errors.name
          ? "new-ws-name-error"
          : "new-ws-name-hint"}
      />
      {#if errors.name}
        <p class="error" id="new-ws-name-error" role="alert">{errors.name}</p>
      {:else}
        <p class="hint" id="new-ws-name-hint">
          Lowercase letters, digits and hyphens. It can't be changed later.
        </p>
      {/if}
    </div>

    {#if offered.length > 0}
      <fieldset class="ids">
        <legend>Git identities</legend>
        <p class="hint" id="new-ws-identities-hint">
          These identities cover this repository. The workspace signs in with
          the ones ticked; you can change them later on its Git tab.
        </p>
        {#each offered as identity (identity.id)}
          <label class="tick">
            <input
              type="checkbox"
              checked={chosen.includes(identity.id)}
              aria-describedby="new-ws-identities-hint"
              onchange={(event) => tick(identity, event.currentTarget.checked)}
            />
            <span>
              {identity.label}
              {#if identity.id === listedBy}<span class="muted"
                  >(listed this repository)</span
                >{/if}
            </span>
          </label>
        {/each}
      </fieldset>
    {/if}

    <details class="more">
      <summary>Image and memory</summary>
      <div class="field">
        <label for="new-ws-image">Image</label>
        <input
          id="new-ws-image"
          type="text"
          autocomplete="off"
          spellcheck="false"
          placeholder="Default development image"
          bind:value={image}
          aria-invalid={errors.image ? "true" : undefined}
          aria-describedby={errors.image ? "new-ws-image-error" : undefined}
        />
        {#if errors.image}
          <p class="error" id="new-ws-image-error" role="alert">
            {errors.image}
          </p>
        {/if}
      </div>
      <div class="field">
        <label for="new-ws-memory_mib">Memory (GiB)</label>
        <input
          id="new-ws-memory_mib"
          type="text"
          inputmode="decimal"
          autocomplete="off"
          placeholder="Use the default"
          bind:value={memoryGib}
          aria-invalid={errors.memory_mib ? "true" : undefined}
          aria-describedby="new-ws-memory_mib-hint"
        />
        <p
          class={errors.memory_mib ? "error" : "hint"}
          id="new-ws-memory_mib-hint"
          role={errors.memory_mib ? "alert" : undefined}
        >
          {errors.memory_mib ??
            "You can change it later; it applies at the next start."}
        </p>
      </div>
    </details>

    {#if errors.form}
      <p class="error" role="alert">{errors.form}</p>
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
      <button type="submit" class="btn primary" disabled={working}>
        {working ? "Creating…" : "Create workspace"}
      </button>
    </div>
  </form>
</FormDialog>

<style>
  .more {
    display: grid;
    gap: var(--space-3);
  }
  summary {
    cursor: pointer;
    font-weight: 600;
  }
  .more .field {
    margin-top: var(--space-3);
  }
  .ids {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  legend {
    font-weight: 600;
    padding: 0 var(--space-1);
  }
  .tick {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--control-size);
  }
  .muted {
    color: var(--color-text-muted);
  }
  .warn {
    color: var(--color-warning);
  }
  .btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
