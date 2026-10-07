<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import FormDialog from "./FormDialog.svelte";
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
    onCreated,
  }: {
    open?: boolean;
    store?: Pick<WorkspaceStore, "create">;
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
      open = false;
      reset();
      onCreated?.(result.value);
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
  .btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
