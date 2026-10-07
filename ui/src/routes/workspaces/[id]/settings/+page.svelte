<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { page } from "$app/state";
  import { LOCAL_LABELS, type LocalCategory } from "#lib/decision/local.ts";
  import { WorkspaceSettings } from "#lib/stores/workspace-settings.svelte.ts";
  import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";
  import {
    DIRECT_SSH_HINT,
    DIRECT_SSH_LABEL,
  } from "#lib/workspaces/direct-ssh.ts";
  import {
    clipboardOptions,
    memoryFromChoice,
    memoryOptions,
    memoryToChoice,
    sourceLabel,
    toggleFromChoice,
    toggleOptions,
    toggleToChoice,
    type Clipboard,
    type Layer,
  } from "#lib/workspaces/settings.ts";
  import "#lib/theme/controls.css";

  const id = $derived(page.params["id"] ?? "");
  const workspace = $derived(workspaces.list.find((w) => w.id === id));
  const settings = new WorkspaceSettings();

  let saved = $state<string | null>(null);
  let problem = $state<string | null>(null);
  let restartHint = $state(false);

  // Reload only for another workspace, not on every status change of this one.
  const name = $derived(workspace?.name);
  $effect(() => {
    if (name) void settings.load(name);
  });

  // Direct SSH can change from the connect step too: read the overrides again when it does.
  const directSsh = $derived(workspace?.direct_ssh);
  let lastDirectSsh: boolean | undefined;
  $effect(() => {
    const now = directSsh;
    if (lastDirectSsh !== undefined && now !== lastDirectSsh && name) {
      void settings.load(name, true);
    }
    lastDirectSsh = now;
  });

  const CATEGORIES: LocalCategory[] = [
    "loopback",
    "private",
    "link_local",
    "metadata",
    "special",
  ];

  /** Saves; on a refusal the select goes back to what is stored (`undo` puts it there). */
  async function save(patch: Partial<Layer>, what: string, undo: () => void) {
    saved = null;
    problem = null;
    const result = await settings.change(patch);
    if (result.ok) {
      saved = `${what} saved.`;
    } else {
      problem = result.message;
      undo();
    }
    return result.ok;
  }

  async function saveMemory(select: HTMLSelectElement) {
    const ok = await save(
      { memory: memoryFromChoice(select.value) },
      "Memory",
      () => {
        select.value = memoryToChoice(settings.overrides?.memory ?? null);
      },
    );
    restartHint = ok && workspace?.status === "running";
  }

  async function saveToggle(
    category: LocalCategory,
    select: HTMLSelectElement,
  ) {
    const current = settings.overrides?.local_toggles;
    if (!current) return;
    await save(
      {
        local_toggles: {
          ...current,
          [category]: toggleFromChoice(select.value),
        },
      },
      LOCAL_LABELS[category],
      () => {
        select.value = toggleToChoice(current[category]);
      },
    );
  }

  /** Off and "follow the global default" save at once; on asks the trust text first. */
  async function saveDirectSsh(select: HTMLSelectElement) {
    const choice = toggleFromChoice(select.value);
    if (choice === true && workspace) {
      select.value = toggleToChoice(settings.overrides?.direct_ssh ?? null);
      actions.requestDirectSsh(workspace, true);
      return;
    }
    const ok = await save({ direct_ssh: choice }, DIRECT_SSH_LABEL, () => {
      select.value = toggleToChoice(settings.overrides?.direct_ssh ?? null);
    });
    if (ok) await workspaces.refresh();
  }

  async function saveClipboard(select: HTMLSelectElement) {
    await save(
      {
        clipboard_read:
          select.value === "inherit" ? null : (select.value as Clipboard),
      },
      "Clipboard",
      () => {
        select.value = settings.overrides?.clipboard_read ?? "inherit";
      },
    );
  }
</script>

{#if workspace}
  {#if settings.status === "loading"}
    <p class="muted">Loading settings&hellip;</p>
  {:else if settings.status === "failed" || !settings.overrides || !settings.effective || !settings.global}
    <p class="muted">Couldn't read this workspace's settings.</p>
  {:else}
    {@const overrides = settings.overrides}
    {@const effective = settings.effective}
    {@const global = settings.global}
    <p class="intro">
      These settings belong to <b>{workspace.name}</b>. Each one can follow the
      global setting or be set here.
    </p>

    <div class="status" aria-live="polite">
      {#if saved}<p class="saved">{saved}</p>{/if}
      {#if problem}<p class="error" role="alert">{problem}</p>{/if}
      {#if restartHint}
        <p>The new memory applies the next time the workspace starts.</p>
      {/if}
    </div>

    <section class="card" aria-labelledby="memory-h">
      <h2 id="memory-h">Memory</h2>
      <div class="setting">
        <div class="grow">
          <label for="ws-memory">Memory for this workspace</label>
          <p class="desc" id="ws-memory-desc">
            A change applies at the next restart. Now in effect:
            {effective.memory.value} MiB
            <span class="chip">{sourceLabel(effective.memory.source)}</span>
          </p>
        </div>
        <select
          id="ws-memory"
          aria-describedby="ws-memory-desc"
          value={memoryToChoice(overrides.memory)}
          onchange={(e) => void saveMemory(e.currentTarget)}
        >
          {#each memoryOptions(overrides.memory, global.memory.value) as option (option.value)}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
    </section>

    <section class="card" aria-labelledby="local-h" id="local-destinations">
      <h2 id="local-h">Local destinations</h2>
      <p class="desc">
        Whether requests to this computer and to private networks may be
        approved. Off by default; a request still needs your approval.
      </p>
      {#each CATEGORIES as category (category)}
        <div class="setting">
          <div class="grow">
            <label for="ws-local-{category}">{LOCAL_LABELS[category]}</label>
            <p class="desc">
              <span class="chip"
                >{sourceLabel(effective.local_toggles[category].source)}</span
              >
            </p>
          </div>
          <select
            id="ws-local-{category}"
            value={toggleToChoice(overrides.local_toggles[category])}
            onchange={(e) => void saveToggle(category, e.currentTarget)}
          >
            {#each toggleOptions(global.local_toggles[category].value) as option (option.value)}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
        </div>
      {/each}
    </section>

    <section class="card" aria-labelledby="ssh-h">
      <h2 id="ssh-h">Direct SSH</h2>
      <div class="setting">
        <div class="grow">
          <label for="ws-direct-ssh">{DIRECT_SSH_LABEL}</label>
          <p class="desc" id="ws-direct-ssh-desc">
            {DIRECT_SSH_HINT} While it is off, puddle opens no SSH way in and writes
            no ssh config entry. It applies at once.
            <span class="chip">{sourceLabel(effective.direct_ssh.source)}</span>
          </p>
        </div>
        <select
          id="ws-direct-ssh"
          aria-describedby="ws-direct-ssh-desc"
          value={toggleToChoice(overrides.direct_ssh)}
          onchange={(e) => void saveDirectSsh(e.currentTarget)}
        >
          {#each toggleOptions(global.direct_ssh.value) as option (option.value)}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
    </section>

    <section class="card" aria-labelledby="clip-h">
      <h2 id="clip-h">Clipboard</h2>
      <div class="setting">
        <div class="grow">
          <label for="ws-clipboard">Pages reading the clipboard</label>
          <p class="desc">
            When a page in this workspace's browser window reads the clipboard
            from a script.
            <span class="chip"
              >{sourceLabel(effective.clipboard_read.source)}</span
            >
          </p>
        </div>
        <select
          id="ws-clipboard"
          value={overrides.clipboard_read ?? "inherit"}
          onchange={(e) => void saveClipboard(e.currentTarget)}
        >
          {#each clipboardOptions(global.clipboard_read.value) as option (option.value)}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
    </section>
  {/if}
{/if}

<style>
  .intro,
  .muted {
    margin: 0 0 var(--space-3);
    color: var(--color-text-muted);
  }
  .status {
    min-height: 1.5rem;
    margin-bottom: var(--space-2);
  }
  .status p {
    margin: 0;
  }
  .saved {
    color: var(--color-success);
  }
  .error {
    color: var(--color-danger);
  }
  .card {
    display: grid;
    gap: var(--space-3);
    max-width: 48rem;
    margin-bottom: var(--space-4);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  h2 {
    font-size: var(--text-md);
  }
  .setting {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  label {
    font-weight: 600;
  }
  .desc {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  .chip {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-pill);
    white-space: nowrap;
  }
  select {
    min-height: 2rem;
    max-width: 18rem;
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font: inherit;
  }
  @media (max-width: 760px) {
    .setting {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
