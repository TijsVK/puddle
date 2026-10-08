<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import CreateWorkspaceDialog from "#lib/components/CreateWorkspaceDialog.svelte";
  import { finishFlow } from "#lib/welcome/finish.ts";
  import StepHeading from "#lib/welcome/StepHeading.svelte";
  import { around } from "#lib/welcome/steps.ts";
  import "#lib/theme/controls.css";

  let createOpen = $state(false);
  let leaving = $state(false);

  /** The flow ends here, with a workspace or without one. */
  async function finish() {
    leaving = true;
    await finishFlow();
  }
</script>

<StepHeading
  title="Your first workspace"
  lead="Optional. Give puddle the HTTPS address of a git repository and it clones it into a workspace of its own."
/>

<p class="body">
  You can also do this later from Workspaces. The workspace appears there while
  puddle prepares it.
</p>

<div class="actions">
  <a class="btn" href={around("workspace").back}>Back</a>
  <span class="grow"></span>
  <button
    type="button"
    class="btn"
    disabled={leaving}
    onclick={() => void finish()}>Skip</button
  >
  <button
    type="button"
    class="btn primary"
    disabled={leaving}
    onclick={() => (createOpen = true)}>Create a workspace</button
  >
</div>

<CreateWorkspaceDialog bind:open={createOpen} onCreated={() => void finish()} />

<style>
  .body {
    margin: 0;
    color: var(--color-text-muted);
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }
  .grow {
    flex: 1;
  }
</style>
