<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { finishFlow } from "#lib/welcome/finish.ts";
  import StepHeading from "#lib/welcome/StepHeading.svelte";
  import { around } from "#lib/welcome/steps.ts";
  import "#lib/theme/controls.css";

  let leaving = $state(false);

  /** Ends the flow here: it is not shown again. The check and the settings stay reachable. */
  async function skip() {
    leaving = true;
    await finishFlow();
  }
</script>

<StepHeading title="Welcome to puddle" />
<p class="body">
  Your code runs in a small virtual machine per workspace. Nothing leaves it
  unless you allow the host, and every connection is logged.
</p>
<p class="body">
  The next steps take about a minute: a check of this computer, certificates,
  how you want to connect, and your first workspace.
</p>
<div class="actions">
  <button
    type="button"
    class="btn"
    disabled={leaving}
    onclick={() => void skip()}>Skip setup</button
  >
  <a class="btn primary" href={around("welcome").next}>Get started</a>
</div>

<style>
  .body {
    margin: 0;
    max-width: 40rem;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
