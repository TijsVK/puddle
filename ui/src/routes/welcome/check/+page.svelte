<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import { doctor } from "#lib/stores/doctor.svelte.ts";
  import StatusMark from "#lib/welcome/StatusMark.svelte";
  import StepHeading from "#lib/welcome/StepHeading.svelte";
  import {
    copyText,
    isBlocked,
    reportText,
    took,
    verdict,
  } from "#lib/welcome/doctor.ts";
  import { around } from "#lib/welcome/steps.ts";
  import "#lib/theme/controls.css";

  // Opened from Settings the page is the system check on its own, with a way back there.
  const fromSettings = $derived(
    page.url.searchParams.get("from") === "settings",
  );
  const report = $derived(doctor.report);
  const running = $derived(doctor.status === "running");
  const blocked = $derived(report !== null && isBlocked(report));
  let copied = $state<"yes" | "no" | null>(null);

  onMount(() => {
    // Back from a later step keeps the result; opened from Settings it always runs afresh.
    if (doctor.status === "idle" || fromSettings) void doctor.run();
  });

  async function copy() {
    if (!report) return;
    copied = (await copyText(reportText(report))) ? "yes" : "no";
  }

  function again() {
    copied = null;
    void doctor.run();
  }
</script>

<StepHeading
  title="System check"
  lead="puddle checks what it needs on this computer. Nothing here needs administrator rights."
/>

<div class="status" aria-live="polite">
  {#if running}
    <p class="muted">
      Checking this computer. This takes a few seconds&hellip;
    </p>
  {:else if doctor.status === "unavailable"}
    <p class="muted">
      This puddle can't run the system check, so there is nothing to show here.
      You can go on.
    </p>
  {:else if doctor.status === "failed"}
    <p class="error" role="alert">
      puddle couldn't run the system check: {doctor.problem}
    </p>
  {/if}
</div>

{#if report}
  <ul class="checks" aria-label="Checks">
    {#each report.checks as check (check.id)}
      <li class="check {check.status}">
        <StatusMark status={check.status} />
        <div class="what">
          <p class="title">{check.title}</p>
          <p class="muted">{check.summary}</p>
          {#if check.fix}
            <p class="fix">
              <b>{check.status === "fail" ? "Fix:" : "Note:"}</b>
              {check.fix}
            </p>
          {/if}
          {#if check.detail}
            <details>
              <summary>Technical details</summary>
              <!-- A scrollable region must be reachable by keyboard. -->
              <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
              <pre
                tabindex="0"
                aria-label="Technical details of {check.title}">{check.detail}</pre>
            </details>
          {/if}
        </div>
      </li>
    {/each}
  </ul>
  <p class="verdict" class:error={blocked} role={blocked ? "alert" : "status"}>
    {verdict(report)}
    <span class="muted">Checked in {took(report)}.</span>
  </p>
  {#if copied === "yes"}
    <p class="muted" role="status">Report copied.</p>
  {:else if copied === "no"}
    <p class="error" role="alert">
      The browser didn't let puddle copy. Select the technical details instead.
    </p>
  {/if}
{/if}

<div class="actions">
  {#if !fromSettings}
    <a class="btn" href={around("check").back}>Back</a>
  {/if}
  <span class="grow"></span>
  <button type="button" class="btn" disabled={running} onclick={again}
    >Check again</button
  >
  {#if report}
    <button type="button" class="btn" onclick={() => void copy()}
      >Copy report</button
    >
  {/if}
  {#if fromSettings}
    <a class="btn primary" href="/settings">Back to Settings</a>
  {:else if blocked}
    <a class="btn" href="/workspaces">Leave setup for now</a>
  {:else if running}
    <button type="button" class="btn primary" disabled>Continue</button>
  {:else}
    <a class="btn primary" href={around("check").next}>Continue</a>
  {/if}
</div>
{#if blocked && !fromSettings}
  <p class="muted">
    puddle can't run workspaces here until the problems are fixed. Setup comes
    back the next time you open puddle, or run the check again from Settings.
  </p>
{/if}

<style>
  .muted {
    margin: 0;
    color: var(--color-text-muted);
  }
  .error {
    margin: 0;
    color: var(--color-danger);
  }
  .status {
    min-height: 1.5rem;
  }
  .status p {
    margin: 0;
  }
  .checks {
    margin: 0;
    padding: 0 var(--space-4);
    list-style: none;
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .check {
    display: flex;
    gap: var(--space-3);
    padding: var(--space-3) 0;
    border-bottom: 1px solid var(--color-border-subtle);
  }
  .check:last-child {
    border-bottom: 0;
  }
  .what {
    min-width: 0;
    display: grid;
    gap: var(--space-1);
  }
  .title {
    margin: 0;
    font-weight: 600;
  }
  .fix {
    margin: var(--space-1) 0 0;
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface-raised);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
  }
  pre {
    margin: var(--space-1) 0 0;
    padding: var(--space-2) var(--space-3);
    max-height: 12rem;
    overflow: auto;
    background: var(--color-bg);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .verdict {
    margin: 0;
    font-weight: 600;
  }
  .verdict .muted {
    font-weight: 400;
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
