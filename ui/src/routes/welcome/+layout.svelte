<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { page } from "$app/state";
  import { APP_NAME } from "#lib/nav.ts";
  import { STEPS, stepFor } from "#lib/welcome/steps.ts";

  let { children } = $props();

  const at = $derived(
    STEPS.findIndex((step) => step.id === stepFor(page.url.pathname)?.id),
  );
  // The system check is also reached from Settings, outside the flow: no step bar there.
  const inFlow = $derived(page.url.searchParams.get("from") !== "settings");
</script>

<div class="welcome">
  <p class="brand">{APP_NAME}</p>
  {#if inFlow}
    <ol class="steps" aria-label="Setup steps">
      {#each STEPS as step, index (step.id)}
        <li
          class:done={index < at}
          class:current={index === at}
          aria-current={index === at ? "step" : undefined}
        >
          <span class="number" aria-hidden="true">{index + 1}</span>
          {step.label}{#if index < at}<span class="visually-hidden">, done</span
            >{/if}
        </li>
      {/each}
    </ol>
  {/if}
  <div class="step">
    {@render children()}
  </div>
</div>

<style>
  .welcome {
    max-width: 52rem;
    margin: 0 auto;
    display: grid;
    gap: var(--space-4);
  }
  .brand {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: 600;
  }
  .steps {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .steps li {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-pill);
    background: var(--color-surface-raised);
    color: var(--color-text-muted);
    font-size: var(--text-sm);
    font-weight: 600;
  }
  .steps li.done {
    color: var(--color-success);
  }
  .steps li.current {
    background: var(--color-accent);
    color: var(--color-accent-contrast);
  }
  .step {
    display: grid;
    gap: var(--space-4);
  }
  .welcome :global(.btn:disabled) {
    opacity: 0.6;
    cursor: default;
  }
  @media (max-width: 760px) {
    .steps li .number {
      display: none;
    }
  }
</style>
