<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { ToggleGroup } from "bits-ui";
  import { theme } from "#lib/theme/theme.svelte.ts";
  import { isThemeChoice } from "#lib/theme/theme.ts";

  const labels = { system: "System", light: "Light", dark: "Dark" } as const;
</script>

<ToggleGroup.Root
  type="single"
  class="theme-toggle"
  aria-label="Colour theme"
  value={theme.choice}
  onValueChange={(value) => {
    if (isThemeChoice(value)) theme.set(value);
  }}
>
  {#each Object.entries(labels) as [value, label] (value)}
    <ToggleGroup.Item {value} class="theme-item">{label}</ToggleGroup.Item>
  {/each}
</ToggleGroup.Root>

<style>
  :global(.theme-toggle) {
    display: flex;
    gap: var(--space-1);
    padding: var(--space-1);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  :global(.theme-item) {
    flex: 1;
    padding: var(--space-1) var(--space-2);
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-text);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
  }
  :global(.theme-item[data-state="on"]) {
    background: var(--color-accent);
    color: var(--color-accent-contrast);
  }
</style>
