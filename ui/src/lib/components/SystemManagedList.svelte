<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    SYSTEM_INTRO,
    byReason,
    entryPattern,
    systemScope,
    type SystemHost,
  } from "#lib/rules/sets.ts";

  // What puddle allows by itself, because of choices you made: each host with its reason and
  // where it applies (rules spec R-40). Read-only.
  let { hosts }: { hosts: SystemHost[] } = $props();

  const id = $props.id();
  const groups = $derived(byReason(hosts));
</script>

<section aria-labelledby="{id}-title" class="system">
  <h2 id="{id}-title">System managed</h2>
  <p class="sub">{SYSTEM_INTRO}</p>
  {#if groups.length === 0}
    <p class="muted">Puddle allows nothing by itself right now.</p>
  {:else}
    {#each groups as group (`${group.reason}/${group.workspace ?? ""}`)}
      <div class="group">
        <p>
          <b>{group.text}</b>
          <span class="muted">Applies to: {systemScope(group)}.</span>
        </p>
        <ul aria-label="Hosts allowed because: {group.text}">
          {#each group.hosts as host (host.pattern)}
            <li>
              <span class="mono"
                >{entryPattern({
                  pattern: host.pattern,
                  pattern_kind: host.pattern.startsWith("*")
                    ? "suffix"
                    : "exact",
                })}</span
              >
              <span class="muted">{host.note}</span>
            </li>
          {/each}
        </ul>
      </div>
    {/each}
  {/if}
</section>

<style>
  .system {
    display: grid;
    gap: var(--space-2);
    margin-top: var(--space-6);
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
  }
  .sub,
  .muted {
    margin: 0;
    color: var(--color-text-muted);
    max-width: 52rem;
  }
  .group {
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .group p {
    margin: 0 0 var(--space-2);
  }
  ul {
    display: grid;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .mono {
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
</style>
