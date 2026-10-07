<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { page } from "$app/state";
  import { APP_NAME, NAV, sectionFor } from "#lib/nav.ts";
  import { live } from "#lib/stores/live.svelte.ts";
  import ThemeToggle from "./ThemeToggle.svelte";

  const current = $derived(sectionFor(page.url.pathname)?.href);
</script>

<aside class="sidebar">
  <p class="brand">{APP_NAME}</p>
  <nav aria-label="Main">
    <ul>
      {#each NAV as item (item.href)}
        <li>
          <a
            href={item.href}
            aria-current={current === item.href ? "page" : undefined}
          >
            <item.icon aria-hidden="true" size={18} />
            <span>{item.label}</span>
            {#if item.badge === "pending" && live.pending > 0}
              <span class="badge" data-testid="pending-badge">
                <span aria-hidden="true">{live.pending}</span>
                <span class="visually-hidden">{live.pending} pending</span>
              </span>
            {/if}
          </a>
        </li>
      {/each}
    </ul>
  </nav>
  <div class="footer">
    <ThemeToggle />
  </div>
</aside>

<style>
  .sidebar {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    width: var(--sidebar-width);
    flex: none;
    padding: var(--space-4);
    background: var(--color-surface);
    border-inline-end: 1px solid var(--color-border-subtle);
  }
  .brand {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: 600;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }
  a {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    color: var(--color-text);
    text-decoration: none;
  }
  a:hover {
    background: var(--color-surface-raised);
  }
  a[aria-current="page"] {
    background: var(--color-accent-subtle);
    font-weight: 600;
  }
  .badge {
    margin-inline-start: auto;
    min-width: 1.5rem;
    padding: 0 var(--space-2);
    border-radius: var(--radius-pill);
    background: var(--color-accent);
    color: var(--color-accent-contrast);
    font-size: var(--text-sm);
    text-align: center;
  }
  .footer {
    margin-top: auto;
  }
</style>
