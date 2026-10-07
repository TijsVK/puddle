<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import {
    notices as defaultCenter,
    type NoticeCenter,
  } from "#lib/notify/notices.svelte.ts";
  import "#lib/theme/controls.css";

  let { center = defaultCenter }: { center?: NoticeCenter } = $props();

  /** More than this are folded behind "Show all". */
  const FOLDED = 3;
  let all = $state(false);

  // Newest first.
  const list = $derived([...center.items].reverse());
  const shown = $derived(all ? list : list.slice(0, FOLDED));
  let region = $state<HTMLElement>();

  /** After a dismissal the focus would fall to the page; keep it in the list, or on the page. */
  function dismiss(id: number, button: HTMLElement) {
    const buttons = [
      ...(region?.querySelectorAll<HTMLElement>("button.dismiss") ?? []),
    ];
    const at = buttons.indexOf(button);
    const next = buttons[at + 1] ?? buttons[at - 1];
    center.dismiss(id);
    if (next) next.focus();
    else document.getElementById("main")?.focus();
  }
</script>

<!-- The live region is always there, so a notice that arrives is announced; it never takes focus. -->
<div
  class="notices"
  class:empty={list.length === 0}
  role="region"
  aria-label="Notices"
  bind:this={region}
>
  <div class="live" aria-live="polite">
    {#each shown as notice (notice.id)}
      <div class="notice" class:warning={notice.tone === "warning"}>
        <div class="text">
          <p class="title">{notice.title}</p>
          {#if notice.detail}<p class="detail">{notice.detail}</p>{/if}
          {#if notice.link}
            <a href={notice.link.href}>{notice.link.label}</a>
          {/if}
        </div>
        <button
          type="button"
          class="btn dismiss"
          aria-label="Dismiss notice: {notice.title}"
          onclick={(e) => dismiss(notice.id, e.currentTarget)}>Dismiss</button
        >
      </div>
    {/each}
  </div>
  {#if list.length > FOLDED}
    <div class="more">
      <button
        type="button"
        class="btn"
        aria-expanded={all}
        onclick={() => (all = !all)}
        >{all ? "Show fewer" : `Show all ${list.length} notices`}</button
      >
      <button type="button" class="btn" onclick={() => center.clear()}
        >Dismiss all</button
      >
    </div>
  {/if}
</div>

<style>
  .notices {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-8) 0;
  }
  .notices.empty {
    padding: 0;
  }
  .live {
    display: grid;
    gap: var(--space-2);
  }
  .notice {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
  }
  .notice.warning {
    border-color: var(--color-warning);
  }
  .text {
    display: grid;
    gap: var(--space-1);
    min-width: 0;
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .title {
    font-weight: 600;
  }
  .detail {
    color: var(--color-text-muted);
  }
  .more {
    display: flex;
    gap: var(--space-2);
  }
</style>
