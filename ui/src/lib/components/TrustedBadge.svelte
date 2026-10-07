<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { TRUSTED_LABEL, TRUSTED_TITLE } from "#lib/workspaces/direct-ssh.ts";
</script>

<!-- The text is the whole message; the title is extra for those who hover. -->
<span class="trusted" title={TRUSTED_TITLE}>{TRUSTED_LABEL}</span>

<style>
  .trusted {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-warning);
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
    color: var(--color-text);
    white-space: nowrap;
  }
</style>
