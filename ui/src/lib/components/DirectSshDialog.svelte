<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import ConfirmDialog from "./ConfirmDialog.svelte";
  import type { TrustWords } from "#lib/workspaces/direct-ssh.ts";

  // The trust text, said once when direct SSH is turned on (for one workspace or as the global
  // default). Cancel is focused first: Enter right after opening changes nothing.
  let {
    open = $bindable(false),
    words,
    onConfirm,
    onCancel = () => undefined,
  }: {
    open?: boolean;
    words: TrustWords;
    onConfirm: () => void;
    onCancel?: () => void;
  } = $props();
</script>

<ConfirmDialog
  bind:open
  title={words.title}
  summary={words.summary}
  detail={words.detail}
  confirmLabel={words.confirmLabel}
  tone="allow"
  {onConfirm}
  {onCancel}
/>
