<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import Toast from "#lib/components/Toast.svelte";
  import WorkspaceDialogs from "#lib/components/WorkspaceDialogs.svelte";
  import { pending } from "#lib/stores/pending.svelte.ts";
  import { workspaceActions } from "#lib/stores/workspace-actions.svelte.ts";
  import { workspaces } from "#lib/stores/workspaces.svelte.ts";

  let { children } = $props();

  // One listener for the list and every detail page, so moving between them keeps the data.
  onMount(() => {
    workspaces.onSettled = workspaceActions.settled;
    const stopWorkspaces = workspaces.start();
    const stopPending = pending.start();
    return () => {
      workspaces.onSettled = null;
      stopWorkspaces();
      stopPending();
    };
  });
</script>

{@render children()}
<WorkspaceDialogs />
<Toast />
