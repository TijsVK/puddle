<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import ConfirmDialog from "./ConfirmDialog.svelte";
  import CreateWorkspaceDialog from "./CreateWorkspaceDialog.svelte";
  import DeleteWorkspaceDialog from "./DeleteWorkspaceDialog.svelte";
  import { workspaceActions as actions } from "#lib/stores/workspace-actions.svelte.ts";
</script>

<CreateWorkspaceDialog bind:open={actions.createOpen} />

<!-- The one notice before the first desktop attach (the editor then runs code with this
     computer's secrets within reach). -->
<ConfirmDialog
  bind:open={actions.noticeOpen}
  title="Open {actions.noticeFor?.name ?? 'this workspace'} in VS Code?"
  summary="Opening it in VS Code on this computer makes the workspace trusted."
  detail="Code that runs in VS Code's remote extension host (extensions, tasks, anything in the repository) can read your VS Code secrets, including a signed-in GitHub token, and run commands on this computer through a local terminal. Only attach workspaces whose code you trust. The browser editor keeps the workspace isolated."
  confirmLabel="Open in VS Code"
  tone="allow"
  onConfirm={actions.confirmNotice}
  onCancel={() => {
    actions.noticeFor = null;
  }}
/>

{#if actions.deleting}
  <DeleteWorkspaceDialog
    bind:open={actions.deleteOpen}
    name={actions.deleting.workspace.name}
    check={actions.deleting.check}
    working={actions.deleting.working}
    error={actions.deleting.error}
    onConfirm={actions.confirmDelete}
    onCancel={() => {}}
  />
{/if}
