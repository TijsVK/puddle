# Direct SSH: the switch

Direct SSH means Puddle opens an SSH way into a workspace that the user's own tools can use:
desktop VS Code Remote-SSH, other IDEs, a terminal `ssh`, `scp`, `sftp`. Puddle cannot tell these
apart, because the bridge only relays an encrypted stream, so one switch covers all of them.

Why it is a switch: desktop editors over SSH let code in the workspace run commands on the user's
computer and read the editor's secrets (a signed-in GitHub token). The browser editor does not.

1. Each workspace has an "Allow direct SSH" setting (`direct_ssh`), off by default. A global default
   (`workspace_defaults.direct_ssh`, also off) applies to workspaces that set none; a workspace's own
   value wins.
2. While it is off for a workspace, Puddle opens no SSH endpoint for it, and writes no ssh config
   entry. The check is `HostWorkspaces::direct_ssh_allowed`; anything that opens a way in must
   call it first. A settings document that cannot be read counts as off.
3. A change applies at once to a running workspace: the endpoint opens or closes without a restart.
   Nothing inside the workspace can change the setting.
4. A desktop attach of a running workspace with the switch off is refused with 409 ("direct SSH is
   off for this workspace; allow it first"). The browser editor and Puddle's own port forwards do
   not use the SSH endpoint and are never affected.
5. Turning the switch on, for one workspace or as the global default, shows the trust text first
   and changes nothing until the user confirms. Turning it off needs no question.
6. A workspace with direct SSH on is shown as "Trusted" on its card and its page. The API reports
   it as `direct_ssh` on the workspace. The old `first_connect_notice_due` field is deprecated and
   always `false`.
7. The setting is in the connect step, the workspace's Settings tab and the global Settings page.
