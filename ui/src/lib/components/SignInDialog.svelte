<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { describeSource, type Credential } from "#lib/identities/model.ts";
  import type {
    IdentitiesStore,
    SignInStart,
  } from "#lib/stores/identities.svelte.ts";
  import FormDialog from "./FormDialog.svelte";

  // The step after the user clicked Sign in: puddle started the sign-in, the user finishes it
  // outside puddle (a one-time code typed at an address, or Git Credential Manager's own window),
  // and this dialog asks the credential every few seconds whether it reads yet. Closing it stops
  // asking; puddle ends the sign-in itself after five minutes.
  let {
    open = $bindable(false),
    credential,
    start,
    error,
    store,
    onSignedIn,
    pollMs = 3000,
    windowMs = 300_000,
  }: {
    open?: boolean;
    credential: Credential | null;
    /** What the sign-in showed; `null` while it is starting. */
    start: SignInStart | null;
    /** Why it could not start. */
    error: string | null;
    store: IdentitiesStore;
    onSignedIn?: () => void;
    pollMs?: number;
    windowMs?: number;
  } = $props();

  let state = $state<"waiting" | "done" | "expired">("waiting");

  $effect(() => {
    if (!open || !credential || !start || error) return;
    state = "waiting";
    const target = credential;
    const began = Date.now();
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      timer = undefined;
      const check = await store.check(target);
      if (stopped) return;
      if (check.state === "ok") {
        state = "done";
        onSignedIn?.();
        return;
      }
      if (Date.now() - began >= windowMs) {
        state = "expired";
        return;
      }
      timer = setTimeout(() => void tick(), pollMs);
    };
    timer = setTimeout(() => void tick(), pollMs);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  });
</script>

<FormDialog
  bind:open
  title="Sign in"
  description={credential ? describeSource(credential.source) : "Sign in"}
>
  {#if error}
    <p class="error" role="alert">{error}</p>
  {:else if !start}
    <p role="status">Starting the sign-in&hellip;</p>
  {:else if state === "done"}
    <p role="status"><b>Signed in.</b> puddle can read this credential now.</p>
  {:else if state === "expired"}
    <p role="status">
      The sign-in wasn't finished in time and puddle ended it. Close this and
      try again.
    </p>
  {:else}
    {#if start.code && start.url}
      <p>
        Open <a href={start.url} target="_blank" rel="noopener noreferrer"
          >{start.url}</a
        >
        and enter this code:
      </p>
      <p class="code" data-testid="sign-in-code">{start.code}</p>
    {:else}
      <p>
        Finish signing in in the window that opened. If none opened, close this
        and try again.
      </p>
    {/if}
    <p class="hint" role="status">
      Waiting for you to finish. puddle checks every few seconds and stops after
      five minutes.
    </p>
  {/if}
  <div class="actions">
    <button type="button" class="btn" onclick={() => (open = false)}
      >{state === "done" ? "Done" : "Close"}</button
    >
  </div>
</FormDialog>

<style>
  p {
    margin: 0;
  }
  .code {
    font-family: var(--font-mono);
    font-size: var(--text-xl);
    letter-spacing: 0.1em;
    font-weight: 600;
  }
  .hint {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }
  .error {
    color: var(--color-danger);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
  }
</style>
