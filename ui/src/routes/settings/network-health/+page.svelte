<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import {
    DETECTED_LABEL,
    MODE_LABEL,
    PAC_STATE_LABEL,
    ROUTE_SOURCE_LABEL,
    SIGN_IN_LABEL,
    attemptKey,
    expiryText,
    findings,
    fixedProxies,
    hopsText,
    methodLabel,
    waitText,
  } from "#lib/network/model.ts";
  import { relativeTime, absoluteTime } from "#lib/format/relative-time.ts";
  import { networkHealth as store } from "#lib/stores/network-health.svelte.ts";
  import "#lib/theme/controls.css";

  let now = $state(Date.now());
  let heading = $state<HTMLElement>();

  const report = $derived(store.report);
  const list = $derived(report ? findings(report) : []);
  const problems = $derived(list.filter((f) => f.level === "problem"));

  onMount(() => {
    const clock = setInterval(() => {
      now = Date.now();
    }, 30_000);
    // The shell keeps the report current; this makes sure there is one when the page opens first.
    void store.refresh();
    heading?.focus();
    return () => clearInterval(clock);
  });

  const when = (ms: number) => relativeTime(ms, now);
</script>

<div class="head">
  <div>
    <p class="crumb"><a href="/settings#s-net">&larr; Settings</a></p>
    <h1 bind:this={heading} tabindex="-1">Network health</h1>
    <p class="sub">
      How puddle reaches the internet from this computer: the proxy it found,
      how it signs in, and the company certificates workspaces get. Passwords
      and tokens are never shown.
    </p>
  </div>
  <button
    type="button"
    class="btn"
    disabled={store.reading}
    onclick={() => void store.refresh()}
    >{store.reading ? "Checking…" : "Check again"}</button
  >
</div>

{#if store.status === "loading"}
  <p class="muted" role="status">Loading&hellip;</p>
{:else if store.status === "failed"}
  <p class="error" role="alert">
    Couldn't read the network report. puddle's service isn't answering.
  </p>
{:else if store.status === "unavailable" && !report}
  <p class="muted" role="status">
    This puddle can't report on the network yet.
  </p>
{:else if report}
  <section class="card" aria-labelledby="h-summary">
    <h2 id="h-summary">Summary</h2>
    {#if problems.length === 0}
      <p class="ok">No problems found.</p>
    {:else}
      <p class="error">
        {problems.length === 1 ? "1 problem" : `${problems.length} problems`} found.
      </p>
    {/if}
    {#if list.length > 0}
      <ul class="findings">
        {#each list as f (f.id)}
          <li class="finding" class:problem={f.level === "problem"}>
            <p class="what">
              <span class="tag"
                >{f.level === "problem" ? "Problem" : "Note"}</span
              >
              {f.title}
            </p>
            {#if f.fix}<p class="fix"><b>What to do:</b> {f.fix}</p>{/if}
          </li>
        {/each}
      </ul>
    {/if}
    <p class="muted small">
      Report from {when(report.generated_at)}.
      {#if store.status === "unavailable"}
        The latest read failed; this is the last one that worked.
      {/if}
    </p>
  </section>

  <section class="card" aria-labelledby="h-proxy">
    <h2 id="h-proxy">Proxy setup</h2>
    <dl>
      <dt>Found</dt>
      <dd>{DETECTED_LABEL[report.proxy.detected]}</dd>
      <dt>Setting comes from</dt>
      <dd>{MODE_LABEL[report.proxy.mode]}</dd>
      {#if report.proxy.pac_url}
        <dt>Proxy script address</dt>
        <dd class="mono wrap">{report.proxy.pac_url}</dd>
      {/if}
      <dt>Proxy script</dt>
      <dd>{PAC_STATE_LABEL[report.proxy.pac_state]}</dd>
      <dt>Automatic detection</dt>
      <dd>{report.proxy.auto_detect ? "On" : "Off"}</dd>
      <dt>Fixed proxy</dt>
      <dd>
        {#each fixedProxies(report.proxy) as p, i (p)}{i > 0 ? ", " : ""}<span
            class="mono">{p}</span
          >{:else}None{/each}
      </dd>
      <dt>Bypass list</dt>
      <dd>
        {report.proxy.bypass_entries === 1
          ? "1 entry"
          : `${report.proxy.bypass_entries} entries`}
      </dd>
      <dt>Last network change</dt>
      <dd>
        {#if report.proxy.last_change_at !== null}
          <span title={absoluteTime(report.proxy.last_change_at)}
            >{when(report.proxy.last_change_at)}</span
          >
          (change number {report.proxy.epoch})
        {:else}
          None since puddle started
        {/if}
      </dd>
    </dl>
    {#if report.proxy.settings_error}
      <p class="error">
        Settings couldn't be read: {report.proxy.settings_error}
      </p>
    {/if}
    <h3>Proxies marked as not answering</h3>
    {#if report.proxy.dead_proxies.length === 0}
      <p class="muted">None.</p>
    {:else}
      <table>
        <thead>
          <tr><th scope="col">Proxy</th><th scope="col">Tried again in</th></tr>
        </thead>
        <tbody>
          {#each report.proxy.dead_proxies as dead (dead.proxy)}
            <tr>
              <td class="mono">{dead.proxy}</td>
              <td>{waitText(dead.retry_in_secs)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section class="card" aria-labelledby="h-sign">
    <h2 id="h-sign">Signing in to the proxy</h2>
    <p>
      puddle can answer with:
      {#if report.sign_in.methods.length === 0}
        <b>nothing</b>. It cannot sign in to a proxy on this system.
      {:else}
        <b>{report.sign_in.methods.map(methodLabel).join(", ")}</b>.
      {/if}
    </p>
    {#if report.sign_in.attempts.length === 0}
      <p class="muted">No proxy has been signed in to yet.</p>
    {:else}
      <table>
        <caption class="visually-hidden">Last sign-in per proxy</caption>
        <thead>
          <tr>
            <th scope="col">Proxy</th>
            <th scope="col">Sent</th>
            <th scope="col">Result</th>
            <th scope="col">When</th>
          </tr>
        </thead>
        <tbody>
          {#each report.sign_in.attempts as a (attemptKey(a))}
            <tr>
              <td class="mono">{a.proxy}</td>
              <td>{a.scheme ?? "nothing"}</td>
              <td>
                {SIGN_IN_LABEL[a.result]}{#if a.detail}
                  <span class="muted wrap"> &middot; {a.detail}</span>{/if}
              </td>
              <td><span title={absoluteTime(a.at)}>{when(a.at)}</span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section class="card" aria-labelledby="h-roots">
    <h2 id="h-roots">Company certificates</h2>
    {#if report.roots.synced}
      <p>
        Workspaces get <b>{report.roots.roots}</b>
        {report.roots.roots === 1 ? "root" : "roots"} and
        <b>{report.roots.intermediates}</b>
        {report.roots.intermediates === 1 ? "intermediate" : "intermediates"},
        read
        {#if report.roots.synced_at !== null}
          <span title={absoluteTime(report.roots.synced_at)}
            >{when(report.roots.synced_at)}</span
          >{/if}.
      </p>
    {:else}
      <p class="muted">Not read yet.</p>
    {/if}
    {#if report.roots.certificates.length > 0}
      <table>
        <caption class="visually-hidden">Certificates workspaces get</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Kind</th>
            <th scope="col">Expires</th>
            <th scope="col">Found in</th>
          </tr>
        </thead>
        <tbody>
          {#each report.roots.certificates as c (c.fingerprint)}
            <tr>
              <td class="wrap">
                {c.subject ?? "(no name)"}
                <span class="muted mono small block"
                  >{c.fingerprint.slice(0, 16)}</span
                >
              </td>
              <td>{c.kind === "root" ? "Root" : "Intermediate"}</td>
              <td>{expiryText(c.not_after, now)}</td>
              <td class="mono small wrap">{c.sources.join(", ")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <h3>Left out</h3>
    {#if report.roots.skipped.length === 0}
      <p class="muted">Nothing.</p>
    {:else}
      <ul class="plain">
        {#each report.roots.skipped as s (s.fingerprint)}
          <li class="wrap">
            {s.subject ?? "(no name)"}
            <span class="muted mono small">{s.fingerprint.slice(0, 16)}</span>:
            {s.reason}
          </li>
        {/each}
      </ul>
    {/if}
    <h3>Stores that couldn't be read</h3>
    {#if report.roots.unreadable_stores.length === 0}
      <p class="muted">None.</p>
    {:else}
      <ul class="plain">
        {#each report.roots.unreadable_stores as s (s)}
          <li class="error wrap">{s}</li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="card" aria-labelledby="h-pull">
    <h2 id="h-pull">Image downloads</h2>
    <dl>
      <dt>Through puddle's pull proxy</dt>
      <dd>
        {report.pull_proxy.active ? "Yes" : "No"}
      </dd>
      <dt>Through the company proxy</dt>
      <dd>
        {report.pull_proxy.via_upstream ? "Yes" : "No"}
      </dd>
    </dl>
  </section>

  <section class="card" aria-labelledby="h-routes">
    <h2 id="h-routes">Routes chosen</h2>
    <p class="desc">
      How puddle reached each destination since the last network change, in
      order of preference. At most 100.
    </p>
    {#if report.routes.length === 0}
      <p class="muted">None yet.</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th scope="col">Destination</th>
            <th scope="col">Route</th>
            <th scope="col">Decided by</th>
          </tr>
        </thead>
        <tbody>
          {#each report.routes as r (`${r.scheme}://${r.host}:${r.port}`)}
            <tr>
              <td class="mono wrap">{r.scheme}://{r.host}:{r.port}</td>
              <td class="wrap">{hopsText(r.hops)}</td>
              <td>{ROUTE_SOURCE_LABEL[r.source]}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: var(--space-4);
  }
  h1 {
    margin: 0;
  }
  h1:focus {
    outline: none;
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
  }
  h3 {
    margin: var(--space-2) 0 0;
    font-size: var(--text-md);
  }
  .crumb {
    margin: 0 0 var(--space-2);
  }
  .sub,
  .muted,
  .desc {
    color: var(--color-text-muted);
  }
  .sub {
    margin: var(--space-2) 0 var(--space-4);
    max-width: 44rem;
  }
  .desc,
  .small {
    font-size: var(--text-sm);
  }
  p {
    margin: 0;
  }
  .error {
    color: var(--color-danger);
  }
  .ok {
    color: var(--color-success);
  }
  .card {
    display: grid;
    gap: var(--space-3);
    max-width: 56rem;
    margin-bottom: var(--space-4);
    padding: var(--space-4);
    background: var(--color-surface);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  dl {
    display: grid;
    grid-template-columns: minmax(10rem, max-content) minmax(0, 1fr);
    gap: var(--space-2) var(--space-4);
    margin: 0;
  }
  dt {
    color: var(--color-text-muted);
  }
  dd {
    margin: 0;
  }
  .wrap {
    overflow-wrap: anywhere;
  }
  .block {
    display: block;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    padding: var(--space-1) var(--space-2);
    text-align: start;
    vertical-align: top;
    border-bottom: 1px solid var(--color-border-subtle);
  }
  th {
    color: var(--color-text-muted);
    font-weight: 600;
  }
  ul.findings,
  ul.plain {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  .finding {
    display: grid;
    gap: var(--space-1);
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-subtle);
    border-radius: var(--radius-md);
  }
  .finding.problem {
    border-color: var(--color-danger);
  }
  .tag {
    font-weight: 600;
    margin-inline-end: var(--space-1);
  }
  .fix {
    color: var(--color-text-muted);
  }
</style>
