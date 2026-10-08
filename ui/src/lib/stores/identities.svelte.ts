// SPDX-License-Identifier: GPL-3.0-or-later
/* eslint-disable svelte/prefer-svelte-reactivity -- the sets here are bookkeeping that no template reads */
// The Identities screens' state: the identities in your order, what puddle found signed in on this
// computer, what the last check of each credential came to, and what a user does to them (make,
// change, delete, default, order, test, paste a token, sign in). It refetches on
// `identities_changed` and on a resync, and polls slowly as a safety net. A credential's secret is
// never here: a credential is a reference, a check says only whether it reads.
import { api as defaultApi, type ApiClient } from "#lib/api/client.ts";
import {
  checkOf,
  credentialKey,
  describeSource,
  UNTESTED,
  type Check,
  type Credential,
  type FoundAccounts,
  type Identity,
  type IdentityRequest,
  type Source,
} from "#lib/identities/model.ts";
import { isIdentitiesChanged } from "#lib/identities/events.ts";
import { sentence } from "#lib/rules/model.ts";
import { live, type LiveSource } from "./live.svelte.ts";

type StoreApi = Pick<ApiClient, "GET" | "POST" | "PUT" | "DELETE">;

export type Status = "loading" | "ready" | "failed";
export type Result<T = undefined> =
  | ({ ok: true } & ([T] extends [undefined] ? object : { value: T }))
  | { ok: false; message: string };

/** What a sign-in shows the user. */
export interface SignInStart {
  code: string | null;
  url: string | null;
}

export interface IdentitiesDeps {
  api?: StoreApi;
  source?: LiveSource;
  pollMs?: number;
}

const DOWN = "puddle's service isn't answering.";

const SIGNED_OUT: Check = {
  state: "problem",
  message: "A workspace asked for it and puddle couldn't read it.",
  needsSignIn: true,
};

export class IdentitiesStore {
  identities = $state.raw<Identity[]>([]);
  status = $state<Status>("loading");
  /** What the last check of each credential came to, by `credentialKey`. */
  checks = $state.raw<Record<string, Check>>({});
  /** The accounts found signed in on this computer; `null` until asked. */
  found = $state.raw<FoundAccounts | null>(null);
  foundStatus = $state<Status>("loading");

  readonly #api: StoreApi;
  readonly #source: LiveSource | undefined;
  readonly #pollMs: number;
  readonly #readable = new Set<(description: string) => void>();
  /** Lines naming the sources a workspace could not read (`credential_sign_in_needed`), until they read. */
  signedOutLines = $state.raw<ReadonlySet<string>>(new Set());

  constructor(deps: IdentitiesDeps = {}) {
    this.#api = deps.api ?? defaultApi;
    this.#source = deps.source;
    this.#pollMs = deps.pollMs ?? 60_000;
  }

  /** Reads the identities; never throws. */
  async refresh(): Promise<void> {
    try {
      const { data } = await this.#api.GET("/api/identities");
      if (data) {
        this.identities = data.identities;
        this.status = "ready";
      } else if (this.status === "loading") {
        this.status = "failed";
      }
    } catch {
      if (this.status === "loading") this.status = "failed";
    }
  }

  byId(id: number): Identity | undefined {
    return this.identities.find((i) => i.id === id);
  }

  /** The identity that has a credential for the source this line names. */
  bySource(description: string): Identity | undefined {
    return this.identities.find((i) =>
      i.credentials.some((c) => describeSource(c.source) === description),
    );
  }

  /** What is known of a credential: its last check, or that a workspace could not read it. */
  checkOf(credential: Credential): Check {
    const known = this.checks[credentialKey(credential)];
    if (known && known.state !== "untested") return known;
    return this.signedOutLines.has(describeSource(credential.source))
      ? SIGNED_OUT
      : UNTESTED;
  }

  #setCheck(credential: Credential, check: Check): void {
    this.checks = { ...this.checks, [credentialKey(credential)]: check };
  }

  #refused(error: { message?: string } | undefined, fallback: string): string {
    return sentence(error?.message ?? fallback);
  }

  /** Makes an identity, last in the order. */
  async create(request: IdentityRequest): Promise<Result<Identity>> {
    try {
      const { data, error } = await this.#api.POST("/api/identities", {
        body: request,
      });
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle refused the identity"),
        };
      }
      this.identities = [...this.identities, data];
      return { ok: true, value: data };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Replaces an identity's label, author and credentials. */
  async update(
    id: number,
    request: IdentityRequest,
  ): Promise<Result<Identity>> {
    try {
      const { data, error } = await this.#api.PUT("/api/identities/{id}", {
        params: { path: { id } },
        body: request,
      });
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle refused the change"),
        };
      }
      this.identities = this.identities.map((i) => (i.id === id ? data : i));
      return { ok: true, value: data };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Deletes an identity; the answer lists the workspaces it left. A missing one counts as deleted. */
  async remove(id: number): Promise<Result<string[]>> {
    try {
      const { data, response } = await this.#api.DELETE(
        "/api/identities/{id}",
        {
          params: { path: { id } },
        },
      );
      if (!data && response.status !== 404) {
        return { ok: false, message: "puddle couldn't delete that identity." };
      }
      this.identities = this.identities.filter((i) => i.id !== id);
      return { ok: true, value: data?.detached_from ?? [] };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  async makeDefault(id: number): Promise<Result> {
    try {
      const { data, error } = await this.#api.PUT(
        "/api/identities/{id}/default",
        { params: { path: { id } } },
      );
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle couldn't change the default"),
        };
      }
      await this.refresh();
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Puts the identities in this order (every id once). */
  async reorder(ids: number[]): Promise<Result> {
    try {
      const { data, error } = await this.#api.PUT("/api/identities/order", {
        body: { ids },
      });
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle couldn't change the order"),
        };
      }
      this.identities = data.identities;
      return { ok: true };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Looks for accounts already signed in on this computer. */
  async loadFound(): Promise<void> {
    this.foundStatus = "loading";
    try {
      const { data } = await this.#api.GET("/api/credentials/found");
      if (data) {
        this.found = data;
        this.foundStatus = "ready";
      } else {
        this.foundStatus = "failed";
      }
    } catch {
      this.foundStatus = "failed";
    }
  }

  /** Reads a source once and says whether it worked; never the value. */
  async checkSource(source: Source): Promise<Check> {
    try {
      const { data, error } = await this.#api.POST("/api/credentials/check", {
        body: { source },
      });
      if (!data) {
        return {
          state: "problem",
          message: this.#refused(error, "puddle couldn't check it"),
          needsSignIn: false,
        };
      }
      return checkOf(data);
    } catch {
      return { state: "problem", message: DOWN, needsSignIn: false };
    }
  }

  /** Tests one credential and remembers the answer. */
  async check(credential: Credential): Promise<Check> {
    this.#setCheck(credential, { state: "checking" });
    const result = await this.checkSource(credential.source);
    this.#setCheck(credential, result);
    if (result.state === "ok") this.#nowReadable(credential.source);
    return result;
  }

  /** Tests every credential of the identities, one after another. */
  async checkAll(
    identities: readonly Identity[] = this.identities,
  ): Promise<void> {
    for (const identity of identities) {
      for (const credential of identity.credentials) {
        await this.check(credential);
      }
    }
  }

  #nowReadable(source: Source): void {
    const description = describeSource(source);
    if (this.signedOutLines.has(description)) {
      const next = new Set(this.signedOutLines);
      next.delete(description);
      this.signedOutLines = next;
    }
    for (const listener of this.#readable) listener(description);
  }

  /** Tells `listener` when a credential reads again (its sign-in notice can go); returns the way to stop. */
  onReadable(listener: (description: string) => void): () => void {
    this.#readable.add(listener);
    return () => {
      this.#readable.delete(listener);
    };
  }

  /** A workspace could not read a credential: the screens show "Sign in needed" until it reads. */
  markSignedOut(description: string): void {
    this.signedOutLines = new Set([...this.signedOutLines, description]);
    const stale = Object.keys(this.checks).filter((k) =>
      k.endsWith(`|${description}`),
    );
    if (stale.length > 0) {
      const next = { ...this.checks };
      for (const key of stale) delete next[key];
      this.checks = next;
    }
  }

  /** Keeps a pasted token in the operating system's store; the answer is the source to use. */
  async storeToken(
    host: string,
    org: string | null,
    token: string,
  ): Promise<Result<Source>> {
    try {
      const { data, error } = await this.#api.POST("/api/credentials/stored", {
        body: { host, org, token },
      });
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle couldn't keep the token"),
        };
      }
      return { ok: true, value: data.source };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Removes a pasted token; never throws, since a token left behind is only an unused entry. */
  async forgetToken(source: Source): Promise<void> {
    if (source.kind !== "stored") return;
    try {
      await this.#api.DELETE("/api/credentials/stored/{id}", {
        params: { path: { id: source.id } },
      });
    } catch {
      // The entry stays in the credential store, unreferenced; the next removal tries again.
    }
  }

  /** Starts a sign-in the user finishes outside puddle (a code at an address, or the helper's own window). */
  async signIn(source: Source): Promise<Result<SignInStart>> {
    try {
      const { data, error } = await this.#api.POST("/api/credentials/sign-in", {
        body: { source },
      });
      if (!data) {
        return {
          ok: false,
          message: this.#refused(error, "puddle couldn't start the sign-in"),
        };
      }
      return { ok: true, value: { code: data.code, url: data.url } };
    } catch {
      return { ok: false, message: DOWN };
    }
  }

  /** Starts listening and polling; returns the function that stops both. */
  start(): () => void {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unsubscribe = this.#source?.subscribe({
      event: (event) => {
        if (isIdentitiesChanged(event)) void this.refresh();
      },
      resync: () => void this.refresh(),
    });
    const tick = () => {
      timer = setTimeout(() => {
        if (stopped) return;
        void this.refresh().finally(tick);
      }, this.#pollMs);
    };
    void this.refresh().finally(() => {
      if (!stopped) tick();
    });
    return () => {
      stopped = true;
      clearTimeout(timer);
      unsubscribe?.();
    };
  }
}

export const identities = new IdentitiesStore({ source: live });
