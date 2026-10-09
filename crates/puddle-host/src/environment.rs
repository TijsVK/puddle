// SPDX-License-Identifier: GPL-3.0-or-later
//! A workspace's environment as the host applies it: the variables its guest starts with, and the
//! stand-ins the proxy swaps for the secrets among them.
//!
//! The plain variables and each secret's stand-in go into the guest's environment. A secret's
//! real value is read from the operating system's credential store into the proxy's registry and
//! nowhere else: this module never puts it in the guest's environment, a file or a log line.

use puddle_proxy::{SecretValue, StandIn, StandInOrigin, TerminationSet, secret_stand_in};
use puddle_secrets::SecretStore;
use puddle_store::{StartValue, Store};
use puddle_types::{GuestEnv, WorkspaceName};

/// What a workspace's environment comes to at one moment.
pub(crate) struct Resolved {
    /// What the guest starts with: every plain variable, and a stand-in under each secret's name.
    pub(crate) guest: GuestEnv,
    /// One entry for each secret, with its real value, for the proxy's registry.
    pub(crate) entries: Vec<StandIn>,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("variables", &self.guest.len())
            .field("secrets", &self.entries.len())
            .finish()
    }
}

/// Reads `workspace`'s variables from the store and its secrets' values from `vault`. Blocking:
/// the credential store may take its time (a locked keyring), so callers run it off the async
/// threads.
///
/// # Errors
/// A message for the user that names the variable and the way out. A secret whose value cannot be
/// read stops the start: a workspace that started without it would only fail later in a tool, with
/// no hint of the cause.
pub(crate) fn resolve(
    store: &Store,
    vault: &dyn SecretStore,
    workspace: &WorkspaceName,
) -> Result<Resolved, String> {
    let vars = store
        .env_for_start(workspace, &mut |name| {
            secret_stand_in(name.as_str()).map_err(|e| e.to_string())
        })
        .map_err(|e| format!("cannot read {workspace}'s environment: {e}"))?;
    let mut guest = GuestEnv::new();
    let mut entries = Vec::new();
    for var in vars {
        let name = var.name.as_str();
        let text = match var.value {
            StartValue::Plain(value) => value,
            StartValue::Secret {
                id,
                hosts,
                stand_in,
            } => {
                let real = match vault.get(&id) {
                    Ok(Some(real)) => real,
                    Ok(None) => {
                        return Err(format!(
                            "the value of the secret {name} is not in this computer's credential store; \
                             set it again on the workspace's Environment tab"
                        ));
                    }
                    Err(_) => {
                        return Err(format!(
                            "cannot read the secret {name} from the operating system's credential store; \
                             unlock it or check that it is running, then start the workspace again"
                        ));
                    }
                };
                let set = TerminationSet::parse(hosts.iter().map(puddle_store::SecretHost::as_str))
                    .map_err(|e| format!("the hosts of the secret {name} are not usable: {e}"))?;
                let entry = StandIn::new(
                    StandInOrigin::Secret,
                    name,
                    &stand_in,
                    SecretValue::new(real.expose()),
                    set,
                )
                .map_err(|e| format!("the secret {name} cannot be used: {e}"))?;
                entries.push(entry);
                stand_in
            }
        };
        guest
            .set(name, &text)
            .map_err(|e| format!("the variable {name} cannot be set: {e}"))?;
    }
    Ok(Resolved { guest, entries })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use puddle_ca::{CaBuilder, TrustBundle};
    use puddle_certs::{CorporateRoots, GuestTrust};
    use puddle_guest_env::{ProxySettings, guest_proxy_config};
    use puddle_secrets::{MemoryStore, Secret, StoredId};
    use puddle_store::{
        EnvDraft, EnvName, EnvScope, Limits, ManualClock, PUDDLE_OWNED_NAMES, SecretHost,
    };
    use puddle_types::Host;

    use super::*;

    const REAL: &str = "real-value-CANARY-0123";

    fn store() -> Store {
        Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap()
    }

    fn ws(name: &str) -> WorkspaceName {
        WorkspaceName::new(name).unwrap()
    }

    fn name(text: &str) -> EnvName {
        EnvName::new(text).unwrap()
    }

    fn add_secret(store: &Store, vault: &MemoryStore, scope: &EnvScope, n: &str, hosts: &[&str]) {
        let id = StoredId::new(format!("env-{n}")).unwrap();
        vault.set(&id, &Secret::new(REAL.to_owned())).unwrap();
        let hosts = hosts.iter().map(|h| SecretHost::new(h).unwrap()).collect();
        store
            .set_env(scope, &name(n), EnvDraft::secret(id, hosts).unwrap())
            .unwrap();
    }

    #[test]
    fn the_guest_gets_plain_values_and_stand_ins_and_the_proxy_gets_the_real_values() {
        let store = store();
        let vault = MemoryStore::new();
        let shop = EnvScope::Workspace(ws("shop"));
        store
            .set_env(
                &EnvScope::Global,
                &name("EDITOR"),
                EnvDraft::plain("vim").unwrap(),
            )
            .unwrap();
        add_secret(&store, &vault, &shop, "NPM_TOKEN", &["registry.npmjs.org"]);

        let resolved = resolve(&store, &vault, &ws("shop")).unwrap();
        assert_eq!(resolved.guest.get("EDITOR"), Some("vim"));
        let stand_in = resolved.guest.get("NPM_TOKEN").unwrap().to_owned();
        assert!(
            stand_in.starts_with("puddle-secret-NPM_TOKEN-"),
            "{stand_in}"
        );
        assert_eq!(resolved.guest.len(), 2);
        // The real value is nowhere in what the guest gets.
        assert!(resolved.guest.iter().all(|(_, v)| !v.contains("CANARY")));
        // It is in the one registry entry, which hides it and lists its hosts.
        assert_eq!(resolved.entries.len(), 1);
        let entry = &resolved.entries[0];
        assert_eq!(entry.id(), "stand-in:secret:NPM_TOKEN");
        assert!(!format!("{entry:?}").contains("CANARY"));
        assert!(!format!("{resolved:?}").contains("CANARY"));
        assert!(
            entry
                .hosts()
                .contains(&Host::parse_normalised("registry.npmjs.org").unwrap())
        );

        // The same stand-in at the next start.
        let again = resolve(&store, &vault, &ws("shop")).unwrap();
        assert_eq!(again.guest.get("NPM_TOKEN"), Some(stand_in.as_str()));
    }

    #[test]
    fn a_secret_whose_value_is_gone_or_unreadable_stops_the_start_with_its_name() {
        let store = store();
        let vault = MemoryStore::new();
        add_secret(
            &store,
            &vault,
            &EnvScope::Global,
            "TOKEN",
            &["api.example.com"],
        );
        vault.delete(&StoredId::new("env-TOKEN").unwrap()).unwrap();
        let gone = resolve(&store, &vault, &ws("a")).unwrap_err();
        assert!(
            gone.contains("TOKEN") && gone.contains("Environment tab"),
            "{gone}"
        );

        vault.break_it();
        let broken = resolve(&store, &vault, &ws("a")).unwrap_err();
        assert!(
            broken.contains("TOKEN") && broken.contains("credential store"),
            "{broken}"
        );
        assert!(!broken.contains(REAL) && !gone.contains(REAL));
    }

    #[test]
    fn a_workspace_with_no_secret_never_asks_the_credential_store() {
        let store = store();
        let vault = MemoryStore::new();
        vault.break_it();
        store
            .set_env(&EnvScope::Global, &name("A"), EnvDraft::plain("1").unwrap())
            .unwrap();
        let resolved = resolve(&store, &vault, &ws("a")).unwrap();
        assert_eq!(resolved.guest.get("A"), Some("1"));
        assert!(resolved.entries.is_empty());
    }

    #[test]
    fn a_secret_that_the_proxy_would_not_swap_stops_the_start_instead_of_starting_dead() {
        let store = store();
        let vault = MemoryStore::new();
        // A value with a line break can never be a header value.
        let id = StoredId::new("env-BAD").unwrap();
        vault.set(&id, &Secret::new("a\nb".to_owned())).unwrap();
        store
            .set_env(
                &EnvScope::Global,
                &name("BAD"),
                EnvDraft::secret(id, vec![SecretHost::new("api.example.com").unwrap()]).unwrap(),
            )
            .unwrap();
        let err = resolve(&store, &vault, &ws("a")).unwrap_err();
        assert!(
            err.contains("BAD") && err.contains("cannot be used"),
            "{err}"
        );
    }

    /// The names the store refuses must be exactly the ones every guest is given (or merged
    /// with the user's), or a workspace's own variable would be shadowed without a word.
    #[test]
    fn the_names_the_store_refuses_are_the_ones_puddle_sets_in_every_guest() {
        let ca = CaBuilder::new("test").build().unwrap();
        let trust = GuestTrust::new(
            &CorporateRoots::default(),
            &TrustBundle::new().with(ca.certificate().clone()),
        );
        let mut set: BTreeSet<String> = BTreeSet::new();
        for (name, _) in guest_proxy_config(&ProxySettings::default(), &[])
            .unwrap()
            .env
            .iter()
            .chain(trust.env().iter())
        {
            set.insert(name.to_owned());
        }
        // These four are added to, not replaced (the user's value is kept and puddle's follows).
        let merged = ["JAVA_TOOL_OPTIONS", "MAVEN_ARGS"];
        let owned: BTreeSet<String> = PUDDLE_OWNED_NAMES.iter().map(|n| (*n).to_owned()).collect();
        let mut expected = set.clone();
        for name in merged {
            assert!(expected.remove(name), "{name} is set by puddle");
        }
        assert_eq!(owned, expected);
    }

    #[test]
    fn the_hosts_the_store_accepts_are_the_hosts_a_stand_in_accepts() {
        let id = StoredId::new("env-1").unwrap();
        let cases = [
            "api.example.com",
            "API.Example.COM",
            "*.example.com",
            "*.visualstudio.com",
            "github.com",
            "localhost",
            "a.b.c.d.example.co.uk",
            "*.example.co.uk",
            "*.co.uk",
            "*.com",
            "*.github.io",
            "*.s3.amazonaws.com",
            "*",
            "*.",
            "",
            ".example.com",
            "10.0.0.1",
            "[::1]",
            "example.com:443",
            "-bad.example.com",
            "bad-.example.com",
            "ex ample.com",
            "example..com",
            "xn--bcher-kva.example",
            "bücher.example",
            "a_b.example.com",
        ];
        for case in cases {
            let store_side = SecretHost::new(case);
            let proxy_side = TerminationSet::parse([case]).and_then(|set| {
                StandIn::new(
                    StandInOrigin::Secret,
                    "N",
                    "puddle-secret-N-0123456789abcdef0123456789abcdef",
                    SecretValue::new("v"),
                    set,
                )
                .map_err(|_| puddle_proxy::PatternError::NotAName(case.to_owned()))
            });
            if let Ok(host) = &store_side {
                // Whatever the store keeps, the proxy takes as it is kept.
                let kept = host.as_str();
                let set = TerminationSet::parse([kept]).unwrap();
                StandIn::new(
                    StandInOrigin::Secret,
                    "N",
                    "puddle-secret-N-0123456789abcdef0123456789abcdef",
                    SecretValue::new("v"),
                    set,
                )
                .unwrap_or_else(|e| panic!("{case} stored as {kept}: {e}"));
                let _ = EnvDraft::secret(id.clone(), vec![host.clone()]).unwrap();
            }
            // The store is never wider than the proxy: what the proxy refuses it refuses.
            if proxy_side.is_err() {
                assert!(
                    store_side.is_err(),
                    "{case}: the proxy refuses it, the store takes it"
                );
            }
        }
    }
}
