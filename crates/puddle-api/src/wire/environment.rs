// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment variables and secrets on the wire (credentials spec §9). A plain variable's value
//! is shown and changed here. A secret's value is write-only: a request carries it once, to be
//! kept in the operating system's credential store, and no response, error or log line carries it,
//! its length or any part of it.

use puddle_secrets::Secret;
use puddle_store as store;
use puddle_types::WorkspaceName;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Where a variable applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnvScope {
    /// Every workspace gets it, unless the workspace has its own of the same name.
    Global,
    /// Only this workspace gets it.
    Workspace,
}

/// What a variable is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnvKind {
    /// The workspace gets the value as it is.
    Plain,
    /// The workspace gets a stand-in; puddle adds the real value on the way out to the secret's
    /// hosts only.
    Secret,
}

/// One variable. A secret's value is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnvVariable {
    /// The variable's name.
    pub name: String,
    /// Where it applies.
    pub scope: EnvScope,
    /// What it is.
    pub kind: EnvKind,
    /// A plain variable's value; `null` for a secret.
    #[schema(required = true)]
    pub value: Option<String>,
    /// The hosts a secret's real value may be sent to (names, or `*.` and a name for every name
    /// below it); empty for a plain variable.
    pub hosts: Vec<String>,
    /// A global variable that the workspace's own variable of the same name hides. Only ever
    /// `true` in a workspace's list.
    pub overridden: bool,
    /// When it last changed, epoch ms.
    pub changed_at: u64,
}

impl EnvVariable {
    pub(crate) fn from_store(entry: store::EnvEntry, overridden: bool) -> Self {
        let (kind, value, hosts) = match entry.value {
            store::EnvValue::Plain(value) => (EnvKind::Plain, Some(value), Vec::new()),
            store::EnvValue::Secret(secret) => (
                EnvKind::Secret,
                None,
                secret.hosts.iter().map(ToString::to_string).collect(),
            ),
        };
        Self {
            name: entry.name.to_string(),
            scope: match entry.scope {
                store::EnvScope::Global => EnvScope::Global,
                store::EnvScope::Workspace(_) => EnvScope::Workspace,
            },
            kind,
            value,
            hosts,
            overridden,
            changed_at: entry.changed_at,
        }
    }
}

/// The global variables, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnvList {
    /// The variables.
    pub variables: Vec<EnvVariable>,
}

/// What a workspace sees: its own variables and the global ones, by name. A global variable that
/// the workspace's own of the same name hides is listed after it with `overridden` set. The
/// workspace's environment is read when it starts: a change reaches a running workspace's own
/// environment at its next start; a secret's hosts and value apply at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceEnv {
    /// The workspace.
    pub workspace: WorkspaceName,
    /// Its variables.
    pub variables: Vec<EnvVariable>,
}

/// A secret's value in a request: written once, kept in the credential store, never shown again.
/// Only a JSON string is accepted, and the refusal of anything else does not quote it.
pub struct SecretText(pub(crate) Secret);

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Text;

        impl<'de> Visitor<'de> for Text {
            type Value = SecretText;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<SecretText, E> {
                Ok(SecretText(Secret::new(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<SecretText, E> {
                Ok(SecretText(Secret::new(value)))
            }

            // Whatever else arrives, the message names the kind and not the content: a secret
            // sent as a number must not come back in the refusal.
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<SecretText, E> {
                Err(E::custom("the value must be a string, not a boolean"))
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> Result<SecretText, E> {
                Err(E::custom("the value must be a string, not a number"))
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> Result<SecretText, E> {
                Err(E::custom("the value must be a string, not a number"))
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<SecretText, E> {
                Err(E::custom("the value must be a string, not a number"))
            }

            fn visit_unit<E: de::Error>(self) -> Result<SecretText, E> {
                Err(E::custom("the value must be a string, not null"))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, _: A) -> Result<SecretText, A::Error> {
                Err(de::Error::custom("the value must be a string, not a list"))
            }

            fn visit_map<A: de::MapAccess<'de>>(self, _: A) -> Result<SecretText, A::Error> {
                Err(de::Error::custom(
                    "the value must be a string, not an object",
                ))
            }
        }

        deserializer.deserialize_any(Text)
    }
}

/// What to set a variable to.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvSetRequest {
    /// A plain variable.
    Plain {
        /// The value.
        value: String,
    },
    /// A secret. A new one needs its `value`; one that is already a secret keeps its value when
    /// `value` is left out, so its hosts can change without typing it again.
    Secret {
        /// The value: written once, kept in the operating system's credential store, never shown
        /// again.
        #[serde(default)]
        #[schema(value_type = Option<String>, format = Password, write_only, required = false)]
        value: Option<SecretText>,
        /// The hosts the real value may be sent to, at least one: names, or `*.` and a name for
        /// every name below it. A pattern over a domain anyone can register a name under
        /// (`*.github.io`) is refused.
        hosts: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_value_never_shows_in_debug_output_or_in_the_refusal_of_a_wrong_type() {
        let request: EnvSetRequest = serde_json::from_str(
            r#"{"kind":"secret","value":"CANARY-9","hosts":["api.example.com"]}"#,
        )
        .unwrap();
        let shown = format!("{request:?}");
        assert!(!shown.contains("CANARY-9"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");

        for wrong in [
            r#"12345678"#,
            r#"1.5"#,
            r#"true"#,
            r#"["CANARY-9"]"#,
            r#"{"v":"CANARY-9"}"#,
            r#"-12345678"#,
        ] {
            let body = format!(r#"{{"kind":"secret","value":{wrong},"hosts":["a.example.com"]}}"#);
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            let err = EnvSetRequest::deserialize(value).unwrap_err().to_string();
            assert!(err.contains("must be a string"), "{err}");
            assert!(
                !err.contains("12345678") && !err.contains("CANARY"),
                "{err}"
            );
        }
        // The value may be left out: the secret keeps what it has.
        assert!(matches!(
            serde_json::from_str::<EnvSetRequest>(r#"{"kind":"secret","hosts":["a.example.com"]}"#)
                .unwrap(),
            EnvSetRequest::Secret { value: None, .. }
        ));
        // Unknown fields and kinds are refused.
        assert!(
            serde_json::from_str::<EnvSetRequest>(r#"{"kind":"plain","value":"x","extra":1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<EnvSetRequest>(r#"{"kind":"other"}"#).is_err());
    }

    #[test]
    fn a_secret_is_listed_by_name_and_hosts_and_never_by_value() {
        let db = store::Store::open_in_memory(
            std::sync::Arc::new(store::ManualClock::new(1)),
            store::Limits::default(),
        )
        .unwrap();
        let draft = store::EnvDraft::secret(
            puddle_secrets::StoredId::new("env-1").unwrap(),
            store::SecretHost::list(&["api.example.com"]).unwrap(),
        )
        .unwrap();
        let secret = db
            .set_env(
                &store::EnvScope::Global,
                &store::EnvName::new("T").unwrap(),
                draft,
            )
            .unwrap()
            .entry;
        let view = EnvVariable::from_store(secret, false);
        assert_eq!(view.kind, EnvKind::Secret);
        assert_eq!(view.value, None);
        assert_eq!(view.hosts, ["api.example.com"]);
        assert_eq!(view.scope, EnvScope::Global);
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains(r#""value":null"#), "{json}");
        assert!(
            !json.contains("env-1"),
            "the credential store's id is not shown: {json}"
        );
    }
}
