// SPDX-License-Identifier: GPL-3.0-or-later
//! Schema versions and the migration runner.
//!
//! A document's `schema_version` names the shape it was written in. Version 1 is the first
//! shape, so there are no migrations yet. To change a shape:
//!
//! 1. bump the kind's `*_SCHEMA_VERSION`;
//! 2. append a [`Migration`] with `from` = the old version to the kind's list (`GLOBAL` or
//!    `SANDBOX` below); it rewrites the JSON object in place (rename a key, convert a value);
//! 3. add a test that loads a stored document of the old version and checks the result.
//!
//! The lists are checked by a unit test: one step per version, in order, none missing.

use serde_json::{Map, Value};

use crate::SettingsError;

/// One step: rewrites a document of version `from` into version `from + 1`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Migration {
    pub(crate) from: u32,
    pub(crate) apply: fn(&mut Map<String, Value>) -> Result<(), String>,
}

/// Steps for [`crate::GlobalSettings`], oldest first.
pub(crate) const GLOBAL: &[Migration] = &[];
/// Steps for [`crate::SandboxSettings`], oldest first.
pub(crate) const SANDBOX: &[Migration] = &[];

/// The key every document carries its version under.
pub(crate) const VERSION_KEY: &str = "schema_version";

/// Takes `doc` apart into its version and the remaining object, and migrates that object up to
/// `current`. Returns the migrated object and the version it was read in.
pub(crate) fn upgrade(
    kind: &'static str,
    doc: Value,
    current: u32,
    steps: &[Migration],
) -> Result<(Map<String, Value>, u32), SettingsError> {
    let Value::Object(mut map) = doc else {
        return Err(SettingsError::NotAnObject { kind });
    };
    let found = match map.remove(VERSION_KEY) {
        None => 1,
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n >= 1)
            .ok_or_else(|| SettingsError::InvalidVersion {
                kind,
                found: truncate(&v.to_string()),
            })?,
    };
    if found > current {
        return Err(SettingsError::NewerSchema {
            kind,
            found,
            supported: current,
        });
    }
    let mut version = found;
    while version < current {
        let step = steps
            .iter()
            .find(|m| m.from == version)
            .ok_or(SettingsError::Migration {
                kind,
                from: version,
                reason: "no migration for this version".to_owned(),
            })?;
        (step.apply)(&mut map).map_err(|reason| SettingsError::Migration {
            kind,
            from: version,
            reason,
        })?;
        version += 1;
    }
    Ok((map, found))
}

fn truncate(s: &str) -> String {
    const MAX: usize = 32;
    let mut out: String = s.chars().take(MAX).collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn complete(steps: &[Migration], current: u32) {
        let starts: Vec<u32> = steps.iter().map(|m| m.from).collect();
        let want: Vec<u32> = (1..current).collect();
        assert_eq!(starts, want, "one migration per version, in order");
    }

    #[test]
    fn every_kind_has_a_complete_chain() {
        complete(GLOBAL, crate::GLOBAL_SCHEMA_VERSION);
        complete(SANDBOX, crate::SANDBOX_SCHEMA_VERSION);
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "has the signature of Migration::apply"
    )]
    fn rename_a_to_b(m: &mut Map<String, Value>) -> Result<(), String> {
        if let Some(v) = m.remove("a") {
            m.insert("b".to_owned(), v);
        }
        Ok(())
    }

    fn double_b(m: &mut Map<String, Value>) -> Result<(), String> {
        let Some(b) = m.get("b") else { return Ok(()) };
        let n = b.as_u64().ok_or("b is not a number")?;
        m.insert("b".to_owned(), json!(n * 2));
        Ok(())
    }

    const STEPS: &[Migration] = &[
        Migration {
            from: 1,
            apply: rename_a_to_b,
        },
        Migration {
            from: 2,
            apply: double_b,
        },
    ];

    #[test]
    fn steps_run_in_order_from_the_stored_version() {
        let (m, found) = upgrade("t", json!({"schema_version":1,"a":5}), 3, STEPS).unwrap();
        assert_eq!(found, 1);
        assert_eq!(Value::Object(m), json!({"b":10}));

        let (m, found) = upgrade("t", json!({"schema_version":2,"b":5}), 3, STEPS).unwrap();
        assert_eq!(found, 2);
        assert_eq!(Value::Object(m), json!({"b":10}));

        let (m, found) = upgrade("t", json!({"schema_version":3,"b":5}), 3, STEPS).unwrap();
        assert_eq!(found, 3);
        assert_eq!(Value::Object(m), json!({"b":5}));
    }

    #[test]
    fn a_missing_version_is_version_one() {
        let (m, found) = upgrade("t", json!({"a":1}), 3, STEPS).unwrap();
        assert_eq!(found, 1);
        assert_eq!(Value::Object(m), json!({"b":2}));
    }

    #[test]
    fn a_failing_step_names_its_version() {
        let err = upgrade("t", json!({"schema_version":2,"b":"x"}), 3, STEPS).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot migrate t settings from schema version 2: b is not a number"
        );
    }

    #[test]
    fn a_gap_in_the_chain_is_an_error_not_a_skip() {
        let err = upgrade("t", json!({"schema_version":1}), 3, &STEPS[1..]).unwrap_err();
        assert!(
            matches!(err, SettingsError::Migration { from: 1, .. }),
            "{err}"
        );
    }

    #[test]
    fn newer_documents_are_refused() {
        let err = upgrade("t", json!({"schema_version":4}), 3, STEPS).unwrap_err();
        assert_eq!(
            err,
            SettingsError::NewerSchema {
                kind: "t",
                found: 4,
                supported: 3
            }
        );
        assert!(err.to_string().contains("newer puddle"), "{err}");
    }

    #[test]
    fn bad_versions_and_non_objects_are_refused() {
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(null),
            json!(u64::from(u32::MAX) + 1),
        ] {
            let err = upgrade("t", json!({ "schema_version": bad }), 3, STEPS).unwrap_err();
            assert!(
                matches!(err, SettingsError::InvalidVersion { .. }),
                "{bad}: {err}"
            );
        }
        let err = upgrade("t", json!({ "schema_version": "x".repeat(100) }), 3, STEPS).unwrap_err();
        assert!(err.to_string().len() < 120, "{err}");
        for bad in [json!([]), json!(1), json!(null), json!("{}")] {
            assert_eq!(
                upgrade("t", bad, 3, STEPS).unwrap_err(),
                SettingsError::NotAnObject { kind: "t" }
            );
        }
    }
}
