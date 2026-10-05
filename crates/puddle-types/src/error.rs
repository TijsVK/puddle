// SPDX-License-Identifier: GPL-3.0-or-later
//! The validation error shared by every checked type in this crate.

use std::fmt;

/// Longest prefix of a rejected value kept in a [`ValidationError`]. Rejected values can come
/// from a hostile guest or a config file, so the error never carries an unbounded copy.
const MAX_ECHOED_CHARS: usize = 64;

/// A value was rejected by one of this crate's checked constructors.
///
/// The message names the kind of value, the (truncated, escaped) value itself and the rule it
/// broke, e.g. `invalid sandbox name "Foo": may only contain a-z, 0-9 and '-'`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {what} {value:?}: {reason}")]
pub struct ValidationError {
    what: &'static str,
    value: String,
    reason: String,
}

impl ValidationError {
    /// A new error for `what` (e.g. `"sandbox name"`), the rejected `value` and the `reason`.
    #[must_use]
    pub fn new(what: &'static str, value: &str, reason: impl fmt::Display) -> Self {
        let mut echoed: String = value.chars().take(MAX_ECHOED_CHARS).collect();
        if value.chars().count() > MAX_ECHOED_CHARS {
            echoed.push('…');
        }
        Self {
            what,
            value: echoed,
            reason: reason.to_string(),
        }
    }

    /// What kind of value was rejected (e.g. `"sandbox name"`).
    #[must_use]
    pub fn what(&self) -> &'static str {
        self.what
    }

    /// The rule the value broke.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_names_kind_value_and_reason() {
        let e = ValidationError::new("sandbox name", "Foo", "must be lower-case");
        assert_eq!(
            e.to_string(),
            r#"invalid sandbox name "Foo": must be lower-case"#
        );
        assert_eq!(e.what(), "sandbox name");
        assert_eq!(e.reason(), "must be lower-case");
    }

    #[test]
    fn long_values_are_truncated() {
        let long = "x".repeat(10_000);
        let e = ValidationError::new("thing", &long, "too long");
        assert!(e.to_string().len() < 120, "{e}");
        assert!(e.to_string().contains('…'));
    }

    #[test]
    fn control_characters_are_escaped_in_the_message() {
        let e = ValidationError::new("thing", "a\nb\u{1b}[31m", "bad");
        assert!(!e.to_string().contains('\n'));
        assert!(!e.to_string().contains('\u{1b}'));
    }
}
