// SPDX-License-Identifier: GPL-3.0-or-later
//! The secret value type: redacted, zeroised, never copied by accident.

use std::fmt;

use zeroize::Zeroize;

/// A secret value. `Debug` prints `<redacted>`, there is no `Display`, `Clone` or `Serialize`, and
/// the bytes are overwritten when the value drops. Share one with an [`std::sync::Arc`].
pub struct Secret(String);

impl Secret {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value, for the one place that puts it on the wire. Keep the borrow short.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_shows_the_value() {
        let s = Secret::new("CANARY-value".to_owned());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), "CANARY-value");
    }
}
