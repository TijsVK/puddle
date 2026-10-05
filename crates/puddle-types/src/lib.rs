// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared types for puddle's crates: identifiers, wire types and errors that cross crate
//! boundaries. Keep this crate small and free of I/O, so every other crate can depend on it.
#![forbid(unsafe_code)]

/// puddle's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The line a puddle binary prints for `--version`: the program name and puddle's version.
///
/// ```
/// assert_eq!(puddle_types::version_line("puddle"), format!("puddle {}", puddle_types::VERSION));
/// ```
#[must_use]
pub fn version_line(program: &str) -> String {
    format!("{program} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, "0.0.0");
    }

    #[test]
    fn version_line_names_program_then_version() {
        assert_eq!(version_line("puddle-agent"), "puddle-agent 0.0.0");
    }
}
