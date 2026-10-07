// SPDX-License-Identifier: GPL-3.0-or-later
//! The environment that makes the msb SDK use puddle's runtime and home, and nothing of the user's.
//!
//! The SDK reads its paths from the process environment, and a user's `MSB_PATH` beats the SDK's
//! own `set_sdk_msb_path`. msb also reads `MSB_BACKEND`, `MSB_API_URL`,
//! `MSB_PROFILE` and more, any of which could redirect puddle. So the rule is simple: remove
//! every `MSB_*` variable, then set exactly the three puddle owns.

use std::ffi::{OsStr, OsString};
use std::process::Command;

use crate::RuntimeLayout;

/// Whether `name` is one of msb's variables: starts with `MSB_`, ASCII case-insensitively
/// (Windows environment names are case-insensitive, so `msb_path` counts too).
#[must_use]
pub fn is_msb_variable(name: &OsStr) -> bool {
    name.as_encoded_bytes()
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"MSB_"))
}

/// The environment changes for the bundled runtime: variables to remove, then variables to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEnv {
    remove: Vec<OsString>,
    set: Vec<(&'static str, OsString)>,
}

impl RuntimeEnv {
    /// The plan for `layout`, given the current environment `vars` (normally
    /// [`std::env::vars_os`]): every `MSB_*` name in `vars` is removed, then `MSB_PATH`,
    /// `MSB_HOME` and `MSB_CONFIG_PATH` are set to the layout's absolute paths.
    #[must_use]
    pub fn plan(
        layout: &RuntimeLayout,
        vars: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Self {
        let mut remove: Vec<OsString> = vars
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| is_msb_variable(name))
            .collect();
        remove.sort();
        remove.dedup();
        let set = vec![
            ("MSB_PATH", layout.msb_path().into_os_string()),
            ("MSB_HOME", layout.home().as_os_str().to_owned()),
            ("MSB_CONFIG_PATH", layout.config_path().into_os_string()),
        ];
        Self { remove, set }
    }

    /// The variables removed (each user-set `MSB_*` name, sorted).
    #[must_use]
    pub fn removed(&self) -> &[OsString] {
        &self.remove
    }

    /// The variables set, in order: `MSB_PATH`, `MSB_HOME`, `MSB_CONFIG_PATH`.
    #[must_use]
    pub fn set(&self) -> &[(&'static str, OsString)] {
        &self.set
    }

    /// Applies the plan to a child process: removes the user's `MSB_*` variables from what the
    /// child inherits and sets puddle's.
    pub fn apply_to(&self, command: &mut Command) {
        for name in &self.remove {
            command.env_remove(name);
        }
        for (name, value) in &self.set {
            command.env(name, value);
        }
    }

    /// Applies the plan to puddle's own process, so the msb SDK (which reads the process
    /// environment) uses the bundled runtime and private home.
    ///
    /// # Safety
    ///
    /// Changing the process environment is only sound while no other thread reads or writes it
    /// ([`std::env::set_var`]). Call this first thing in `main`, before the tokio runtime or any
    /// other thread starts.
    #[expect(
        unsafe_code,
        reason = "the SDK only reads its paths from the process environment"
    )]
    pub unsafe fn apply_to_process(&self) {
        for name in &self.remove {
            // SAFETY: the caller guarantees no other thread touches the environment (see # Safety).
            unsafe { std::env::remove_var(name) };
        }
        for (name, value) in &self.set {
            // SAFETY: as above.
            unsafe { std::env::set_var(name, value) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn layout() -> RuntimeLayout {
        let root = std::env::temp_dir();
        RuntimeLayout::new(root.join("rt"), root.join("home")).unwrap()
    }

    fn vars(names: &[&str]) -> Vec<(OsString, OsString)> {
        names
            .iter()
            .map(|n| (OsString::from(n), OsString::from("/user/value")))
            .collect()
    }

    #[test]
    fn every_msb_variable_is_removed_and_nothing_else() {
        let env = RuntimeEnv::plan(
            &layout(),
            vars(&[
                "PATH",
                "MSB_PATH",
                "MSB_LIBKRUNFW_PATH",
                "MSB_AGENTD_PATH",
                "MSB_BACKEND",
                "msb_home",
                "Msb_Api_Key",
                "MSBX",
                "MY_MSB_PATH",
                "HOME",
            ]),
        );
        let removed: Vec<_> = env.removed().iter().map(|n| n.to_str().unwrap()).collect();
        assert_eq!(
            removed,
            [
                "MSB_AGENTD_PATH",
                "MSB_BACKEND",
                "MSB_LIBKRUNFW_PATH",
                "MSB_PATH",
                "Msb_Api_Key",
                "msb_home"
            ]
        );
    }

    #[test]
    fn sets_exactly_path_home_and_config_to_absolute_paths() {
        let l = layout();
        let env = RuntimeEnv::plan(&l, vars(&["MSB_PATH"]));
        let set: Vec<_> = env
            .set()
            .iter()
            .map(|(n, v)| (*n, PathBuf::from(v)))
            .collect();
        assert_eq!(
            set,
            [
                ("MSB_PATH", l.msb_path()),
                ("MSB_HOME", l.home().to_path_buf()),
                ("MSB_CONFIG_PATH", l.config_path()),
            ]
        );
        assert!(set.iter().all(|(_, p)| p.is_absolute()));
        // The firmware and agent paths stay unset: msb finds them next to its own binary.
        assert!(
            env.set()
                .iter()
                .all(|(n, _)| *n != "MSB_LIBKRUNFW_PATH" && *n != "MSB_AGENTD_PATH")
        );
    }

    #[test]
    fn prefix_match_is_exact_about_the_underscore() {
        assert!(is_msb_variable(OsStr::new("MSB_")));
        assert!(is_msb_variable(OsStr::new("msb_x")));
        assert!(!is_msb_variable(OsStr::new("MSB")));
        assert!(!is_msb_variable(OsStr::new("MSBPATH")));
        assert!(!is_msb_variable(OsStr::new("")));
    }

    #[test]
    fn command_gets_the_plan() {
        let env = RuntimeEnv::plan(&layout(), vars(&["MSB_BACKEND"]));
        let mut cmd = Command::new("msb");
        env.apply_to(&mut cmd);
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap().to_owned(), v.is_some()))
            .collect();
        assert!(envs.contains(&("MSB_BACKEND".into(), false)));
        assert!(envs.contains(&("MSB_PATH".into(), true)));
        assert!(envs.contains(&("MSB_HOME".into(), true)));
        assert!(envs.contains(&("MSB_CONFIG_PATH".into(), true)));
    }
}
