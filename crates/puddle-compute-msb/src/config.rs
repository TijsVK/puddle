// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the adapter's msb world lives, and the mount-source rule.

use std::path::{Path, PathBuf};
use std::time::Duration;

use puddle_compute::ComputeError;

/// The SDK's SSH server settings for [`puddle_compute::Sandbox::serve_ssh`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    /// OpenSSH public key lines that may log in. The SDK refuses to serve without one.
    pub authorized_keys: Vec<String>,
    /// Session inactivity timeout; `None` turns it off (IDE sessions sit idle for long).
    pub inactivity_timeout: Option<Duration>,
}

/// The proxy the registry client sends image pulls through, as a URL that may carry credentials
/// (`http://puddle:<token>@127.0.0.1:<port>`). `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistryProxy(String);

impl RegistryProxy {
    /// The URL, credentials included. Only for handing to the SDK.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RegistryProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryProxy(<redacted>)")
    }
}

/// Everything [`crate::MsbRuntime::open`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsbConfig {
    /// puddle's private msb home (database, image cache, sandboxes, volumes, logs).
    pub home: PathBuf,
    /// The bundled `msb` binary.
    pub msb: PathBuf,
    /// The `libkrunfw` library released with it.
    pub libkrunfw: PathBuf,
    /// The only directory file mounts may come from: it holds just the files meant for guests,
    /// never puddle's data (database, tokens, CA keys).
    pub guest_share: PathBuf,
    /// SSH server settings.
    pub ssh: SshConfig,
    /// Extra roots the registry client trusts for image pulls, as PEM: the corporate roots
    /// (`puddle-certs`), so pulls work behind a TLS-intercepting company proxy.
    /// Added to the platform's roots, never instead of them.
    pub registry_roots: Vec<String>,
    /// Where image pulls go: puddle's pull proxy. Given to the SDK's registry client
    /// directly, so the token is never in the process environment. `None` leaves pulls
    /// to the process environment, which is what tests without a pull proxy want.
    pub registry_proxy: Option<RegistryProxy>,
    /// Default log level of msb's sandbox runtimes (`runtime.log`, msb's `log_level`): `error`,
    /// `warn`, `info`, `debug` or `trace`. [`DEFAULT_RUNTIME_LOG_LEVEL`] unless changed, so a rare
    /// boot failure in the field leaves the VMM's trace. `None` leaves msb's own default, which
    /// is silent. The VM tests set `debug`.
    pub runtime_log_level: Option<String>,
    /// Where [`crate::MsbRuntime`] copies a sandbox's `logs/` directory to before it removes the
    /// sandbox, as `<dir>/<sandbox>/logs/`. `None` (the default) keeps nothing: removing a sandbox
    /// deletes its logs. The VM tests set it so a failed boot keeps its full logs as CI artifacts.
    pub keep_logs_dir: Option<PathBuf>,
}

/// The default [`MsbConfig::runtime_log_level`]. `info` is a few lines per boot; msb rotates
/// `runtime.log` at 10 MiB on Linux and macOS (3 rotated files kept). On Windows msb appends
/// without rotating, which [`crate::MsbRuntime`] bounds itself (see [`RUNTIME_LOG_CAP_BYTES`]).
pub const DEFAULT_RUNTIME_LOG_LEVEL: &str = "info";

/// The size at which [`crate::MsbRuntime`] moves a sandbox's `runtime.log` aside to
/// `runtime.log.1` (replacing an older one) before it starts the sandbox. It matches msb's own
/// rotation size on Linux and macOS, and makes Windows, where msb never rotates, as bounded
/// (about twice the cap per sandbox).
pub const RUNTIME_LOG_CAP_BYTES: u64 = 10 * 1024 * 1024;

impl MsbConfig {
    /// A config for msb home `home`, runtime pair `msb` + `libkrunfw` and guest-share root
    /// `guest_share`, with no SSH keys.
    #[must_use]
    pub fn new(
        home: impl Into<PathBuf>,
        msb: impl Into<PathBuf>,
        libkrunfw: impl Into<PathBuf>,
        guest_share: impl Into<PathBuf>,
    ) -> Self {
        Self {
            home: home.into(),
            msb: msb.into(),
            libkrunfw: libkrunfw.into(),
            guest_share: guest_share.into(),
            ssh: SshConfig::default(),
            registry_roots: Vec::new(),
            registry_proxy: None,
            runtime_log_level: Some(DEFAULT_RUNTIME_LOG_LEVEL.to_owned()),
            keep_logs_dir: None,
        }
    }

    /// The same config, with msb's sandbox runtimes logging at `level`; `None` keeps the level
    /// the config has (by default [`DEFAULT_RUNTIME_LOG_LEVEL`]), so a test can pass an optional
    /// override straight through.
    #[must_use]
    pub fn with_runtime_log_level(mut self, level: Option<impl Into<String>>) -> Self {
        if let Some(level) = level {
            self.runtime_log_level = Some(level.into());
        }
        self
    }

    /// The same config, keeping a removed sandbox's `logs/` under `dir` (see
    /// [`MsbConfig::keep_logs_dir`]).
    #[must_use]
    pub fn with_keep_logs_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.keep_logs_dir = Some(dir.into());
        self
    }

    /// The same config, with image pulls also trusting `roots` (PEM, one or more certificates
    /// each).
    #[must_use]
    pub fn with_registry_roots(mut self, roots: impl IntoIterator<Item = String>) -> Self {
        self.registry_roots.extend(roots);
        self
    }

    /// The same config, with image pulls sent through the proxy at `url` (credentials allowed).
    /// The SDK's registry client takes it as its own setting and ignores the proxy variables of
    /// the process environment for those pulls.
    #[must_use]
    pub fn with_registry_proxy(mut self, url: impl Into<String>) -> Self {
        self.registry_proxy = Some(RegistryProxy(url.into()));
        self
    }

    /// The same config, accepting SSH logins with `key` (an OpenSSH public key line).
    #[must_use]
    pub fn with_ssh_key(mut self, key: impl Into<String>) -> Self {
        self.ssh.authorized_keys.push(key.into());
        self
    }

    /// msb's `config.json` in the home: the runtime pair, written by
    /// [`crate::MsbRuntime::open`].
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.home.join("config.json")
    }

    /// The `config.json` contents: version 1, the two runtime paths and, when set, the
    /// runtimes' `log_level`; nothing else, so every other setting is the SDK default listed in
    /// [`crate::SDK_OPTIONS`].
    #[must_use]
    pub fn config_json(&self) -> String {
        let mut config = serde_json::Map::new();
        config.insert("version".into(), 1.into());
        config.insert(
            "paths".into(),
            serde_json::json!({ "msb": self.msb, "libkrunfw": self.libkrunfw }),
        );
        if let Some(level) = &self.runtime_log_level {
            config.insert("log_level".into(), level.as_str().into());
        }
        serde_json::Value::Object(config).to_string()
    }

    /// Checks that `host` lies under [`MsbConfig::guest_share`] after resolving symlinks and
    /// `..`, so a mount can never expose puddle's own data.
    ///
    /// # Errors
    ///
    /// [`ComputeError::InvalidSpec`] when it doesn't, or when either path can't be resolved.
    pub fn check_mount_source(&self, host: &Path) -> Result<(), ComputeError> {
        let invalid = |reason: String| ComputeError::InvalidSpec { reason };
        let root = self.guest_share.canonicalize().map_err(|e| {
            invalid(format!(
                "guest-share root {} can't be resolved: {e}",
                self.guest_share.display()
            ))
        })?;
        let source = host.canonicalize().map_err(|e| {
            invalid(format!(
                "mount source {} can't be resolved: {e}",
                host.display()
            ))
        })?;
        if source.starts_with(&root) && source != root {
            Ok(())
        } else {
            Err(invalid(format!(
                "mount source {} is outside the guest-share root {}",
                host.display(),
                self.guest_share.display()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("puddle-msb-config-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_registry_proxy_is_kept_but_never_shown_or_written() {
        let url = "http://puddle:t0k3n@127.0.0.1:4000";
        let plain = MsbConfig::new("/h", "/rt/msb", "/rt/libkrunfw.so", "/share");
        assert_eq!(plain.registry_proxy, None);
        let c = plain.clone().with_registry_proxy(url);
        assert_eq!(
            c.registry_proxy.as_ref().map(RegistryProxy::expose),
            Some(url)
        );
        assert!(!format!("{c:?}").contains("t0k3n"), "{c:?}");
        assert_eq!(c.config_json(), plain.config_json());
    }

    #[test]
    fn config_json_pins_only_the_runtime_pair_and_the_log_level() {
        let mut c = MsbConfig::new("/h", "/rt/msb", "/rt/libkrunfw.so", "/share");
        c.runtime_log_level = None;
        let v: serde_json::Value = serde_json::from_str(&c.config_json()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["paths"]["msb"], "/rt/msb");
        assert_eq!(v["paths"]["libkrunfw"], "/rt/libkrunfw.so");
        assert_eq!(v.as_object().unwrap().len(), 2);
        assert_eq!(c.config_path(), PathBuf::from("/h").join("config.json"));
    }

    #[test]
    fn the_runtime_log_level_defaults_to_info_and_none_keeps_what_is_set() {
        let plain = MsbConfig::new("/h", "/m", "/l", "/s");
        assert_eq!(plain.runtime_log_level.as_deref(), Some("info"));
        let v: serde_json::Value = serde_json::from_str(&plain.config_json()).unwrap();
        assert_eq!(v["log_level"], "info");
        let c = plain.clone().with_runtime_log_level(Some("debug"));
        let v: serde_json::Value = serde_json::from_str(&c.config_json()).unwrap();
        assert_eq!(v["log_level"], "debug");
        assert_eq!(v["paths"]["msb"], "/m");
        let same = c.clone().with_runtime_log_level(None::<String>);
        assert_eq!(same.config_json(), c.config_json());
        let mut silent = plain;
        silent.runtime_log_level = None;
        let v: serde_json::Value = serde_json::from_str(&silent.config_json()).unwrap();
        assert!(v.get("log_level").is_none());
    }

    #[test]
    fn kept_logs_are_off_unless_a_directory_is_given() {
        let c = MsbConfig::new("/h", "/m", "/l", "/s");
        assert_eq!(c.keep_logs_dir, None);
        let c = c.with_keep_logs_dir("/kept");
        assert_eq!(c.keep_logs_dir, Some(PathBuf::from("/kept")));
    }

    #[test]
    fn ssh_keys_accumulate_and_the_timeout_is_off_by_default() {
        let c = MsbConfig::new("/h", "/m", "/l", "/s")
            .with_ssh_key("ssh-ed25519 AAAA a")
            .with_ssh_key("ssh-ed25519 BBBB b");
        assert_eq!(c.ssh.authorized_keys.len(), 2);
        assert_eq!(c.ssh.inactivity_timeout, None);
    }

    #[test]
    fn mount_sources_must_be_inside_the_guest_share_root() {
        let dir = Dir::new("mounts");
        let share = dir.0.join("guest-share");
        let data = dir.0.join("data");
        std::fs::create_dir_all(share.join("boot")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(share.join("boot").join("boot.sh"), b"x").unwrap();
        std::fs::write(data.join("puddle.db"), b"x").unwrap();
        let c = MsbConfig::new("/h", "/m", "/l", &share);

        c.check_mount_source(&share.join("boot").join("boot.sh"))
            .unwrap();
        let outside = c.check_mount_source(&data.join("puddle.db")).unwrap_err();
        assert!(
            outside.to_string().contains("outside the guest-share root"),
            "{outside}"
        );
        // `..` can't climb out: the path is resolved first.
        let climb = share
            .join("boot")
            .join("..")
            .join("..")
            .join("data")
            .join("puddle.db");
        assert!(c.check_mount_source(&climb).is_err());
        // The root itself isn't a file meant for a guest.
        assert!(c.check_mount_source(&share).is_err());
        // A missing source or root is refused, not assumed fine.
        let missing = c.check_mount_source(&share.join("nope")).unwrap_err();
        assert!(
            missing.to_string().contains("can't be resolved"),
            "{missing}"
        );
        let no_root = MsbConfig::new("/h", "/m", "/l", dir.0.join("absent"));
        assert!(no_root.check_mount_source(&data.join("puddle.db")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_share_cannot_point_outside() {
        let dir = Dir::new("symlink");
        let share = dir.0.join("guest-share");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(dir.0.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.0.join("secret"), share.join("link")).unwrap();
        let c = MsbConfig::new("/h", "/m", "/l", &share);
        assert!(c.check_mount_source(&share.join("link")).is_err());
    }
}
