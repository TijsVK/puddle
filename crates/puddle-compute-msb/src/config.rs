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
    /// Session inactivity timeout; `None` turns it off (IDE sessions sit idle for long, T-114).
    pub inactivity_timeout: Option<Duration>,
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
    /// never puddle's data (database, tokens, CA keys). T-020 C-7.
    pub guest_share: PathBuf,
    /// SSH server settings.
    pub ssh: SshConfig,
}

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
        }
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

    /// The `config.json` contents: version 1 and the two runtime paths, nothing else, so every
    /// other setting is the SDK default listed in [`crate::SDK_OPTIONS`].
    #[must_use]
    pub fn config_json(&self) -> String {
        serde_json::json!({
            "version": 1,
            "paths": { "msb": self.msb, "libkrunfw": self.libkrunfw },
        })
        .to_string()
    }

    /// Checks that `host` lies under [`MsbConfig::guest_share`] after resolving symlinks and
    /// `..`, so a mount can never expose puddle's own data (T-020 C-7, T-029).
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
    fn config_json_pins_only_the_runtime_pair() {
        let c = MsbConfig::new("/h", "/rt/msb", "/rt/libkrunfw.so", "/share");
        let v: serde_json::Value = serde_json::from_str(&c.config_json()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["paths"]["msb"], "/rt/msb");
        assert_eq!(v["paths"]["libkrunfw"], "/rt/libkrunfw.so");
        assert_eq!(v.as_object().unwrap().len(), 2);
        assert_eq!(c.config_path(), PathBuf::from("/h").join("config.json"));
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
