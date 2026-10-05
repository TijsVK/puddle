// SPDX-License-Identifier: GPL-3.0-or-later
//! One isolated msb world per test process: settings, private home, scoped SDK backend.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use microsandbox::sandbox::SandboxBuilder;
use microsandbox::{Backend, LocalBackend, Sandbox};
use puddle_types::SandboxName;

use crate::error::HarnessError;
use crate::prefix::RunPrefix;
use crate::runtime::{RuntimePair, refuse_ambient_msb_vars};
use crate::{PREFIX_VAR, ROOT_VAR, RUN_LABEL, RUNTIME_DIR_VAR};

/// Memory for harness sandboxes: enough for the devcontainer image, small enough that three
/// runs fit a 2-vCPU / 8 GB hosted runner.
const SANDBOX_MEMORY_MIB: u32 = 512;

/// How long cleanup waits for a sandbox to stop before killing it.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a run's runtime, prefix and private home come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Directory holding `msb` and `libkrunfw`.
    pub runtime_dir: PathBuf,
    /// The run prefix.
    pub prefix: RunPrefix,
    /// Directory the private home goes under.
    pub root: PathBuf,
}

impl Settings {
    /// Reads the settings through `lookup` (the process environment in [`VmEnv::from_env`]).
    ///
    /// # Errors
    ///
    /// [`HarnessError::AmbientMsbVar`] when an msb variable is set,
    /// [`HarnessError::MissingVar`] without a runtime directory,
    /// [`HarnessError::InvalidPrefix`] for a bad `PUDDLE_VM_PREFIX`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, HarnessError> {
        let get = |var: &str| lookup(var).filter(|value| !value.is_empty());
        refuse_ambient_msb_vars(get)?;
        let runtime_dir = get(RUNTIME_DIR_VAR).ok_or(HarnessError::MissingVar {
            var: RUNTIME_DIR_VAR,
            hint: "a directory with msb and libkrunfw from msb's release archive (ci/fetch-msb.sh)",
        })?;
        let prefix = RunPrefix::from_value_or_generate(get(PREFIX_VAR).as_deref())?;
        let root = get(ROOT_VAR).map_or_else(|| std::env::temp_dir().join("pvm"), PathBuf::from);
        Ok(Self {
            runtime_dir: PathBuf::from(runtime_dir),
            prefix,
            root,
        })
    }

    /// The private msb home of this run: `<root>/<prefix>`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join(self.prefix.as_str())
    }

    /// Finds the runtime pair, creates the private home and writes its `config.json`.
    ///
    /// # Errors
    ///
    /// Whatever [`RuntimePair::find_in`] reports, or [`HarnessError::Io`].
    pub fn prepare(&self) -> Result<RuntimePair, HarnessError> {
        let pair = RuntimePair::find_in(&self.runtime_dir)?;
        let home = self.home();
        std::fs::create_dir_all(&home).map_err(|e| HarnessError::io("create", &home, e))?;
        let config = config_path(&home);
        std::fs::write(&config, pair.config_json())
            .map_err(|e| HarnessError::io("write", &config, e))?;
        Ok(pair)
    }
}

fn config_path(home: &Path) -> PathBuf {
    home.join("config.json")
}

/// A ready VM test environment: settings, runtime pair and an SDK backend on the private home.
pub struct VmEnv {
    settings: Settings,
    runtime: RuntimePair,
    backend: Arc<dyn Backend>,
}

impl VmEnv {
    /// Sets up from the process environment (see the crate docs for the variables).
    ///
    /// # Errors
    ///
    /// Anything [`Settings::from_lookup`] or [`Settings::prepare`] reports, or
    /// [`HarnessError::Sdk`] when the backend can't open its database.
    pub async fn from_env() -> Result<Self, HarnessError> {
        Self::new(Settings::from_lookup(|var| std::env::var(var).ok())?).await
    }

    /// Sets up from explicit settings.
    ///
    /// # Errors
    ///
    /// As [`VmEnv::from_env`].
    pub async fn new(settings: Settings) -> Result<Self, HarnessError> {
        let runtime = settings.prepare()?;
        let home = settings.home();
        let local = LocalBackend::builder()
            .home(&home)
            .config_path(config_path(&home))
            .build()
            .await?;
        Ok(Self {
            settings,
            runtime,
            backend: Arc::new(local),
        })
    }

    /// The settings this environment was built from.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The runtime pair in use.
    #[must_use]
    pub fn runtime(&self) -> &RuntimePair {
        &self.runtime
    }

    /// The prefixed sandbox name for `tag`.
    ///
    /// # Errors
    ///
    /// [`HarnessError::InvalidName`] when `<prefix>-<tag>` isn't a valid sandbox name.
    pub fn sandbox_name(&self, tag: &str) -> Result<SandboxName, HarnessError> {
        self.settings.prefix.sandbox_name(tag)
    }

    /// A builder with the harness defaults: prefixed name, `image`, 1 vCPU, 512 MiB, the run
    /// label, and `replace` (a leftover of the same name from a crashed attempt is replaced).
    ///
    /// # Errors
    ///
    /// [`HarnessError::InvalidName`] for a bad `tag`.
    pub fn sandbox(&self, tag: &str, image: &str) -> Result<SandboxBuilder, HarnessError> {
        let name = self.sandbox_name(tag)?;
        Ok(Sandbox::builder(name.as_str())
            .image(image)
            .cpus(1)
            .memory(SANDBOX_MEMORY_MIB)
            .label(RUN_LABEL, self.settings.prefix.as_str())
            .replace())
    }

    /// Runs `future` with this environment's backend as the SDK default (task-local, so other
    /// tests in the process are unaffected).
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        microsandbox::with_backend(Arc::clone(&self.backend), future).await
    }

    /// Stops and removes every sandbox of this run, including ones a failed test left behind.
    /// Returns the names it removed.
    ///
    /// # Errors
    ///
    /// The first [`HarnessError::Sdk`] error; it still tries every sandbox.
    pub async fn cleanup(&self) -> Result<Vec<String>, HarnessError> {
        // Boxed: the SDK's futures are large (clippy::large_futures).
        self.scope(Box::pin(async {
            let page = Sandbox::list().await?;
            let mut removed = Vec::new();
            let mut first_error = None;
            for handle in page.sandboxes {
                let name = handle.name().to_owned();
                if !self.settings.prefix.owns(&name) {
                    continue;
                }
                if let Ok(sandbox) = handle.connect().await
                    && sandbox.stop_with_timeout(STOP_TIMEOUT).await.is_err()
                    && let Err(e) = sandbox.kill().await
                {
                    first_error.get_or_insert(HarnessError::from(e));
                }
                match Sandbox::remove(&name).await {
                    Ok(()) => removed.push(name),
                    Err(e) => {
                        first_error.get_or_insert(HarnessError::from(e));
                    }
                }
            }
            first_error.map_or(Ok(removed), Err)
        }))
        .await
    }

    /// Deletes the private home (image cache, database, logs). Call it only after a passing
    /// test, so a failure keeps msb's logs for the CI artefact.
    ///
    /// Takes the environment by value: the backend's database must be closed first, because
    /// Windows refuses to delete an open file (T-102 saw "being used by another process"). Files
    /// msb or SQLite release a moment later are retried for up to 5 s.
    ///
    /// # Errors
    ///
    /// [`HarnessError::Io`] when the directory still can't be removed.
    pub async fn remove_home(self) -> Result<(), HarnessError> {
        let home = self.settings.home();
        drop(self);
        remove_dir_retrying(&home, REMOVE_ATTEMPTS, REMOVE_BACKOFF).await
    }
}

/// How often [`VmEnv::remove_home`] tries, and how long it waits between tries.
const REMOVE_ATTEMPTS: u32 = 20;
const REMOVE_BACKOFF: Duration = Duration::from_millis(250);

/// Removes `dir` and everything in it; a missing `dir` counts as removed.
async fn remove_dir_retrying(
    dir: &Path,
    attempts: u32,
    backoff: Duration,
) -> Result<(), HarnessError> {
    let mut tried = 1;
    loop {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) if tried < attempts => {
                tried += 1;
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(HarnessError::io("remove", dir, e)),
        }
    }
}

/// Awaits `future` for at most `limit`.
///
/// # Errors
///
/// [`HarnessError::Timeout`] naming `what` when the budget runs out.
pub async fn within<T>(
    what: &'static str,
    limit: Duration,
    future: impl Future<Output = T>,
) -> Result<T, HarnessError> {
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_| HarnessError::Timeout { what, limit })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A temp dir removed on drop (no tempfile dependency for a few tests).
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("puddle-vm-tests-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0); // best effort; it's under the temp dir
        }
    }

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |var| map.get(var).cloned()
    }

    #[test]
    fn settings_read_runtime_prefix_and_root() {
        let settings = Settings::from_lookup(lookup(&[
            (RUNTIME_DIR_VAR, "/rt"),
            (PREFIX_VAR, "r9-1"),
            (ROOT_VAR, "/vm"),
        ]))
        .unwrap();
        assert_eq!(settings.runtime_dir, PathBuf::from("/rt"));
        assert_eq!(settings.prefix.as_str(), "r9-1");
        assert_eq!(settings.home(), PathBuf::from("/vm").join("r9-1"));
    }

    #[test]
    fn settings_default_the_prefix_and_root() {
        let settings = Settings::from_lookup(lookup(&[
            (RUNTIME_DIR_VAR, "/rt"),
            (PREFIX_VAR, ""),
            (ROOT_VAR, ""),
        ]))
        .unwrap();
        assert!(settings.prefix.as_str().starts_with('v'));
        assert_eq!(settings.root, std::env::temp_dir().join("pvm"));
    }

    #[test]
    fn settings_need_a_runtime_dir() {
        let err = Settings::from_lookup(lookup(&[(RUNTIME_DIR_VAR, "")])).unwrap_err();
        assert!(matches!(
            err,
            HarnessError::MissingVar {
                var: RUNTIME_DIR_VAR,
                ..
            }
        ));
    }

    #[test]
    fn settings_refuse_ambient_msb_vars_and_bad_prefixes() {
        let err = Settings::from_lookup(lookup(&[(RUNTIME_DIR_VAR, "/rt"), ("MSB_PATH", "/x")]))
            .unwrap_err();
        assert!(matches!(
            err,
            HarnessError::AmbientMsbVar { var: "MSB_PATH" }
        ));
        let err = Settings::from_lookup(lookup(&[(RUNTIME_DIR_VAR, "/rt"), (PREFIX_VAR, "UP")]))
            .unwrap_err();
        assert!(matches!(err, HarnessError::InvalidPrefix { .. }));
    }

    #[test]
    fn prepare_writes_the_private_home_config() {
        let runtime = TempDir::new("prep-rt");
        std::fs::write(
            runtime
                .path()
                .join(if cfg!(windows) { "msb.exe" } else { "msb" }),
            b"x",
        )
        .unwrap();
        let library = if cfg!(windows) {
            "libkrunfw.dll"
        } else {
            "libkrunfw.so.5"
        };
        std::fs::write(runtime.path().join(library), b"x").unwrap();
        let root = TempDir::new("prep-root");
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-1").unwrap(),
            root: root.path().to_owned(),
        };
        let pair = settings.prepare().unwrap();
        let written = std::fs::read_to_string(config_path(&settings.home())).unwrap();
        assert_eq!(written, pair.config_json());
        assert_eq!(pair.libkrunfw, runtime.path().join(library));
    }

    #[test]
    fn prepare_fails_on_an_incomplete_runtime() {
        let runtime = TempDir::new("prep-empty");
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-2").unwrap(),
            root: runtime.path().to_owned(),
        };
        assert!(matches!(
            settings.prepare().unwrap_err(),
            HarnessError::RuntimeIncomplete { .. }
        ));
    }

    #[test]
    fn prepare_reports_an_unwritable_home() {
        let runtime = TempDir::new("prep-file");
        std::fs::write(
            runtime
                .path()
                .join(if cfg!(windows) { "msb.exe" } else { "msb" }),
            b"x",
        )
        .unwrap();
        let library = if cfg!(windows) {
            "libkrunfw.dll"
        } else {
            "libkrunfw.so"
        };
        std::fs::write(runtime.path().join(library), b"x").unwrap();
        // The root is a file, so the home under it can't be created.
        let root = runtime.path().join(library);
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-3").unwrap(),
            root,
        };
        assert!(matches!(
            settings.prepare().unwrap_err(),
            HarnessError::Io {
                action: "create",
                ..
            }
        ));
    }

    /// A fake runtime pair is enough for everything short of booting: the backend opens its
    /// database in the private home, lists nothing and builds sandbox specs.
    fn fake_settings(tag: &str) -> (TempDir, Settings) {
        let dir = TempDir::new(tag);
        let msb = if cfg!(windows) { "msb.exe" } else { "msb" };
        let library = if cfg!(windows) {
            "libkrunfw.dll"
        } else {
            "libkrunfw.so"
        };
        std::fs::write(dir.path().join(msb), b"x").unwrap();
        std::fs::write(dir.path().join(library), b"x").unwrap();
        let settings = Settings {
            runtime_dir: dir.path().to_owned(),
            prefix: RunPrefix::new("r7-1").unwrap(),
            root: dir.path().join("root"),
        };
        (dir, settings)
    }

    #[tokio::test]
    async fn env_opens_a_private_home_without_booting() {
        let (_dir, settings) = fake_settings("env-open");
        let env = VmEnv::new(settings.clone()).await.unwrap();
        assert_eq!(env.settings(), &settings);
        assert_eq!(
            env.runtime().msb.parent(),
            Some(settings.runtime_dir.as_path())
        );
        assert!(settings.home().join("config.json").is_file());
        assert_eq!(env.sandbox_name("smoke").unwrap().as_str(), "r7-1-smoke");
        let builder = env.sandbox("smoke", crate::DEBIAN_DEVCONTAINER);
        assert!(builder.is_ok());
        assert!(env.sandbox("Bad_Tag", crate::DEBIAN_DEVCONTAINER).is_err());
        assert_eq!(Box::pin(env.cleanup()).await.unwrap(), Vec::<String>::new());
        env.remove_home().await.unwrap();
        assert!(!settings.home().exists());
    }

    #[tokio::test]
    async fn removal_accepts_a_missing_dir_and_reports_a_stuck_one() {
        let dir = TempDir::new("rm");
        let gone = dir.path().join("gone");
        remove_dir_retrying(&gone, 3, Duration::ZERO).await.unwrap();
        let full = dir.path().join("full");
        std::fs::create_dir_all(full.join("sub")).unwrap();
        std::fs::write(full.join("sub").join("f"), b"x").unwrap();
        remove_dir_retrying(&full, 3, Duration::ZERO).await.unwrap();
        assert!(!full.exists());
        // A plain file isn't a directory: every attempt fails, the last error is reported.
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let err = remove_dir_retrying(&file, 3, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                HarnessError::Io {
                    action: "remove",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn within_passes_values_and_names_timeouts() {
        assert_eq!(
            within("quick", Duration::from_secs(5), async { 7 })
                .await
                .unwrap(),
            7
        );
        let err = within(
            "slow",
            Duration::from_millis(10),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HarnessError::Timeout { what: "slow", .. }));
    }
}
