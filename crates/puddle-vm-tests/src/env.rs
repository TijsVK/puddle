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
use crate::{MSB_LOG_LEVEL_VAR, PREFIX_VAR, ROOT_VAR, RUN_LABEL, RUNTIME_DIR_VAR};

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
    /// Default log level of msb's sandbox runtimes (`runtime.log`); `None` leaves them silent.
    pub msb_log_level: Option<String>,
}

/// The levels msb's `config.json` accepts for `log_level`.
const MSB_LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

impl Settings {
    /// Reads the settings through `lookup` (the process environment in [`VmEnv::from_env`]).
    ///
    /// # Errors
    ///
    /// [`HarnessError::AmbientMsbVar`] when an msb variable is set,
    /// [`HarnessError::MissingVar`] without a runtime directory,
    /// [`HarnessError::InvalidPrefix`] for a bad `PUDDLE_VM_PREFIX`,
    /// [`HarnessError::InvalidLogLevel`] for a bad `PUDDLE_VM_MSB_LOG_LEVEL`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, HarnessError> {
        let get = |var: &str| lookup(var).filter(|value| !value.is_empty());
        refuse_ambient_msb_vars(get)?;
        let runtime_dir = get(RUNTIME_DIR_VAR).ok_or(HarnessError::MissingVar {
            var: RUNTIME_DIR_VAR,
            hint: "a directory with msb and libkrunfw from msb's release archive (ci/fetch-msb.sh)",
        })?;
        let prefix = RunPrefix::from_value_or_generate(get(PREFIX_VAR).as_deref())?;
        let root = get(ROOT_VAR).map_or_else(|| std::env::temp_dir().join("pvm"), PathBuf::from);
        let msb_log_level = get(MSB_LOG_LEVEL_VAR).map(|v| v.to_ascii_lowercase());
        if let Some(level) = &msb_log_level
            && !MSB_LOG_LEVELS.contains(&level.as_str())
        {
            return Err(HarnessError::InvalidLogLevel {
                value: level.chars().take(64).collect(),
            });
        }
        Ok(Self {
            runtime_dir: PathBuf::from(runtime_dir),
            prefix,
            root,
            msb_log_level,
        })
    }

    /// The private msb home of this run: `<root>/<prefix>`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join(self.prefix.as_str())
    }

    /// A second, empty msb home beside the run's: `<root>/<prefix>-<tag>`. For a test that needs
    /// an image cache nothing else has filled. It stays a sibling (not below [`Self::home`]) and
    /// the tag should be a few characters, because msb derives Unix socket paths from the home
    /// and refuses 108 bytes or more.
    #[must_use]
    pub fn scratch_home(&self, tag: &str) -> PathBuf {
        self.root.join(format!("{}-{tag}", self.prefix.as_str()))
    }

    /// Where [`VmEnv::cleanup`] keeps the logs of the sandboxes it removes:
    /// `<root>/<prefix>-kept/<sandbox>/logs/`. A sibling of [`Self::home`], so a later passing
    /// test's [`VmEnv::remove_home`] doesn't delete a failed test's evidence.
    #[must_use]
    pub fn kept_logs(&self) -> PathBuf {
        self.root.join(format!("{}-kept", self.prefix.as_str()))
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
        std::fs::write(&config, pair.config_json(self.msb_log_level.as_deref()))
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
    sandboxes_dir: PathBuf,
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
            sandboxes_dir: local.sandboxes_dir(),
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
    /// Returns the names it removed. Each sandbox's msb logs are copied to
    /// [`Settings::kept_logs`] first, so a boot that failed keeps its evidence for the CI
    /// artefact; [`VmEnv::remove_home`] deletes them after a passing test.
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
                keep_logs(
                    &self.sandboxes_dir.join(&name).join(MSB_LOGS_DIR),
                    &self.settings.kept_logs().join(&name).join(MSB_LOGS_DIR),
                );
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
    /// Windows refuses to delete an open file ("being used by another process"). Files
    /// msb or SQLite release a moment later are retried for up to 5 s.
    ///
    /// # Errors
    ///
    /// [`HarnessError::Io`] when the directory still can't be removed.
    pub async fn remove_home(self) -> Result<(), HarnessError> {
        let home = self.settings.home();
        let kept = self.settings.kept_logs();
        drop(self);
        remove_metrics_segments(&home);
        remove_dir_retrying(&home, REMOVE_ATTEMPTS, REMOVE_BACKOFF).await?;
        remove_dir_retrying(&kept, REMOVE_ATTEMPTS, REMOVE_BACKOFF).await
    }
}

/// The registry ABI versions whose segment msb may have created for a home (current and legacy).
const METRICS_ABIS: [u32; 2] = [2, 3];

/// The POSIX shared-memory object names (without the leading `/`) msb's metrics registry uses for
/// `home`: `msb-met-<FNV-1a 64 of the home path's bytes>-v<abi>`. msb creates one per home on the
/// first sandbox start and never unlinks it.
fn metrics_segment_names(home: &Path) -> Vec<String> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in home.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    METRICS_ABIS
        .iter()
        .map(|abi| format!("msb-met-{hash:016x}-v{abi}"))
        .collect()
}

/// Unlinks the metrics segments msb left for the private `home`, so a test run leaves nothing in
/// `/dev/shm`. Best effort. Only Linux shows these as files; Windows frees the mapping with its
/// last handle, and macOS names live outside the file system.
fn remove_metrics_segments(home: &Path) {
    if cfg!(target_os = "linux") {
        for name in metrics_segment_names(home) {
            let _ = std::fs::remove_file(Path::new("/dev/shm").join(name));
        }
    }
}

/// The directory under `sandboxes/<name>/` where msb writes `runtime.log` and `kernel.log`.
const MSB_LOGS_DIR: &str = "logs";

/// Copies the files of `from` into `to`, best effort: a sandbox that never got a log directory
/// has nothing to keep, and a copy that fails must not fail the cleanup.
fn keep_logs(from: &Path, to: &Path) {
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    if std::fs::create_dir_all(to).is_err() {
        return;
    }
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            let _ = std::fs::copy(&path, to.join(entry.file_name()));
        }
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

    use puddle_runtime::HostOs;

    use super::*;

    #[test]
    fn the_metrics_segment_name_matches_msbs_hash_of_the_home() {
        // Value from msb's own `metrics_registry_shm_name` for this path.
        assert_eq!(
            metrics_segment_names(Path::new("/tmp/msb-abc123")),
            ["msb-met-d63328847086d141-v2", "msb-met-d63328847086d141-v3"]
        );
    }

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
    fn settings_read_the_msb_log_level_and_refuse_unknown_ones() {
        let base = [(RUNTIME_DIR_VAR, "/rt"), (PREFIX_VAR, "r9-1")];
        let unset = Settings::from_lookup(lookup(&base)).unwrap();
        assert_eq!(unset.msb_log_level, None);
        let empty = Settings::from_lookup(lookup(&[base[0], base[1], (MSB_LOG_LEVEL_VAR, "")]));
        assert_eq!(empty.unwrap().msb_log_level, None);
        let debug =
            Settings::from_lookup(lookup(&[base[0], base[1], (MSB_LOG_LEVEL_VAR, "Debug")]));
        assert_eq!(debug.unwrap().msb_log_level.as_deref(), Some("debug"));
        let err = Settings::from_lookup(lookup(&[base[0], base[1], (MSB_LOG_LEVEL_VAR, "loud")]))
            .unwrap_err();
        assert!(matches!(err, HarnessError::InvalidLogLevel { value } if value == "loud"));
    }

    #[test]
    fn kept_logs_are_a_sibling_of_the_run_home() {
        let settings = Settings::from_lookup(lookup(&[
            (RUNTIME_DIR_VAR, "/rt"),
            (PREFIX_VAR, "r9-1"),
            (ROOT_VAR, "/vm"),
        ]))
        .unwrap();
        assert_eq!(settings.kept_logs(), PathBuf::from("/vm").join("r9-1-kept"));
        assert!(!settings.kept_logs().starts_with(settings.home()));
    }

    #[test]
    fn keep_logs_copies_the_files_and_tolerates_a_missing_dir() {
        let dir = TempDir::new("keep");
        let from = dir.path().join("sandboxes").join("sb").join("logs");
        std::fs::create_dir_all(from.join("nested")).unwrap();
        std::fs::write(from.join("runtime.log"), b"vmm").unwrap();
        std::fs::write(from.join("kernel.log"), b"").unwrap();
        let to = dir.path().join("kept").join("sb").join("logs");
        keep_logs(&from, &to);
        assert_eq!(std::fs::read(to.join("runtime.log")).unwrap(), b"vmm");
        assert!(to.join("kernel.log").is_file());
        assert!(!to.join("nested").exists());
        let none = dir.path().join("kept").join("never-booted");
        keep_logs(&dir.path().join("missing"), &none);
        assert!(!none.exists());
    }

    #[test]
    fn a_scratch_home_is_a_short_sibling_of_the_run_home() {
        let settings = Settings::from_lookup(lookup(&[
            (RUNTIME_DIR_VAR, "/rt"),
            (PREFIX_VAR, "r9-1"),
            (ROOT_VAR, "/vm"),
        ]))
        .unwrap();
        let scratch = settings.scratch_home("pp");
        assert_eq!(scratch, PathBuf::from("/vm").join("r9-1-pp"));
        // Not below the run home, and only the tag longer: msb derives Unix socket paths from
        // the home and refuses 108 bytes or more (CI's root is already 29 bytes).
        assert!(!scratch.starts_with(settings.home()));
        assert_eq!(
            scratch.as_os_str().len(),
            settings.home().as_os_str().len() + 3
        );
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
        let files = HostOs::current().runtime_files();
        std::fs::write(runtime.path().join(files.msb), b"x").unwrap();
        let library = files.libkrunfw;
        std::fs::write(runtime.path().join(library), b"x").unwrap();
        let root = TempDir::new("prep-root");
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-1").unwrap(),
            root: root.path().to_owned(),
            msb_log_level: None,
        };
        let pair = settings.prepare().unwrap();
        let written = std::fs::read_to_string(config_path(&settings.home())).unwrap();
        assert_eq!(written, pair.config_json(None));
        let debug = Settings {
            msb_log_level: Some("debug".into()),
            ..settings.clone()
        };
        debug.prepare().unwrap();
        let written = std::fs::read_to_string(config_path(&debug.home())).unwrap();
        assert_eq!(written, pair.config_json(Some("debug")));
        assert_eq!(pair.libkrunfw, runtime.path().join(library));
    }

    #[test]
    fn prepare_fails_on_an_incomplete_runtime() {
        let runtime = TempDir::new("prep-empty");
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-2").unwrap(),
            root: runtime.path().to_owned(),
            msb_log_level: None,
        };
        assert!(matches!(
            settings.prepare().unwrap_err(),
            HarnessError::RuntimeIncomplete { .. }
        ));
    }

    #[test]
    fn prepare_reports_an_unwritable_home() {
        let runtime = TempDir::new("prep-file");
        let files = HostOs::current().runtime_files();
        std::fs::write(runtime.path().join(files.msb), b"x").unwrap();
        let library = files.libkrunfw;
        std::fs::write(runtime.path().join(library), b"x").unwrap();
        // The root is a file, so the home under it can't be created.
        let root = runtime.path().join(library);
        let settings = Settings {
            runtime_dir: runtime.path().to_owned(),
            prefix: RunPrefix::new("r1-3").unwrap(),
            root,
            msb_log_level: None,
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
        let files = HostOs::current().runtime_files();
        let (msb, library) = (files.msb, files.libkrunfw);
        std::fs::write(dir.path().join(msb), b"x").unwrap();
        std::fs::write(dir.path().join(library), b"x").unwrap();
        let settings = Settings {
            runtime_dir: dir.path().to_owned(),
            prefix: RunPrefix::new("r7-1").unwrap(),
            root: dir.path().join("root"),
            msb_log_level: None,
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
        std::fs::create_dir_all(settings.kept_logs().join("sb").join("logs")).unwrap();
        env.remove_home().await.unwrap();
        assert!(!settings.home().exists());
        assert!(!settings.kept_logs().exists());
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
