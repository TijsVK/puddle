// SPDX-License-Identifier: GPL-3.0-or-later
//! The real Windows certificate stores (Windows CI job): a root in `CurrentUser\Disallowed` is
//! not exported, machine (Intune-style) and Group Policy roots are, and a `CurrentUser\Root`
//! root is wherever the session may add one (not on the hosted runner, see below).
//!
//! These tests change the stores of the user running them, so they only run where `CI` or
//! `PUDDLE_STORE_TESTS` is set; elsewhere they pass without doing anything. Every certificate
//! they add is removed again, pass or fail.
#![cfg(windows)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use puddle_certs::{
    CorporateRoots, Fingerprint, Location, Physical, SkipReason, StoreName, StoreSource,
    read_host_stores,
};

const CU_ROOT: StoreSource =
    StoreSource::new(Location::CurrentUser, StoreName::Root, Physical::Default);
const LM_ROOT: StoreSource =
    StoreSource::new(Location::LocalMachine, StoreName::Root, Physical::Default);
const LM_ROOT_GP: StoreSource = StoreSource::new(
    Location::LocalMachine,
    StoreName::Root,
    Physical::GroupPolicy,
);

/// Adding to `CurrentUser\Root` asks the user to confirm in a dialog on an interactive desktop;
/// a hung dialog must fail the test, not hang the job.
const POWERSHELL_LIMIT: Duration = Duration::from_secs(90);

fn enabled() -> bool {
    let on = std::env::var_os("CI").is_some() || std::env::var_os("PUDDLE_STORE_TESTS").is_some();
    if !on {
        eprintln!("skipped: changes the certificate stores; set PUDDLE_STORE_TESTS=1 to run");
    }
    on
}

/// Runs a PowerShell script; `Ok(stdout)` on exit 0, `Err(output)` otherwise or on timeout.
fn powershell(script: &str) -> Result<String, String> {
    let mut child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > POWERSHELL_LIMIT {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            return Err(format!(
                "timed out after {POWERSHELL_LIMIT:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

struct TestCert {
    der: Vec<u8>,
    file: PathBuf,
    thumbprint: String,
}

fn test_root(tag: &str) -> TestCert {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("puddle test root {tag} {nanos}"),
    );
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let der = p.self_signed(&key).unwrap().der().to_vec();
    let file = std::env::temp_dir().join(format!("puddle-t110-{tag}-{nanos}.cer"));
    std::fs::write(&file, &der).unwrap();
    let thumbprint = powershell(&format!(
        "(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{}')).Thumbprint",
        file.display()
    ))
    .unwrap()
    .trim()
    .to_owned();
    TestCert {
        der,
        file,
        thumbprint,
    }
}

/// Imports `cert` into `store` (`Cert:\\...` path); `Err` with PowerShell's output when refused.
fn try_add(cert: &TestCert, store: &str) -> Result<(), String> {
    powershell(&format!(
        "Import-Certificate -FilePath '{}' -CertStoreLocation '{store}' | Out-Null",
        cert.file.display()
    ))
    .map(drop)
}

fn add(cert: &TestCert, store: &str) {
    try_add(cert, store).unwrap_or_else(|e| panic!("import into {store}: {e}"));
}

/// Writes `cert` as a serialized certificate (property 32 = the DER) under `key`, the way
/// `CryptoAPI`'s registry stores hold it; Group Policy writes these the same way.
fn write_registry_blob(cert: &TestCert, key: &str) {
    let script = format!(
        "$raw = [IO.File]::ReadAllBytes('{file}'); \
         $blob = [byte[]](0x20,0,0,0,1,0,0,0) + [BitConverter]::GetBytes([int]$raw.Length) + $raw; \
         $k = '{key}\\Certificates\\{t}'; \
         New-Item -Path $k -Force | Out-Null; \
         New-ItemProperty -Path $k -Name Blob -PropertyType Binary -Value $blob -Force | Out-Null",
        file = cert.file.display(),
        t = cert.thumbprint,
    );
    powershell(&script).unwrap_or_else(|e| panic!("registry write under {key}: {e}"));
}

/// Removes `cert` from every store path given, ignoring "not there".
fn remove(cert: &TestCert, stores: &[&str], registry_keys: &[&str]) {
    for store in stores {
        let _ = powershell(&format!(
            "Remove-Item -LiteralPath '{store}\\{}' -ErrorAction SilentlyContinue",
            cert.thumbprint
        ));
    }
    for key in registry_keys {
        let _ = powershell(&format!(
            "Remove-Item -LiteralPath '{key}\\Certificates\\{}' -Recurse -ErrorAction SilentlyContinue",
            cert.thumbprint
        ));
    }
    let _ = std::fs::remove_file(&cert.file);
}

struct Cleanup<'a>(Vec<(&'a TestCert, Vec<&'static str>, Vec<&'static str>)>);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        for (cert, stores, keys) in &self.0 {
            remove(cert, stores, keys);
        }
    }
}

fn select() -> CorporateRoots {
    let snapshot = read_host_stores().unwrap();
    for u in snapshot.unreadable() {
        eprintln!("unreadable store {}: {}", u.source, u.reason);
    }
    CorporateRoots::select(&snapshot, SystemTime::now())
}

fn synced_sources(roots: &CorporateRoots, der: &[u8]) -> Option<Vec<StoreSource>> {
    let fp = Fingerprint::of(der);
    roots
        .certificates()
        .iter()
        .find(|c| c.fingerprint() == fp)
        .map(|c| c.sources().to_vec())
}

const LM_GP_ROOT_KEY: &str = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root";

/// `CurrentUser\\Root` needs the user to confirm each added root in a dialog; a non-interactive
/// session (the hosted runner) gets "UI is not allowed in this operation", and a root written to
/// the store's registry key directly is not enumerated. So the
/// export half runs where the import succeeds (an interactive session, e.g. a workstation, where
/// someone clicks Yes) and is reported as skipped otherwise.
#[test]
fn a_current_user_root_is_exported_when_one_can_be_added() {
    if !enabled() {
        return;
    }
    let trusted = test_root("user");
    let _cleanup = Cleanup(vec![(&trusted, vec!["Cert:\\CurrentUser\\Root"], vec![])]);
    if let Err(e) = try_add(&trusted, "Cert:\\CurrentUser\\Root") {
        eprintln!(
            "skipped: CurrentUser\\Root refused the import here: {}",
            e.trim()
        );
        return;
    }
    assert_eq!(
        synced_sources(&select(), &trusted.der),
        Some(vec![CU_ROOT]),
        "the CurrentUser root is not exported"
    );
}

#[test]
fn a_root_in_current_user_disallowed_is_not_exported() {
    if !enabled() {
        return;
    }
    let banned = test_root("banned");
    let _cleanup = Cleanup(vec![(
        &banned,
        vec![
            "Cert:\\LocalMachine\\Root",
            "Cert:\\CurrentUser\\Disallowed",
        ],
        vec![],
    )]);
    add(&banned, "Cert:\\LocalMachine\\Root");
    let roots = select();
    assert_eq!(
        synced_sources(&roots, &banned.der),
        Some(vec![LM_ROOT]),
        "control: trusted before it is distrusted"
    );
    add(&banned, "Cert:\\CurrentUser\\Disallowed");
    let roots = select();
    assert_eq!(
        synced_sources(&roots, &banned.der),
        None,
        "a Disallowed root was exported"
    );
    let skipped = roots
        .skipped()
        .iter()
        .find(|s| s.fingerprint == Fingerprint::of(&banned.der))
        .expect("the Disallowed root is listed as skipped");
    assert_eq!(skipped.reason, SkipReason::Disallowed);
    eprintln!(
        "{} certificates synced, {} skipped",
        roots.certificates().len(),
        roots.skipped().len()
    );
}

#[test]
fn machine_and_group_policy_roots_are_exported() {
    if !enabled() {
        return;
    }
    let intune = test_root("machine");
    let gpo = test_root("gpo");
    let _cleanup = Cleanup(vec![
        (&intune, vec!["Cert:\\LocalMachine\\Root"], vec![]),
        (&gpo, vec![], vec![LM_GP_ROOT_KEY]),
    ]);
    // Needs an elevated runner (GitHub's is); Intune puts its roots in LocalMachine\Root.
    add(&intune, "Cert:\\LocalMachine\\Root");
    // A GPO-pushed root, written where Group Policy writes it.
    write_registry_blob(&gpo, LM_GP_ROOT_KEY);

    let roots = select();
    assert_eq!(synced_sources(&roots, &intune.der), Some(vec![LM_ROOT]));
    assert_eq!(synced_sources(&roots, &gpo.der), Some(vec![LM_ROOT_GP]));
}

#[test]
fn reading_the_stores_twice_gives_the_same_selection() {
    let now = SystemTime::now();
    let one = CorporateRoots::select(&read_host_stores().unwrap(), now);
    let two = CorporateRoots::select(&read_host_stores().unwrap(), now);
    assert_eq!(one, two);
}
