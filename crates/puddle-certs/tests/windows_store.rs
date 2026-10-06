// SPDX-License-Identifier: GPL-3.0-or-later
//! The real Windows certificate stores (Windows CI job): a test root added to
//! `CurrentUser\Root` is exported, one also in `CurrentUser\Disallowed` is not, and the machine
//! (Intune-style) and Group Policy stores are read too.
//!
//! These tests change the stores of the user running them, so they only run where `CI` is set
//! (GitHub Actions sets it); elsewhere they pass without doing anything. Every certificate they
//! add is removed again, pass or fail.
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
    let on = std::env::var_os("CI").is_some();
    if !on {
        eprintln!("skipped: changes the user's certificate stores; runs only where CI is set");
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
        format!("puddle T-110 test root {tag} {nanos}"),
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

/// Imports `cert` into `store` (`Cert:\...` path). For `CurrentUser\Root`, falls back to
/// writing the registry entry directly when the import is refused or times out (the import
/// needs the user's confirmation on an interactive desktop). Returns how it was added.
fn add(cert: &TestCert, store: &str, registry_fallback: Option<&str>) -> String {
    let import = format!(
        "Import-Certificate -FilePath '{}' -CertStoreLocation '{store}' | Out-Null",
        cert.file.display()
    );
    match powershell(&import) {
        Ok(_) => "Import-Certificate".to_owned(),
        Err(e) => {
            let key = registry_fallback.unwrap_or_else(|| panic!("import into {store}: {e}"));
            write_registry_blob(cert, key);
            format!("registry (Import-Certificate failed: {})", e.trim())
        }
    }
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

const CU_ROOT_KEY: &str = "HKCU:\\Software\\Microsoft\\SystemCertificates\\Root";
const LM_GP_ROOT_KEY: &str = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root";

#[test]
fn a_current_user_root_is_exported_and_a_disallowed_one_is_not() {
    if !enabled() {
        return;
    }
    let trusted = test_root("trusted");
    let banned = test_root("banned");
    let _cleanup = Cleanup(vec![
        (
            &trusted,
            vec!["Cert:\\CurrentUser\\Root"],
            vec![CU_ROOT_KEY],
        ),
        (
            &banned,
            vec!["Cert:\\CurrentUser\\Root", "Cert:\\CurrentUser\\Disallowed"],
            vec![CU_ROOT_KEY],
        ),
    ]);
    let how = add(&trusted, "Cert:\\CurrentUser\\Root", Some(CU_ROOT_KEY));
    eprintln!("CurrentUser\\Root: added by {how}");
    add(&banned, "Cert:\\CurrentUser\\Root", Some(CU_ROOT_KEY));
    add(&banned, "Cert:\\CurrentUser\\Disallowed", None);

    let roots = select();
    assert_eq!(
        synced_sources(&roots, &trusted.der),
        Some(vec![CU_ROOT]),
        "the CurrentUser root is not exported"
    );
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
    add(&intune, "Cert:\\LocalMachine\\Root", None);
    // A GPO-pushed root, written where Group Policy writes it (T-026 lab L8).
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
