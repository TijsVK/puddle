// SPDX-License-Identifier: GPL-3.0-or-later
//! Root sync through the real `boot.sh` and `guest/ca-bundle.sh`, on the test host against a
//! fake guest root (stubbed `sysctl` and a Debian-like `update-ca-certificates`), under dash and
//! bash. The VM version is `puddle-vm-tests/tests/vm_root_sync.rs`.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use puddle_boot::{BOOT_SH, BootPlan, ENV_FILE_GUEST};
use puddle_ca::{CaBuilder, CaCertificate, NameConstraints, TrustBundle};
use puddle_certs::{
    BUNDLE_STEP_SH, CA_BUNDLE_PATH, CorporateRoots, EXTRA_CAS_PATH, GuestTrust, HOST_CA_DIR,
    SOURCES, StoreSnapshot,
};
use puddle_compute::ImageConfig;

/// The agent binary as the merge tool: reads the spec and leaves the file as it is.
const MERGE_TOOL_STUB: &str = "#!/bin/sh\ncat >/dev/null\necho unchanged\n";

const SYSCTL_STUB: &str = r#"#!/bin/sh
[ "$1" = -w ] && shift
key=${1%%=*}
printf '%s\n' "${1#*=}" >"$PUDDLE_ROOT/proc/sys/$(printf %s "$key" | tr . /)"
"#;

/// Like Debian's: the distro's roots plus every `*.crt` below `/usr/local/share/ca-certificates`
/// (subdirectories too), concatenated into the system bundle.
const UPDATE_CA_STUB: &str = r#"#!/bin/sh
echo "update-ca-certificates" >>"$PUDDLE_ROOT/calls"
mkdir -p "$PUDDLE_ROOT/etc/ssl/certs"
{
    cat "$PUDDLE_ROOT/usr/share/ca-certificates/distro.pem"
    find "$PUDDLE_ROOT/usr/local/share/ca-certificates" -name '*.crt' -type f | sort | while read -r f; do cat "$f"; done
} >"$PUDDLE_ROOT/etc/ssl/certs/ca-certificates.crt"
"#;

struct Guest {
    root: PathBuf,
    shell: PathBuf,
    path: String,
}

fn shells() -> Vec<PathBuf> {
    let found: Vec<PathBuf> = ["/bin/dash", "/bin/bash"]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    assert!(!found.is_empty(), "no POSIX shell found");
    found
}

fn write_exec(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Guest {
    /// A fake Debian-like guest whose distro bundle holds `distro`; `update_ca` says whether the
    /// image has `update-ca-certificates`.
    fn new(shell: &Path, distro: &str, update_ca: bool) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let root = std::env::temp_dir().join(format!(
            "puddle-certs-test-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["proc/sys/fs/inotify", "proc/sys/kernel/random", "etc"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in [
            "fs/inotify/max_user_instances",
            "fs/inotify/max_user_watches",
            "kernel/unprivileged_bpf_disabled",
        ] {
            std::fs::write(root.join("proc/sys").join(f), "0\n").unwrap();
        }
        std::fs::write(root.join("proc/sys/kernel/random/boot_id"), "boot-1\n").unwrap();
        write_exec(&root.join("puddle/boot.sh"), BOOT_SH);
        // Every plan merges VS Code's Machine settings through the agent binary.
        write_exec(&root.join("puddle/puddle-agent"), MERGE_TOOL_STUB);
        let stubs = root.join("stubs");
        write_exec(&stubs.join("sysctl"), SYSCTL_STUB);
        let g = Self {
            path: format!("{}:/usr/bin:/bin", stubs.display()),
            root,
            shell: shell.to_owned(),
        };
        if update_ca {
            write_exec(&stubs.join("update-ca-certificates"), UPDATE_CA_STUB);
            g.write("/usr/share/ca-certificates/distro.pem", distro);
            // The image as built: its bundle already made.
            g.write("/etc/ssl/certs/ca-certificates.crt", distro);
        } else if !distro.is_empty() {
            g.write("/etc/pki/tls/certs/ca-bundle.crt", distro);
        }
        g
    }

    fn p(&self, guest: &str) -> PathBuf {
        self.root.join(guest.trim_start_matches('/'))
    }

    fn write(&self, guest: &str, text: &str) {
        let p = self.p(guest);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn read(&self, guest: &str) -> String {
        std::fs::read_to_string(self.p(guest)).unwrap_or_else(|e| panic!("{guest}: {e}"))
    }

    fn calls(&self, what: &str) -> usize {
        std::fs::read_to_string(self.root.join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|l| *l == what)
            .count()
    }

    fn boot(&self, trust: &GuestTrust) -> Output {
        let mut b = BootPlan::builder(&ImageConfig::default())
            .no_agent()
            .files(trust.guest_files())
            .env(&trust.env());
        if let Some(step) = trust.boot_step() {
            b = b.step(step);
        }
        let plan = b.build().unwrap();
        let mut child = Command::new(&self.shell)
            .arg(self.p("/puddle/boot.sh"))
            .env_clear()
            .env("PATH", &self.path)
            .env("PUDDLE_ROOT", &self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&plan.render())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs only the step script with `path` as `PATH`.
    fn step(&self, path: &str) -> Output {
        let script = self.root.join("ca-bundle.sh");
        write_exec(&script, BUNDLE_STEP_SH);
        Command::new(&self.shell)
            .arg(script)
            .env_clear()
            .env("PATH", path)
            .env("PUDDLE_ROOT", &self.root)
            .output()
            .unwrap()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn show(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn root_pem(cn: &str) -> (Vec<u8>, String) {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    (cert.der().to_vec(), cert.pem().replace("\r\n", "\n"))
}

fn puddle_ca() -> CaCertificate {
    CaBuilder::new(
        "puddle proxy CA (test)",
        NameConstraints::new().permit_dns("github.com").unwrap(),
    )
    .build()
    .unwrap()
    .certificate()
    .clone()
}

fn trust(host: &[&Vec<u8>], puddle: &[&CaCertificate]) -> GuestTrust {
    let mut s = StoreSnapshot::new();
    for der in host {
        s.add(SOURCES[0], (*der).clone());
    }
    let now = UNIX_EPOCH + Duration::from_hours(500_000);
    let bundle = puddle
        .iter()
        .fold(TrustBundle::new(), |b, c| b.with((*c).clone()));
    GuestTrust::new(&CorporateRoots::select(&s, now), &bundle)
}

/// How often each certificate (by its base64 body) appears in `pem`, in first-seen order.
fn counts(pem: &str) -> Vec<(String, usize)> {
    let mut order = Vec::new();
    let mut n: BTreeMap<String, usize> = BTreeMap::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body: String = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if !n.contains_key(&body) {
            order.push(body.clone());
        }
        *n.entry(body).or_default() += 1;
    }
    order
        .into_iter()
        .map(|b| {
            let c = n.get(&b).copied().unwrap_or_default();
            (b, c)
        })
        .collect()
}

fn body(pem: &str) -> String {
    counts(pem).remove(0).0
}

#[test]
fn first_boot_appends_roots_and_puddle_cas_to_the_distro_bundle_each_once() {
    let (_, d1) = root_pem("Distro Root 1");
    let (_, d2) = root_pem("Distro Root 2");
    // A corporate root that is also public: in the distro bundle and in the Windows store.
    let (public_der, public) = root_pem("Public Corp Root");
    let (corp_der, corp) = root_pem("Corp Root");
    let ca = puddle_ca();
    let t = trust(&[&corp_der, &public_der], &[&ca]);
    for sh in shells() {
        let g = Guest::new(&sh, &format!("{d1}{d2}{public}"), true);
        let out = g.boot(&t);
        assert!(out.status.success(), "{}: {}", sh.display(), show(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("update-ca-certificates ran"), "{stdout}");
        assert!(
            stdout
                .contains("bundle updated, 5 certificates with /etc/ssl/certs/ca-certificates.crt"),
            "{stdout}"
        );
        assert_eq!(g.calls("update-ca-certificates"), 1);

        let bundle = g.read(CA_BUNDLE_PATH);
        let c = counts(&bundle);
        assert!(c.iter().all(|(_, n)| *n == 1), "a certificate twice");
        let bodies: Vec<&str> = c.iter().map(|(b, _)| b.as_str()).collect();
        // Distro roots first, in their order, then the rest.
        assert_eq!(&bodies[..3], [body(&d1), body(&d2), body(&public)]);
        for extra in [&corp, &ca.pem().replace("\r\n", "\n")] {
            assert!(bodies.contains(&body(extra).as_str()));
        }
        // The system bundle got them too (through update-ca-certificates).
        let system = g.read("/etc/ssl/certs/ca-certificates.crt");
        assert!(system.contains(&body(&corp)[..60]));
        // Node's extra file: host roots and puddle's CA only.
        assert_eq!(counts(&g.read(EXTRA_CAS_PATH)).len(), 3);
        let env = g.read(ENV_FILE_GUEST);
        assert!(
            env.contains(&format!("export SSL_CERT_FILE='{CA_BUNDLE_PATH}'")),
            "{env}"
        );
        assert!(env.contains(&format!("export NODE_EXTRA_CA_CERTS='{EXTRA_CAS_PATH}'")));
        let mode = std::fs::metadata(g.p(CA_BUNDLE_PATH))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }
}

#[test]
fn unchanged_roots_skip_update_ca_certificates_and_leave_the_bundle_alone() {
    let (_, d1) = root_pem("Distro Root");
    let (corp_der, _) = root_pem("Corp Root");
    let t = trust(&[&corp_der], &[]);
    for sh in shells() {
        let g = Guest::new(&sh, &d1, true);
        assert!(g.boot(&t).status.success());
        let before = std::fs::metadata(g.p(CA_BUNDLE_PATH)).unwrap();
        let out = g.boot(&t);
        assert!(out.status.success(), "{}", show(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("update-ca-certificates skipped"),
            "{stdout}"
        );
        assert!(stdout.contains("bundle unchanged"), "{stdout}");
        assert_eq!(g.calls("update-ca-certificates"), 1);
        let after = std::fs::metadata(g.p(CA_BUNDLE_PATH)).unwrap();
        assert_eq!(
            (before.ino(), before.mtime_nsec()),
            (after.ino(), after.mtime_nsec())
        );
    }
}

#[test]
fn a_root_removed_on_the_host_leaves_the_guest() {
    let (_, d1) = root_pem("Distro Root");
    let (a_der, a) = root_pem("Corp Root A");
    let (b_der, b) = root_pem("Corp Root B");
    let g = Guest::new(&shells()[0], &d1, true);
    assert!(g.boot(&trust(&[&a_der, &b_der], &[])).status.success());
    assert!(g.read(CA_BUNDLE_PATH).contains(&body(&b)[..60]));
    let out = g.boot(&trust(&[&a_der], &[]));
    assert!(out.status.success(), "{}", show(&out));
    assert_eq!(g.calls("update-ca-certificates"), 2);
    let bundle = g.read(CA_BUNDLE_PATH);
    assert!(bundle.contains(&body(&a)[..60]));
    assert!(!bundle.contains(&body(&b)[..60]));
    assert!(
        !g.read("/etc/ssl/certs/ca-certificates.crt")
            .contains(&body(&b)[..60])
    );
    let left = std::fs::read_dir(g.p(HOST_CA_DIR)).unwrap().count();
    assert_eq!(left, 1);
}

#[test]
fn an_image_without_update_ca_certificates_still_gets_distro_plus_extras() {
    let (_, d1) = root_pem("Fedora Root");
    let (corp_der, corp) = root_pem("Corp Root");
    // Fedora's bundle has comment lines and CRLF here; neither may break the merge.
    let distro = format!("# Fedora Root\n{}", d1.replace('\n', "\r\n"));
    let t = trust(&[&corp_der], &[]);
    for sh in shells() {
        let g = Guest::new(&sh, &distro, false);
        let out = g.boot(&t);
        assert!(out.status.success(), "{}", show(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("update-ca-certificates skipped (not in this image)"),
            "{stdout}"
        );
        assert!(
            stdout.contains("with /etc/pki/tls/certs/ca-bundle.crt"),
            "{stdout}"
        );
        let bundle = g.read(CA_BUNDLE_PATH);
        assert!(!bundle.contains('\r') && !bundle.contains("# Fedora"));
        let bodies: Vec<String> = counts(&bundle).into_iter().map(|(b, _)| b).collect();
        assert_eq!(bodies, [body(&d1), body(&corp)]);
    }
}

#[test]
fn no_distro_bundle_gives_the_extras_alone() {
    let (corp_der, corp) = root_pem("Corp Root");
    let g = Guest::new(&shells()[0], "", false);
    let out = g.boot(&trust(&[&corp_der], &[]));
    assert!(out.status.success(), "{}", show(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("(no distro bundle)"));
    assert_eq!(counts(&g.read(CA_BUNDLE_PATH)), [(body(&corp), 1)]);
}

#[test]
fn without_awk_the_bundle_is_complete_if_not_deduplicated() {
    let (_, d1) = root_pem("Distro Root");
    let (corp_der, _) = root_pem("Corp Root");
    let g = Guest::new(&shells()[0], &d1, true);
    assert!(g.boot(&trust(&[&corp_der], &[])).status.success());
    // A PATH with the script's tools but no awk.
    let bin = g.root.join("no-awk");
    std::fs::create_dir_all(&bin).unwrap();
    for tool in ["cat", "chmod", "cmp", "mv", "grep", "rm"] {
        let found = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap();
        std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
    }
    let out = g.step(&bin.display().to_string());
    assert!(out.status.success(), "{}", show(&out));
    let c = counts(&g.read(CA_BUNDLE_PATH));
    // The system bundle already holds the corporate root, so it shows up twice.
    assert_eq!(c.len(), 2);
    assert_eq!(c.iter().map(|(_, n)| n).sum::<usize>(), 3);
}

#[test]
fn the_step_fails_clearly_without_its_input_or_with_a_directory_in_the_way() {
    let g = Guest::new(&shells()[0], "", false);
    let out = g.step("/usr/bin:/bin");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("ca-bundle: {EXTRA_CAS_PATH} is missing\n")
    );
    g.write(EXTRA_CAS_PATH, "");
    std::fs::create_dir_all(g.p(CA_BUNDLE_PATH)).unwrap();
    let out = g.step("/usr/bin:/bin");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("ca-bundle: {CA_BUNDLE_PATH} is a directory\n")
    );
}
