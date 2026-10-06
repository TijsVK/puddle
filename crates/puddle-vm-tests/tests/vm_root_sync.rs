// SPDX-License-Identifier: GPL-3.0-or-later
//! Corporate root sync on a real microVM (T-110, tier K on Linux KVM, W on Windows WHP).
//!
//! A test "corporate" root, selected from a store snapshot as the Windows export would, signs a
//! fixture HTTPS server inside the guest. Before the sync curl refuses it; after the root-sync
//! files, `update-ca-certificates` and the bundle step, curl, Node and Python all trust it, with
//! and without puddle's env, and the image's own roots are still in the bundle. A second step
//! run changes nothing.
//!
//! The steps are applied by plain exec, in `boot.sh`'s order, not through `boot.sh` itself: on
//! a real msb VM `boot.sh` currently stops at its first sysctl (`fs.inotify.max_user_instances
//! is '1' after setting it to 1024`, T-110 brief), which is the boot hook's VM bar (T-108/T-106).
//! The fake-root test `puddle-certs/tests/boot_trust.rs` covers the same plan through `boot.sh`.
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code outside #[test] fns: a failed check fails the test, output goes to the log"
)]

use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

use microsandbox::Sandbox;
use puddle_ca::{CaBuilder, NameConstraints, TrustBundle};
use puddle_certs::{
    CorporateRoots, GuestTrust, Location, Physical, StoreName, StoreSnapshot, StoreSource,
};
use puddle_vm_tests::{HarnessError, VmEnv, within};

/// Has curl, Node 22 and Python 3 (through mercurial in buildpack-deps), runs as root.
const IMAGE: &str = "node:22-bookworm";
const CREATE_BUDGET: Duration = Duration::from_secs(600);
const EXEC_BUDGET: Duration = Duration::from_secs(120);
const STOP_BUDGET: Duration = Duration::from_secs(60);

const SERVER_PY: &str = r"
import http.server, ssl, os
os.chdir('/tmp/www')
srv = http.server.HTTPServer(('127.0.0.1', 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/leaf.pem', '/tmp/leaf.key')
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
";

/// Starts the fixture server, waits for it, runs `clients`, stops the server.
fn with_server(clients: &str) -> String {
    format!(
        "set -u
mkdir -p /tmp/www && printf puddle-ok >/tmp/www/ok.txt
python3 /tmp/server.py >/tmp/server.log 2>&1 &
srv=$!
i=0
until python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 8443), 1)' 2>/dev/null; do
  i=$((i+1)); [ $i -gt 100 ] && {{ echo 'server did not start'; cat /tmp/server.log; kill $srv; exit 99; }}
  sleep 0.1
done
{clients}
rc=$?
kill $srv
exit $rc"
    )
}

const URL: &str = "https://localhost:8443/ok.txt";

struct Fixture {
    trust: GuestTrust,
    leaf_pem: String,
    leaf_key: String,
}

fn fixture() -> Fixture {
    let mut root = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    root.distinguished_name.push(
        rcgen::DnType::CommonName,
        "puddle T-110 corporate test root",
    );
    root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let root_key = rcgen::KeyPair::generate().unwrap();
    let root_cert = root.self_signed(&root_key).unwrap();

    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.subject_alt_names
        .push(rcgen::SanType::IpAddress([127, 0, 0, 1].into()));
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::from_params(&root, &root_key);
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();

    // As the Windows export finds it: a user-added root.
    let mut snapshot = StoreSnapshot::new();
    snapshot.add(
        StoreSource::new(Location::CurrentUser, StoreName::Root, Physical::Default),
        root_cert.der().to_vec(),
    );
    let corporate = CorporateRoots::select(&snapshot, SystemTime::now());
    assert_eq!(corporate.certificates().len(), 1);
    // And puddle's own proxy CA next to it (D-11), as in a real sandbox.
    let proxy_ca = CaBuilder::new(
        "puddle proxy CA (T-110 VM test)",
        NameConstraints::new().permit_dns("github.com").unwrap(),
    )
    .build()
    .unwrap();
    let bundle = TrustBundle::new().with(proxy_ca.certificate().clone());
    Fixture {
        trust: GuestTrust::new(&corporate, &bundle),
        leaf_pem: leaf_cert.pem(),
        leaf_key: leaf_key.serialize_pem(),
    }
}

/// The trust's files as `(guest path, mode, contents)` plus an install script that copies each
/// from `/tmp/rootsync-<n>` into place, then the env file, as `boot.sh` would.
fn install(trust: &GuestTrust) -> (Vec<(String, Vec<u8>)>, String) {
    let mut uploads = Vec::new();
    let mut script = String::from("set -e\n");
    for (n, f) in trust.guest_files().iter().enumerate() {
        let tmp = format!("/tmp/rootsync-{n}");
        let dest = f.path().as_str();
        let dir = dest.rsplit_once('/').unwrap().0;
        writeln!(
            script,
            "mkdir -p '{dir}' && cp '{tmp}' '{dest}' && chmod {:o} '{dest}'",
            f.mode()
        )
        .unwrap();
        uploads.push((tmp, f.contents().to_vec()));
    }
    let mut env = String::new();
    for (k, v) in trust.env().iter() {
        writeln!(env, "export {k}='{v}'").unwrap();
    }
    uploads.push(("/tmp/rootsync-env".to_owned(), env.into_bytes()));
    script.push_str("cp /tmp/rootsync-env /etc/profile.d/01-puddle-env.sh\n");
    (uploads, script)
}

async fn sh(
    sandbox: &Sandbox,
    what: &'static str,
    script: String,
) -> Result<(i32, String), HarnessError> {
    let out = within(what, EXEC_BUDGET, sandbox.shell(script)).await??;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(out.stdout_bytes()),
        String::from_utf8_lossy(out.stderr_bytes())
    );
    Ok((out.status().code, text))
}

async fn run(env: &VmEnv) -> Result<(), HarnessError> {
    let f = fixture();
    let builder = env.sandbox("rootsync", IMAGE)?;
    env.scope(Box::pin(async {
        let sandbox = within("create", CREATE_BUDGET, builder.create()).await??;
        let fs = sandbox.fs();
        let (uploads, install_sh) = install(&f.trust);
        for (path, data) in uploads {
            within("write", EXEC_BUDGET, fs.write(&path, data)).await??;
        }
        for (path, data) in [
            ("/tmp/server.py", SERVER_PY.as_bytes().to_vec()),
            ("/tmp/leaf.pem", f.leaf_pem.clone().into_bytes()),
            ("/tmp/leaf.key", f.leaf_key.clone().into_bytes()),
        ] {
            within("write", EXEC_BUDGET, fs.write(path, data)).await??;
        }

        // Negative control: the image alone doesn't trust the fixture.
        let (code, out) = sh(&sandbox, "curl before", with_server(&format!("curl -sS {URL}"))).await?;
        assert_ne!(code, 0, "curl trusted the test root before the sync: {out}");

        // boot.sh's order: files, update-ca-certificates (a CA file changed), the step.
        let step = f.trust.boot_step().unwrap();
        let apply = format!("{install_sh}update-ca-certificates\nsh {step}\n");
        let (code, out) = sh(&sandbox, "apply", apply).await?;
        eprintln!("first apply:\n{out}");
        assert_eq!(code, 0, "apply failed: {out}");
        assert!(out.contains("bundle updated"), "{out}");

        let clients = format!(
            ". /etc/profile.d/01-puddle-env.sh
echo \"curl: $(curl -sS {URL})\"
echo \"curl-system: $(env -u CURL_CA_BUNDLE -u SSL_CERT_FILE curl -sS {URL})\"
echo \"node: $(node -e \"require('https').get('{URL}', r => {{ let b=''; r.on('data', d => b += d); r.on('end', () => console.log(b)); }}).on('error', e => {{ console.log(e.message); process.exit(1); }})\")\"
echo \"python: $(python3 -c \"import urllib.request; print(urllib.request.urlopen('{URL}').read().decode())\" 2>&1)\"
echo \"bundle: $(grep -c 'BEGIN CERTIFICATE' /etc/puddle/ca-bundle.pem) distro: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)\"
echo \"dupes: $(awk '/BEGIN/{{k=\"\"}} !/-----/{{k=k $0}} /END/{{print k}}' /etc/puddle/ca-bundle.pem | sort | uniq -d | wc -l)\""
        );
        let (code, out) = sh(&sandbox, "clients after", with_server(&clients)).await?;
        eprintln!("clients after the sync:\n{out}");
        assert_eq!(code, 0, "{out}");
        for line in ["curl: puddle-ok", "curl-system: puddle-ok", "node: puddle-ok", "python: puddle-ok"] {
            assert!(out.lines().any(|l| l == line), "missing {line:?} in:\n{out}");
        }
        let bundle_line = out.lines().find(|l| l.starts_with("bundle: ")).unwrap();
        let counts: Vec<usize> = bundle_line
            .split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect();
        // The distro bundle (already with the synced root and puddle's CA, through
        // update-ca-certificates) equals the merged one: nothing lost, nothing twice.
        assert!(counts[0] > 100, "distro roots missing: {bundle_line}");
        assert_eq!(counts[0], counts[1], "{bundle_line}");
        assert!(out.lines().any(|l| l == "dupes: 0"), "{out}");

        // A second run with the same roots changes nothing.
        let (code, out) = sh(&sandbox, "step again", format!("sh {step}")).await?;
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("bundle unchanged"), "{out}");

        within("stop", STOP_BUDGET, sandbox.stop()).await??;
        within("remove", STOP_BUDGET, Sandbox::remove(sandbox.name())).await??;
        Ok(())
    }))
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_root_sync_curl_node_python_trust_a_synced_root() {
    let env = VmEnv::from_env().await.unwrap();
    let result = Box::pin(run(&env)).await;
    let cleaned = Box::pin(env.cleanup()).await;
    result.unwrap();
    cleaned.unwrap();
    env.remove_home().await.unwrap();
}
