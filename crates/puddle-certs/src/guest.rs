// SPDX-License-Identifier: GPL-3.0-or-later
//! What the guest gets: the synced roots and puddle's CAs as boot files, the step that builds
//! the full bundle in the guest, and the environment that points tools at it.

use std::collections::BTreeSet;

use puddle_ca::{CaCertificate, TrustBundle};
use puddle_types::{GuestEnv, GuestFile, GuestPath};

use crate::select::{CorporateRoots, Fingerprint, to_pem};

/// Directory for the synced host certificates, one `<fingerprint prefix>.crt` each, inside
/// `update-ca-certificates`' input so the system store gets them (Debian, Ubuntu, Alpine).
pub const HOST_CA_DIR: &str = "/usr/local/share/ca-certificates/puddle-host";

/// Every extra CA (synced host certificates, then puddle's CAs), each once:
/// `NODE_EXTRA_CA_CERTS`, which adds to Node's built-in roots.
pub const EXTRA_CAS_PATH: &str = "/etc/puddle/extra-cas.pem";

/// The full bundle the step writes: the image's bundle plus [`EXTRA_CAS_PATH`], each
/// certificate once. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` point here.
pub const CA_BUNDLE_PATH: &str = "/etc/puddle/ca-bundle.pem";

/// The step script (`guest/ca-bundle.sh`) in the guest.
pub const BUNDLE_STEP_PATH: &str = "/usr/local/lib/puddle/ca-bundle.sh";

/// The step script's text.
pub const BUNDLE_STEP_SH: &str = include_str!("../guest/ca-bundle.sh");

/// Hex digits of the fingerprint in a host certificate's file name: enough to never collide in
/// one store set, short enough to read.
const NAME_HEX: usize = 16;

/// The guest side of root sync for one sandbox: the host's synced roots plus puddle's own CAs
/// ([`TrustBundle`], a list so a dev CA is one more entry, T-020 F-9).
///
/// Hand [`GuestTrust::guest_files`], [`GuestTrust::env`] and [`GuestTrust::boot_step`] to the
/// boot plan. With nothing to add, all three are empty and the guest keeps the image's trust.
///
/// ```
/// use puddle_ca::TrustBundle;
/// use puddle_certs::{CA_BUNDLE_PATH, CorporateRoots, GuestTrust};
///
/// let trust = GuestTrust::new(&CorporateRoots::default(), &TrustBundle::new());
/// assert!(trust.guest_files().is_empty() && trust.env().is_empty() && trust.boot_step().is_none());
/// # let _ = CA_BUNDLE_PATH;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTrust {
    host: Vec<(Fingerprint, String)>,
    puddle: TrustBundle,
}

impl GuestTrust {
    /// The trust for a sandbox from the host's `corporate` roots and puddle's CAs.
    #[must_use]
    pub fn new(corporate: &CorporateRoots, puddle: &TrustBundle) -> Self {
        Self {
            host: corporate
                .certificates()
                .iter()
                .map(|c| (c.fingerprint(), c.pem()))
                .collect(),
            puddle: puddle.clone(),
        }
    }

    /// Whether there is nothing to add to the guest.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.host.is_empty() && self.puddle.certificates().is_empty()
    }

    /// The boot files, in a fixed order (the same inputs give byte-identical files, so the boot
    /// hook sees no change and skips `update-ca-certificates`):
    ///
    /// 1. one file per synced host certificate under [`HOST_CA_DIR`];
    /// 2. puddle's CA files ([`TrustBundle::guest_files`]);
    /// 3. [`EXTRA_CAS_PATH`];
    /// 4. the step script at [`BUNDLE_STEP_PATH`] (mode `0755`).
    ///
    /// All are public certificates or the script; nothing secret.
    #[must_use]
    pub fn guest_files(&self) -> Vec<GuestFile> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut files: Vec<GuestFile> = self
            .host
            .iter()
            .filter_map(|(fingerprint, pem)| {
                let hex = fingerprint.to_string();
                let name = hex.get(..NAME_HEX)?;
                let path = GuestPath::new(&format!("{HOST_CA_DIR}/{name}.crt")).ok()?;
                Some(GuestFile::new(path, pem.clone().into_bytes()))
            })
            .collect();
        files.extend(self.puddle.guest_files());
        files.push(fixed(EXTRA_CAS_PATH, self.extra_cas().into_bytes()));
        let step = fixed(BUNDLE_STEP_PATH, BUNDLE_STEP_SH.as_bytes().to_vec());
        files.extend(step.with_mode(0o755).ok());
        files
    }

    /// `NODE_EXTRA_CA_CERTS` (the extra CAs only; Node keeps its own roots) and
    /// `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` (the full bundle: OpenSSL, Python,
    /// requests, pip, curl). Empty when there is nothing to add.
    #[must_use]
    pub fn env(&self) -> GuestEnv {
        let mut env = GuestEnv::new();
        if self.is_empty() {
            return env;
        }
        for (name, value) in [
            ("NODE_EXTRA_CA_CERTS", EXTRA_CAS_PATH),
            ("SSL_CERT_FILE", CA_BUNDLE_PATH),
            ("REQUESTS_CA_BUNDLE", CA_BUNDLE_PATH),
            ("CURL_CA_BUNDLE", CA_BUNDLE_PATH),
        ] {
            // Fixed, valid names and values: can't fail.
            let _ = env.set(name, value);
        }
        env
    }

    /// The step the boot plan runs at every boot (after `update-ca-certificates`) to build
    /// [`CA_BUNDLE_PATH`] from the image's bundle; `None` when there is nothing to add.
    #[must_use]
    pub fn boot_step(&self) -> Option<GuestPath> {
        (!self.is_empty()).then(|| path(BUNDLE_STEP_PATH))
    }

    /// The text of [`EXTRA_CAS_PATH`]: host certificates, then puddle's CAs, each once (a dev CA
    /// the user also added to their Windows store is not repeated).
    fn extra_cas(&self) -> String {
        let mut seen = BTreeSet::new();
        let host = self.host.iter().map(|(fp, pem)| (*fp, pem.clone()));
        let puddle = self
            .puddle
            .certificates()
            .iter()
            .map(|c: &CaCertificate| (Fingerprint::of(c.der()), to_pem(c.der())));
        host.chain(puddle)
            .filter(|(fp, _)| seen.insert(*fp))
            .map(|(_, pem)| pem)
            .collect()
    }
}

fn path(p: &str) -> GuestPath {
    #[expect(
        clippy::expect_used,
        reason = "invariant: only called with this module's absolute, normalised constants"
    )]
    GuestPath::new(p).expect("a constant guest path is valid")
}

fn fixed(p: &str, contents: Vec<u8>) -> GuestFile {
    GuestFile::new(path(p), contents)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use puddle_ca::{CaBuilder, GUEST_BUNDLE_PATH, NameConstraints};

    use super::*;
    use crate::store::{SOURCES, StoreSnapshot};

    fn root_der(cn: &str) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().der().to_vec()
    }

    fn corporate(ders: &[Vec<u8>]) -> CorporateRoots {
        let mut s = StoreSnapshot::new();
        for d in ders {
            s.add(SOURCES[0], d.clone());
        }
        CorporateRoots::select(&s, UNIX_EPOCH + Duration::from_hours(525_960))
    }

    fn puddle_ca(host: &str) -> CaCertificate {
        CaBuilder::new(
            "puddle test CA",
            NameConstraints::new().permit_dns(host).unwrap(),
        )
        .build()
        .unwrap()
        .certificate()
        .clone()
    }

    fn text(files: &[GuestFile], p: &str) -> String {
        let f = files.iter().find(|f| f.path().as_str() == p).unwrap();
        String::from_utf8(f.contents().to_vec()).unwrap()
    }

    #[test]
    fn host_roots_and_puddle_cas_become_files_env_and_a_step() {
        let corp = corporate(&[root_der("Corp Root"), root_der("User Root")]);
        let ca = puddle_ca("github.com");
        let trust = GuestTrust::new(&corp, &TrustBundle::new().with(ca.clone()));
        let files = trust.guest_files();
        let paths: Vec<&str> = files.iter().map(|f| f.path().as_str()).collect();

        let host_files: Vec<&str> = paths
            .iter()
            .copied()
            .filter(|p| p.starts_with(HOST_CA_DIR))
            .collect();
        let expected: Vec<String> = corp
            .certificates()
            .iter()
            .map(|c| format!("{HOST_CA_DIR}/{}.crt", &c.fingerprint().to_string()[..16]))
            .collect();
        assert_eq!(host_files, expected);
        assert_eq!(text(&files, &expected[0]), corp.certificates()[0].pem());
        assert_eq!(
            &paths[2..],
            [
                "/usr/local/share/ca-certificates/puddle/puddle-ca-1.crt",
                GUEST_BUNDLE_PATH,
                EXTRA_CAS_PATH,
                BUNDLE_STEP_PATH,
            ]
        );
        let extra = text(&files, EXTRA_CAS_PATH);
        assert_eq!(extra.matches("-----BEGIN CERTIFICATE-----").count(), 3);
        assert!(extra.starts_with(&corp.certificates()[0].pem()));
        assert!(extra.ends_with(&to_pem(ca.der())));
        let step = files
            .iter()
            .find(|f| f.path().as_str() == BUNDLE_STEP_PATH)
            .unwrap();
        assert_eq!(step.mode(), 0o755);
        assert_eq!(step.contents(), BUNDLE_STEP_SH.as_bytes());
        assert!(
            files
                .iter()
                .filter(|f| f.path().as_str() != BUNDLE_STEP_PATH)
                .all(|f| f.mode() == 0o644)
        );

        let env = trust.env();
        assert_eq!(env.get("NODE_EXTRA_CA_CERTS"), Some(EXTRA_CAS_PATH));
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"] {
            assert_eq!(env.get(name), Some(CA_BUNDLE_PATH), "{name}");
        }
        assert_eq!(env.len(), 4);
        assert_eq!(trust.boot_step().unwrap().as_str(), BUNDLE_STEP_PATH);
        assert!(!trust.is_empty());
    }

    #[test]
    fn only_puddle_cas_or_only_host_roots_still_sync() {
        let only_ca = GuestTrust::new(
            &CorporateRoots::default(),
            &TrustBundle::new().with(puddle_ca("dev.azure.com")),
        );
        assert!(only_ca.boot_step().is_some());
        assert_eq!(
            text(&only_ca.guest_files(), EXTRA_CAS_PATH)
                .matches("BEGIN")
                .count(),
            1
        );
        let only_host = GuestTrust::new(&corporate(&[root_der("Corp")]), &TrustBundle::new());
        let files = only_host.guest_files();
        assert_eq!(files.len(), 3, "one root, extra-cas, step");
        assert!(!only_host.env().is_empty());
    }

    #[test]
    fn nothing_to_add_leaves_the_guest_alone() {
        let trust = GuestTrust::new(&CorporateRoots::default(), &TrustBundle::new());
        assert!(trust.is_empty());
        assert_eq!(trust.guest_files(), []);
        assert_eq!(trust.env(), GuestEnv::new());
        assert_eq!(trust.boot_step(), None);
    }

    #[test]
    fn unchanged_inputs_give_byte_identical_files() {
        let ders = [root_der("A"), root_der("B")];
        let ca = puddle_ca("github.com");
        let one = GuestTrust::new(&corporate(&ders), &TrustBundle::new().with(ca.clone()));
        let reversed = [ders[1].clone(), ders[0].clone()];
        let two = GuestTrust::new(&corporate(&reversed), &TrustBundle::new().with(ca));
        assert_eq!(one.guest_files(), two.guest_files());
        assert_eq!(one.env(), two.env());
    }

    #[test]
    fn a_ca_present_on_both_sides_is_listed_once() {
        let ca = puddle_ca("localhost");
        // The user also trusted puddle's CA in Windows (a dev CA, D-13).
        let corp = corporate(&[ca.der().to_vec(), root_der("Corp")]);
        let trust = GuestTrust::new(&corp, &TrustBundle::new().with(ca));
        let extra = text(&trust.guest_files(), EXTRA_CAS_PATH);
        assert_eq!(extra.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }
}
