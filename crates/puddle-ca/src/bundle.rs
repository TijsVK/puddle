// SPDX-License-Identifier: GPL-3.0-or-later
//! The public half of a CA, and the guest trust bundle built from a list of them.

use puddle_types::{GuestFile, GuestPath};
use rustls::pki_types::CertificateDer;

/// Directory under the guest's `update-ca-certificates` input where puddle's CAs go, one file
/// each (`update-ca-certificates` and `openssl rehash` read one certificate per file).
pub(crate) const GUEST_CA_DIR: &str = "/usr/local/share/ca-certificates/puddle";

/// All of puddle's CAs in one PEM file, for tools that take a bundle path
/// (`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`), which do not read the system store.
pub const GUEST_BUNDLE_PATH: &str = "/etc/puddle/puddle-cas.pem";

/// A CA certificate without its key: safe to copy, log and hand to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCertificate {
    der: CertificateDer<'static>,
    pem: String,
}

impl CaCertificate {
    pub(crate) fn new(cert: &rcgen::Certificate) -> Self {
        Self {
            der: cert.der().clone(),
            pem: cert.pem(),
        }
    }

    /// The certificate in DER, e.g. as a rustls or webpki trust anchor.
    #[must_use]
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// The certificate as one PEM block.
    #[must_use]
    pub fn pem(&self) -> &str {
        &self.pem
    }
}

/// The puddle CAs one sandbox's guest trusts: a list, so a later dev CA (T-020 F-9) is one more
/// entry next to the proxy CA rather than a second mechanism.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustBundle {
    certs: Vec<CaCertificate>,
}

impl TrustBundle {
    /// An empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The bundle with `cert` appended (a certificate already present is not added twice).
    #[must_use]
    pub fn with(mut self, cert: CaCertificate) -> Self {
        if !self.certs.contains(&cert) {
            self.certs.push(cert);
        }
        self
    }

    /// The certificates, in the order they were added.
    #[must_use]
    pub fn certificates(&self) -> &[CaCertificate] {
        &self.certs
    }

    /// The files the boot hook writes: `puddle-ca-<n>.crt` under the guest's local CA directory
    /// (so `update-ca-certificates` adds them to the system store) and every certificate in
    /// [`GUEST_BUNDLE_PATH`]. All are public certificates, mode `0644`. An empty bundle gives no
    /// files.
    #[must_use]
    pub fn guest_files(&self) -> Vec<GuestFile> {
        if self.certs.is_empty() {
            return Vec::new();
        }
        let mut files: Vec<GuestFile> = self
            .certs
            .iter()
            .zip(1_usize..)
            .filter_map(|(cert, n)| {
                let path = GuestPath::new(&format!("{GUEST_CA_DIR}/puddle-ca-{n}.crt")).ok()?;
                Some(GuestFile::new(path, cert.pem().as_bytes().to_vec()))
            })
            .collect();
        let all: String = self.certs.iter().map(CaCertificate::pem).collect();
        if let Ok(path) = GuestPath::new(GUEST_BUNDLE_PATH) {
            files.push(GuestFile::new(path, all.into_bytes()));
        }
        files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaBuilder, NameConstraints};

    fn cert(host: &str) -> CaCertificate {
        let constraints = NameConstraints::new().permit_dns(host).unwrap();
        CaBuilder::new("puddle test CA", constraints)
            .build()
            .unwrap()
            .certificate()
            .clone()
    }

    #[test]
    fn empty_bundle_writes_nothing() {
        assert_eq!(TrustBundle::new().guest_files(), [] as [GuestFile; 0]);
    }

    #[test]
    fn each_ca_gets_its_own_file_and_all_share_the_bundle_file() {
        let proxy = cert("github.com");
        let dev = cert("localhost");
        let bundle = TrustBundle::new()
            .with(proxy.clone())
            .with(dev.clone())
            .with(proxy.clone());
        assert_eq!(bundle.certificates(), [proxy.clone(), dev.clone()]);

        let files = bundle.guest_files();
        let paths: Vec<&str> = files.iter().map(|f| f.path().as_str()).collect();
        assert_eq!(
            paths,
            [
                "/usr/local/share/ca-certificates/puddle/puddle-ca-1.crt",
                "/usr/local/share/ca-certificates/puddle/puddle-ca-2.crt",
                GUEST_BUNDLE_PATH,
            ]
        );
        assert_eq!(files[0].contents(), proxy.pem().as_bytes());
        assert_eq!(files[1].contents(), dev.pem().as_bytes());
        assert_eq!(
            files[2].contents(),
            format!("{}{}", proxy.pem(), dev.pem()).as_bytes()
        );
        assert!(files.iter().all(|f| f.mode() == GuestFile::DEFAULT_MODE));
        let text = String::from_utf8(files[2].contents().to_vec()).unwrap();
        assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }
}
