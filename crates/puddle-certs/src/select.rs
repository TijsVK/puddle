// SPDX-License-Identifier: GPL-3.0-or-later
//! Which certificates of a [`StoreSnapshot`] the guest gets.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use crate::der;
use crate::store::{StoreName, StoreSnapshot, StoreSource, UnreadableStore};

/// Whether a synced certificate is a trust anchor or an intermediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CertKind {
    /// From a `Root` store.
    Root,
    /// From a `CA` store, issued by a synced certificate (a corporate issuing CA that proxies
    /// often leave out of the chain they send).
    Intermediate,
}

/// Why a certificate from the stores is not synced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SkipReason {
    /// It is in (or shares its key with a certificate in) a `Disallowed` store.
    Disallowed,
    /// Its `notAfter` has passed.
    Expired,
    /// It is not a readable X.509 certificate.
    Unreadable,
    /// An intermediate whose issuer is not among the synced certificates (e.g. a public CA's
    /// intermediate Windows cached; the guest's distro bundle covers its root).
    NotIssuedBySyncedCert,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Disallowed => "distrusted by Windows (Disallowed store)",
            Self::Expired => "expired",
            Self::Unreadable => "not a readable certificate",
            Self::NotIssuedBySyncedCert => "intermediate not issued by a synced root",
        })
    }
}

/// SHA-256 of a certificate's DER, the identity used for duplicates and guest file names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of `der`.
    #[must_use]
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    /// Lower-case hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// A certificate the guest gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedCert {
    der: Vec<u8>,
    fingerprint: Fingerprint,
    kind: CertKind,
    subject_cn: Option<String>,
    not_after: i64,
    sources: Vec<StoreSource>,
}

impl SyncedCert {
    /// The certificate, DER.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The certificate as one PEM block (LF line ends).
    #[must_use]
    pub fn pem(&self) -> String {
        to_pem(&self.der)
    }

    /// SHA-256 of the DER.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Root or intermediate.
    #[must_use]
    pub fn kind(&self) -> CertKind {
        self.kind
    }

    /// The subject's common name, for display.
    #[must_use]
    pub fn subject_cn(&self) -> Option<&str> {
        self.subject_cn.as_deref()
    }

    /// `notAfter`, as seconds since the Unix epoch.
    #[must_use]
    pub fn not_after_unix(&self) -> i64 {
        self.not_after
    }

    /// Every store it was found in, sorted.
    #[must_use]
    pub fn sources(&self) -> &[StoreSource] {
        &self.sources
    }
}

/// A certificate from the stores that the guest doesn't get, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedCert {
    /// SHA-256 of the DER.
    pub fingerprint: Fingerprint,
    /// The subject's common name, when readable.
    pub subject_cn: Option<String>,
    /// Every store it was found in, sorted.
    pub sources: Vec<StoreSource>,
    /// Why it is not synced.
    pub reason: SkipReason,
}

/// The host's admin- and user-added roots (and the intermediates they issued) that the guest
/// trusts, plus what was left out, for the network health page.
///
/// Selection: every certificate from a `Root` store; from a `CA` store only
/// those issued by a synced certificate; never one whose certificate or public key is in a
/// `Disallowed` store; never an expired one. Each certificate once, however many stores hold
/// it, sorted by fingerprint so the same stores give byte-identical guest files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorporateRoots {
    synced: Vec<SyncedCert>,
    skipped: Vec<SkippedCert>,
    unreadable: Vec<UnreadableStore>,
}

/// One distinct certificate of the snapshot with every store it was in.
struct Candidate<'a> {
    der: &'a [u8],
    sources: BTreeSet<StoreSource>,
}

impl CorporateRoots {
    /// Selects from `snapshot` as of `now`.
    #[must_use]
    pub fn select(snapshot: &StoreSnapshot, now: SystemTime) -> Self {
        let now = unix_seconds(now);
        let mut distrusted_certs = BTreeSet::new();
        let mut distrusted_keys = BTreeSet::new();
        let mut candidates: BTreeMap<Fingerprint, Candidate<'_>> = BTreeMap::new();
        for cert in snapshot.certs() {
            let fingerprint = Fingerprint::of(&cert.der);
            if cert.source.store == StoreName::Disallowed {
                distrusted_certs.insert(fingerprint);
                if let Ok(fields) = der::parse(&cert.der) {
                    distrusted_keys.insert(fields.spki.to_vec());
                }
                continue;
            }
            candidates
                .entry(fingerprint)
                .or_insert_with(|| Candidate {
                    der: &cert.der,
                    sources: BTreeSet::new(),
                })
                .sources
                .insert(cert.source);
        }

        let mut out = Self {
            unreadable: snapshot.unreadable().to_vec(),
            ..Self::default()
        };
        // Intermediates wait until their issuer is known to be synced.
        let mut pending = Vec::new();
        for (fingerprint, candidate) in candidates {
            let sources: Vec<StoreSource> = candidate.sources.into_iter().collect();
            let skip = |reason, subject_cn| SkippedCert {
                fingerprint,
                subject_cn,
                sources: sources.clone(),
                reason,
            };
            let Ok(fields) = der::parse(candidate.der) else {
                out.skipped.push(skip(SkipReason::Unreadable, None));
                continue;
            };
            let cn = fields.subject_cn.clone();
            if distrusted_certs.contains(&fingerprint) || distrusted_keys.contains(fields.spki) {
                out.skipped.push(skip(SkipReason::Disallowed, cn));
            } else if fields.not_after < now {
                out.skipped.push(skip(SkipReason::Expired, cn));
            } else {
                let is_root = sources.iter().any(|s| s.store == StoreName::Root);
                let cert = SyncedCert {
                    der: candidate.der.to_vec(),
                    fingerprint,
                    kind: if is_root {
                        CertKind::Root
                    } else {
                        CertKind::Intermediate
                    },
                    subject_cn: cn,
                    not_after: fields.not_after,
                    sources,
                };
                if is_root {
                    out.synced.push(cert);
                } else {
                    pending.push((cert, fields.issuer.to_vec()));
                }
            }
        }

        // Add intermediates issued by a synced certificate until nothing changes (a chain of
        // corporate intermediates comes in one at a time).
        let mut subjects: BTreeSet<Vec<u8>> = out
            .synced
            .iter()
            .filter_map(|c| der::parse(&c.der).ok().map(|f| f.subject.to_vec()))
            .collect();
        loop {
            let (issued, rest): (Vec<_>, Vec<_>) = pending
                .into_iter()
                .partition(|(_, issuer)| subjects.contains(issuer));
            pending = rest;
            if issued.is_empty() {
                break;
            }
            for (cert, _) in issued {
                if let Ok(f) = der::parse(&cert.der) {
                    subjects.insert(f.subject.to_vec());
                }
                out.synced.push(cert);
            }
        }
        for (cert, _) in pending {
            out.skipped.push(SkippedCert {
                fingerprint: cert.fingerprint,
                subject_cn: cert.subject_cn,
                sources: cert.sources,
                reason: SkipReason::NotIssuedBySyncedCert,
            });
        }
        out.synced.sort_by_key(|c| c.fingerprint);
        out.skipped.sort_by_key(|c| c.fingerprint);
        out
    }

    /// The certificates the guest gets, sorted by fingerprint.
    #[must_use]
    pub fn certificates(&self) -> &[SyncedCert] {
        &self.synced
    }

    /// What was left out and why, sorted by fingerprint.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedCert] {
        &self.skipped
    }

    /// Stores that could not be read (their certificates are missing above).
    #[must_use]
    pub fn unreadable_stores(&self) -> &[UnreadableStore] {
        &self.unreadable
    }

    /// Whether nothing is synced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.synced.is_empty()
    }
}

fn unix_seconds(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// `der` as one PEM certificate block with LF line ends.
pub(crate) fn to_pem(der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::store::SOURCES;

    const LM_ROOT: StoreSource = SOURCES[0];
    const LM_ROOT_GP: StoreSource = SOURCES[1];
    const CU_ROOT: StoreSource = SOURCES[3];
    const LM_CA: StoreSource = SOURCES[5];
    const CU_CA: StoreSource = SOURCES[8];
    const LM_DISALLOWED: StoreSource = SOURCES[10];
    const CU_DISALLOWED: StoreSource = SOURCES[11];

    /// 2030-01-01, a fixed "now".
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_hours(525_960)
    }

    struct Ca {
        key: rcgen::KeyPair,
        cert: rcgen::Certificate,
        params: rcgen::CertificateParams,
    }

    fn params(cn: &str, not_after_year: i32) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        p
    }

    fn root(cn: &str, year: i32) -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = params(cn, year);
        let cert = p.self_signed(&key).unwrap();
        Ca {
            key,
            cert,
            params: p,
        }
    }

    fn issued(cn: &str, year: i32, by: &Ca) -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = params(cn, year);
        let issuer = rcgen::Issuer::from_params(&by.params, &by.key);
        let cert = p.signed_by(&key, &issuer).unwrap();
        Ca {
            key,
            cert,
            params: p,
        }
    }

    fn der(ca: &Ca) -> Vec<u8> {
        ca.cert.der().to_vec()
    }

    fn names(roots: &CorporateRoots) -> Vec<&str> {
        let mut n: Vec<&str> = roots
            .certificates()
            .iter()
            .map(|c| c.subject_cn().unwrap())
            .collect();
        n.sort_unstable();
        n
    }

    fn skipped(roots: &CorporateRoots) -> Vec<(String, SkipReason)> {
        let mut s: Vec<(String, SkipReason)> = roots
            .skipped()
            .iter()
            .map(|c| (c.subject_cn.clone().unwrap_or_default(), c.reason))
            .collect();
        s.sort();
        s
    }

    #[test]
    fn admin_and_user_roots_are_synced_disallowed_and_expired_are_not() {
        let corp = root("Corp Root", 2040);
        let user = root("Fiddler Root", 2040);
        let banned = root("Banned Root", 2040);
        let old = root("Old Root", 2029);
        let mut s = StoreSnapshot::new();
        s.add(LM_ROOT_GP, der(&corp));
        s.add(CU_ROOT, der(&user));
        s.add(LM_ROOT, der(&banned));
        s.add(CU_DISALLOWED, der(&banned));
        s.add(LM_ROOT, der(&old));
        let r = CorporateRoots::select(&s, now());
        assert_eq!(names(&r), ["Corp Root", "Fiddler Root"]);
        assert!(r.certificates().iter().all(|c| c.kind() == CertKind::Root));
        assert_eq!(
            skipped(&r),
            [
                ("Banned Root".to_owned(), SkipReason::Disallowed),
                ("Old Root".to_owned(), SkipReason::Expired),
            ]
        );
        let corp_synced = r
            .certificates()
            .iter()
            .find(|c| c.subject_cn() == Some("Corp Root"))
            .unwrap();
        assert_eq!(corp_synced.der(), der(&corp));
        assert_eq!(corp_synced.sources(), [LM_ROOT_GP]);
        assert_eq!(corp_synced.not_after_unix(), 2_208_988_800);
        assert!(!r.is_empty());
    }

    #[test]
    fn a_disallowed_key_counts_even_in_a_reissued_certificate() {
        let original = root("Rotated Root", 2040);
        // Same key, new certificate (e.g. re-issued with a longer validity).
        let mut p = params("Rotated Root", 2045);
        p.serial_number = Some(rcgen::SerialNumber::from(vec![7]));
        let reissued = p.self_signed(&original.key).unwrap();
        let mut s = StoreSnapshot::new();
        s.add(LM_DISALLOWED, der(&original));
        s.add(LM_ROOT, reissued.der().to_vec());
        let r = CorporateRoots::select(&s, now());
        assert!(r.is_empty());
        assert_eq!(
            skipped(&r),
            [("Rotated Root".to_owned(), SkipReason::Disallowed)]
        );
    }

    #[test]
    fn a_certificate_in_several_stores_is_synced_once_with_every_source() {
        let corp = root("Corp Root", 2040);
        let mut s = StoreSnapshot::new();
        for source in [CU_ROOT, LM_ROOT, LM_ROOT_GP, LM_ROOT, LM_CA] {
            s.add(source, der(&corp));
        }
        let r = CorporateRoots::select(&s, now());
        assert_eq!(r.certificates().len(), 1);
        let c = &r.certificates()[0];
        assert_eq!(c.kind(), CertKind::Root, "in a Root store, so a root");
        assert_eq!(c.sources(), [LM_ROOT, LM_ROOT_GP, LM_CA, CU_ROOT]);
    }

    #[test]
    fn intermediates_need_a_synced_issuer_and_chain_in_any_order() {
        let corp = root("Corp Root", 2040);
        let issuing = issued("Corp Issuing CA", 2039, &corp);
        let proxy = issued("Corp Proxy CA", 2038, &issuing);
        let public_root = root("Public Root (AuthRoot, not read)", 2040);
        let public_int = issued("Public Intermediate", 2039, &public_root);
        let expired_int = issued("Corp Old Issuing CA", 2029, &corp);
        let mut s = StoreSnapshot::new();
        // Grandchild first, so one pass can't place it.
        s.add(CU_CA, der(&proxy));
        s.add(LM_CA, der(&issuing));
        s.add(CU_CA, der(&public_int));
        s.add(LM_CA, der(&expired_int));
        s.add(LM_ROOT, der(&corp));
        let r = CorporateRoots::select(&s, now());
        assert_eq!(names(&r), ["Corp Issuing CA", "Corp Proxy CA", "Corp Root"]);
        let kind = |cn| {
            r.certificates()
                .iter()
                .find(|c| c.subject_cn() == Some(cn))
                .unwrap()
                .kind()
        };
        assert_eq!(kind("Corp Proxy CA"), CertKind::Intermediate);
        assert_eq!(kind("Corp Root"), CertKind::Root);
        assert_eq!(
            skipped(&r),
            [
                ("Corp Old Issuing CA".to_owned(), SkipReason::Expired),
                (
                    "Public Intermediate".to_owned(),
                    SkipReason::NotIssuedBySyncedCert
                ),
            ]
        );
    }

    #[test]
    fn an_intermediate_under_a_disallowed_root_is_not_synced() {
        let corp = root("Corp Root", 2040);
        let issuing = issued("Corp Issuing CA", 2039, &corp);
        let mut s = StoreSnapshot::new();
        s.add(LM_ROOT, der(&corp));
        s.add(LM_DISALLOWED, der(&corp));
        s.add(LM_CA, der(&issuing));
        let r = CorporateRoots::select(&s, now());
        assert!(r.is_empty());
        assert_eq!(
            skipped(&r),
            [
                (
                    "Corp Issuing CA".to_owned(),
                    SkipReason::NotIssuedBySyncedCert
                ),
                ("Corp Root".to_owned(), SkipReason::Disallowed),
            ]
        );
    }

    #[test]
    fn unreadable_certificates_and_stores_are_reported_not_synced() {
        let mut s = StoreSnapshot::new();
        s.add(LM_ROOT, b"not a certificate".to_vec());
        // Garbage in Disallowed still blocks the identical bytes, and breaks nothing.
        s.add(CU_DISALLOWED, b"junk".to_vec());
        s.note_unreadable(CU_ROOT, "os error 0x5");
        let r = CorporateRoots::select(&s, now());
        assert!(r.is_empty());
        assert_eq!(r.skipped().len(), 1);
        assert_eq!(r.skipped()[0].reason, SkipReason::Unreadable);
        assert_eq!(r.skipped()[0].subject_cn, None);
        assert_eq!(r.unreadable_stores()[0].source, CU_ROOT);
    }

    #[test]
    fn the_same_stores_in_any_order_give_the_same_selection() {
        let a = root("A", 2040);
        let b = root("B", 2040);
        let c = root("C", 2040);
        let mut one = StoreSnapshot::new();
        let mut two = StoreSnapshot::new();
        for x in [&a, &b, &c] {
            one.add(LM_ROOT, der(x));
        }
        for x in [&c, &a, &b] {
            two.add(LM_ROOT, der(x));
        }
        let (r1, r2) = (
            CorporateRoots::select(&one, now()),
            CorporateRoots::select(&two, now()),
        );
        assert_eq!(r1, r2);
        let fps: Vec<Fingerprint> = r1
            .certificates()
            .iter()
            .map(SyncedCert::fingerprint)
            .collect();
        let mut sorted = fps.clone();
        sorted.sort();
        assert_eq!(fps, sorted);
    }

    #[test]
    fn fingerprints_print_as_hex_and_pem_round_trips() {
        let a = root("A", 2040);
        let mut s = StoreSnapshot::new();
        s.add(LM_ROOT, der(&a));
        let r = CorporateRoots::select(&s, now());
        let c = &r.certificates()[0];
        let hex = c.fingerprint().to_string();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(
            c.fingerprint().as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(der(&a)))
        );
        let pem = c.pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(!pem.contains('\r'));
        assert_eq!(pem::parse(&pem).unwrap().contents(), der(&a));
    }

    #[test]
    fn skip_reasons_read_well_and_times_before_1970_work() {
        assert_eq!(
            SkipReason::Disallowed.to_string(),
            "distrusted by Windows (Disallowed store)"
        );
        assert_eq!(SkipReason::Expired.to_string(), "expired");
        assert_eq!(
            SkipReason::Unreadable.to_string(),
            "not a readable certificate"
        );
        assert_eq!(
            SkipReason::NotIssuedBySyncedCert.to_string(),
            "intermediate not issued by a synced root"
        );
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(5)), -5);
        assert_eq!(unix_seconds(UNIX_EPOCH + Duration::from_secs(5)), 5);
    }
}
