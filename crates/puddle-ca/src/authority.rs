// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-workspace CA and its leaf cache.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;

use crate::name::DnsName;
use crate::{CaCertificate, CaError};

/// X.520's upper bound for a common name.
const MAX_COMMON_NAME: usize = 64;

/// Settings for a new CA.
///
/// The CA carries no name constraint: which hosts the proxy decrypts is decided by the
/// workspace's decrypt set and never by what the guest's trust would verify, so a host added to
/// the set while the workspace runs needs no new CA. It signs for DNS names only, never for an IP
/// address.
///
/// ```
/// use puddle_ca::CaBuilder;
///
/// let ca = CaBuilder::new("puddle proxy CA (workspace demo)").build()?;
/// let leaf = ca.leaf("github.com")?;
/// assert_eq!(leaf.cert.len(), 1);
/// assert!(ca.leaf("example.com").is_ok());
/// assert!(ca.leaf("140.82.112.3").is_err());
/// # Ok::<(), puddle_ca::CaError>(())
/// ```
#[derive(Debug, Clone)]
pub struct CaBuilder {
    common_name: String,
    ca_validity: Duration,
    leaf_validity: Duration,
    backdate: Duration,
    leaf_cache_capacity: usize,
}

impl CaBuilder {
    /// Default CA lifetime: one year. The CA exists only in memory, so it is replaced at every
    /// start of puddle long before that.
    pub const DEFAULT_CA_VALIDITY: Duration = Duration::from_hours(365 * 24);
    /// Default leaf lifetime: seven days. A cached leaf is replaced after three quarters of it.
    pub const DEFAULT_LEAF_VALIDITY: Duration = Duration::from_hours(7 * 24);
    /// Default backdating of `notBefore`: one day, for a guest clock that lags after the host
    /// slept.
    pub const DEFAULT_BACKDATE: Duration = Duration::from_hours(24);
    /// Default number of cached leaves per CA. The decrypt set can hold a pattern that covers
    /// many names, so the cache is bounded; the least recently used leaf goes first.
    pub const DEFAULT_LEAF_CACHE_CAPACITY: usize = 256;

    /// A CA named `common_name`, which is visible in the guest's trust store.
    #[must_use]
    pub fn new(common_name: &str) -> Self {
        Self {
            common_name: common_name.to_owned(),
            ca_validity: Self::DEFAULT_CA_VALIDITY,
            leaf_validity: Self::DEFAULT_LEAF_VALIDITY,
            backdate: Self::DEFAULT_BACKDATE,
            leaf_cache_capacity: Self::DEFAULT_LEAF_CACHE_CAPACITY,
        }
    }

    /// How long the CA certificate is valid from now.
    #[must_use]
    pub fn ca_validity(mut self, validity: Duration) -> Self {
        self.ca_validity = validity;
        self
    }

    /// How long each leaf is valid from its issue (never past the CA's end).
    #[must_use]
    pub fn leaf_validity(mut self, validity: Duration) -> Self {
        self.leaf_validity = validity;
        self
    }

    /// How far before now `notBefore` is set, on the CA and every leaf.
    #[must_use]
    pub fn backdate(mut self, backdate: Duration) -> Self {
        self.backdate = backdate;
        self
    }

    /// The most leaves kept in the cache.
    #[must_use]
    pub fn leaf_cache_capacity(mut self, capacity: usize) -> Self {
        self.leaf_cache_capacity = capacity;
        self
    }

    /// Generates the CA key (ECDSA P-256) and its self-signed certificate: `CA:TRUE` with a path
    /// length of 0 (it signs leaves, never another CA), critical, and no name constraint.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidSetting`] for an empty or over-long common name, a zero validity, a leaf
    /// validity longer than the CA's, or a zero cache capacity, and [`CaError::Generate`] when key
    /// generation or signing fails.
    pub fn build(self) -> Result<WorkspaceCa, CaError> {
        self.build_at(OffsetDateTime::now_utc())
    }

    pub(crate) fn build_at(self, now: OffsetDateTime) -> Result<WorkspaceCa, CaError> {
        let invalid = |setting, reason| Err(CaError::InvalidSetting { setting, reason });
        if self.common_name.trim().is_empty() || self.common_name.len() > MAX_COMMON_NAME {
            return invalid("common name", "must be 1 to 64 bytes");
        }
        if self.ca_validity.is_zero() || self.leaf_validity.is_zero() {
            return invalid("validity", "must not be zero");
        }
        if self.leaf_validity > self.ca_validity {
            return invalid("leaf validity", "must not exceed the CA validity");
        }
        if self.leaf_cache_capacity == 0 {
            return invalid("leaf cache capacity", "must be at least 1");
        }
        let (Some(not_before), Some(not_after)) = (
            checked_sub(now, self.backdate),
            checked_add(now, self.ca_validity),
        ) else {
            return invalid("validity", "out of range");
        };

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, self.common_name.as_str());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = not_before;
        params.not_after = not_after;

        let key = KeyPair::generate().map_err(CaError::Generate)?;
        let cert = params.self_signed(&key).map_err(CaError::Generate)?;
        Ok(WorkspaceCa {
            certificate: CaCertificate::new(&cert),
            issuer: Issuer::new(params, key),
            not_before,
            not_after,
            leaf_validity: self.leaf_validity,
            backdate: self.backdate,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            cache: Mutex::new(LeafCache::new(self.leaf_cache_capacity)),
        })
    }
}

/// One workspace's CA (never shared between workspaces), with the leaves it issued.
///
/// The key stays inside: the type has no accessor for it and implements neither `Clone` nor
/// serde's traits, and `Debug` prints only the expiry. The CA itself does not limit which names it
/// signs for (the caller's decrypt set does, see [`CaBuilder`]); a dev CA that must hand its key
/// to the guest would be a separate, name-constrained type.
pub struct WorkspaceCa {
    certificate: CaCertificate,
    issuer: Issuer<'static, KeyPair>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    leaf_validity: Duration,
    backdate: Duration,
    provider: Arc<CryptoProvider>,
    cache: Mutex<LeafCache>,
}

impl fmt::Debug for WorkspaceCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceCa")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl WorkspaceCa {
    /// The CA certificate, for the guest's trust bundle.
    #[must_use]
    pub fn certificate(&self) -> &CaCertificate {
        &self.certificate
    }

    /// A leaf certificate and signing key for `host` (a DNS name), from the cache or newly
    /// issued. The chain holds the leaf only; the guest has the CA as a trust anchor.
    ///
    /// Any DNS name gets a leaf: whether the proxy may decrypt `host` is the caller's decision
    /// and must be made before this is called.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidHost`] for anything but a plain DNS name (an IP address, a wildcard, a
    /// port), [`CaError::Expired`] once the CA has expired, and [`CaError::Generate`] /
    /// [`CaError::LoadKey`] when issuing fails.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        self.leaf_at(host, OffsetDateTime::now_utc())
    }

    pub(crate) fn leaf_at(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<CertifiedKey>, CaError> {
        let parsed = DnsName::parse(host).ok_or_else(|| CaError::InvalidHost {
            host: host.to_owned(),
        })?;
        if now >= self.not_after {
            return Err(CaError::Expired);
        }
        // Issuing under the lock keeps two connections from minting the same leaf twice; one
        // ECDSA key and signature take well under a millisecond.
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(leaf) = cache.get(&parsed, now) {
            return Ok(leaf);
        }
        let (leaf, refresh_at) = self.issue(&parsed, now)?;
        cache.insert(parsed, Arc::clone(&leaf), refresh_at);
        Ok(leaf)
    }

    fn issue(
        &self,
        host: &DnsName,
        now: OffsetDateTime,
    ) -> Result<(Arc<CertifiedKey>, OffsetDateTime), CaError> {
        let not_before =
            checked_sub(now, self.backdate).map_or(self.not_before, |t| t.max(self.not_before));
        let not_after =
            checked_add(now, self.leaf_validity).map_or(self.not_after, |t| t.min(self.not_after));
        let refresh_at =
            checked_add(now, self.leaf_validity / 4 * 3).map_or(not_after, |t| t.min(not_after));

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.subject_alt_names = vec![SanType::DnsName(
            host.as_str().try_into().map_err(CaError::Generate)?,
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = not_before;
        params.not_after = not_after;

        let key = KeyPair::generate().map_err(CaError::Generate)?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(CaError::Generate)?;
        let certified = CertifiedKey::from_der(
            vec![cert.der().clone()],
            PrivateKeyDer::from(key),
            &self.provider,
        )
        .map_err(CaError::LoadKey)?;
        Ok((Arc::new(certified), refresh_at))
    }

    #[cfg(test)]
    pub(crate) fn cached_leaves(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    #[cfg(test)]
    pub(crate) fn key_der_for_test(&self) -> Vec<u8> {
        self.issuer.key().serialize_der()
    }
}

fn checked_add(t: OffsetDateTime, d: Duration) -> Option<OffsetDateTime> {
    t.checked_add(time::Duration::try_from(d).ok()?)
}

fn checked_sub(t: OffsetDateTime, d: Duration) -> Option<OffsetDateTime> {
    t.checked_sub(time::Duration::try_from(d).ok()?)
}

struct LeafCache {
    entries: HashMap<DnsName, CachedLeaf>,
    capacity: usize,
    clock: u64,
}

struct CachedLeaf {
    leaf: Arc<CertifiedKey>,
    refresh_at: OffsetDateTime,
    last_used: u64,
}

impl LeafCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            clock: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn get(&mut self, host: &DnsName, now: OffsetDateTime) -> Option<Arc<CertifiedKey>> {
        let tick = self.tick();
        let entry = self.entries.get_mut(host)?;
        if now >= entry.refresh_at {
            return None;
        }
        entry.last_used = tick;
        Some(Arc::clone(&entry.leaf))
    }

    fn insert(&mut self, host: DnsName, leaf: Arc<CertifiedKey>, refresh_at: OffsetDateTime) {
        let last_used = self.tick();
        if !self.entries.contains_key(&host) && self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(host, _)| host.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            host,
            CachedLeaf {
                leaf,
                refresh_at,
                last_used,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn ca() -> WorkspaceCa {
        CaBuilder::new("puddle proxy CA (workspace test)")
            .build()
            .unwrap()
    }

    fn unix(t: OffsetDateTime) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(t.unix_timestamp()).unwrap(),
        ))
    }

    /// Verifies `leaf` as a TLS server certificate for `host` under `anchor`, as rustls does.
    fn verify(
        anchor: &CaCertificate,
        leaf: &CertificateDer<'_>,
        host: &str,
        at: OffsetDateTime,
    ) -> Result<(), webpki::Error> {
        let anchors = [webpki::anchor_from_trusted_cert(anchor.der())?];
        let ee = webpki::EndEntityCert::try_from(leaf)?;
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            unix(at),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        let name = ServerName::try_from(host).unwrap();
        ee.verify_is_valid_for_subject_name(&name)
    }

    #[test]
    fn a_leaf_for_any_dns_name_verifies_under_the_ca() {
        let ca = ca();
        let now = OffsetDateTime::now_utc();
        for host in [
            "github.com",
            "api.github.com",
            "dev.azure.com",
            "GitHub.com.",
            "example.com",
            "evilgithub.com",
            "a.b.c.example.org",
        ] {
            let leaf = ca.leaf(host).unwrap();
            let expected = host.trim_end_matches('.').to_ascii_lowercase();
            verify(
                ca.certificate(),
                leaf.end_entity_cert().unwrap(),
                &expected,
                now,
            )
            .unwrap();
            leaf.keys_match().unwrap();
        }
    }

    #[test]
    fn the_ca_refuses_what_is_not_a_dns_name() {
        let ca = ca();
        for bad in [
            "",
            "*.github.com",
            "git hub.com",
            "github.com:443",
            "140.82.112.3",
            "127.0.0.1",
            "::1",
            "[2606:50c0:8000::153]",
        ] {
            assert!(
                matches!(ca.leaf(bad), Err(CaError::InvalidHost { .. })),
                "{bad:?}"
            );
        }
        assert_eq!(ca.cached_leaves(), 0);
    }

    #[test]
    fn a_leaf_from_one_workspace_does_not_verify_under_another() {
        let a = ca();
        let b = ca();
        assert_ne!(a.certificate(), b.certificate());
        let leaf = a.leaf("github.com").unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(
            verify(
                b.certificate(),
                leaf.end_entity_cert().unwrap(),
                "github.com",
                now
            )
            .is_err()
        );
    }

    #[test]
    fn leaves_are_cached_per_host_and_reissued_before_they_expire() {
        let ca = ca();
        let t0 = OffsetDateTime::now_utc();
        let first = ca.leaf_at("github.com", t0).unwrap();
        let again = ca
            .leaf_at("GITHUB.com", t0 + time::Duration::hours(1))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        let other = ca.leaf_at("api.github.com", t0).unwrap();
        assert!(!Arc::ptr_eq(&first, &other));

        // Three quarters into the seven-day default, the cache hands out a new leaf.
        let late = t0 + time::Duration::hours(7 * 24 * 3 / 4);
        let renewed = ca.leaf_at("github.com", late).unwrap();
        assert!(!Arc::ptr_eq(&first, &renewed));
        verify(
            ca.certificate(),
            renewed.end_entity_cert().unwrap(),
            "github.com",
            late + time::Duration::days(3),
        )
        .unwrap();
        assert_eq!(ca.cached_leaves(), 2);
    }

    #[test]
    fn the_cache_evicts_the_least_recently_used_leaf() {
        let ca = CaBuilder::new("puddle test CA")
            .leaf_cache_capacity(2)
            .build()
            .unwrap();
        let now = OffsetDateTime::now_utc();
        let a = ca.leaf_at("a.github.com", now).unwrap();
        let b = ca.leaf_at("b.github.com", now).unwrap();
        // Touch a, so b is the least recently used when c arrives.
        assert!(Arc::ptr_eq(&a, &ca.leaf_at("a.github.com", now).unwrap()));
        ca.leaf_at("c.github.com", now).unwrap();
        assert_eq!(ca.cached_leaves(), 2);
        assert!(Arc::ptr_eq(&a, &ca.leaf_at("a.github.com", now).unwrap()));
        assert!(!Arc::ptr_eq(&b, &ca.leaf_at("b.github.com", now).unwrap()));
        assert_eq!(ca.cached_leaves(), 2);
    }

    #[test]
    fn leaf_validity_is_clamped_to_the_ca() {
        let ca = CaBuilder::new("puddle test CA")
            .ca_validity(10 * HOUR)
            .leaf_validity(10 * HOUR)
            .backdate(HOUR)
            .build()
            .unwrap();
        let t0 = OffsetDateTime::now_utc();
        let later = t0 + time::Duration::hours(5);
        let leaf = ca.leaf_at("github.com", later).unwrap();
        let der = leaf.end_entity_cert().unwrap();
        // Valid at the CA's last hour, not after the CA ends.
        verify(
            ca.certificate(),
            der,
            "github.com",
            t0 + time::Duration::hours(9),
        )
        .unwrap();
        assert!(
            verify(
                ca.certificate(),
                der,
                "github.com",
                t0 + time::Duration::hours(11)
            )
            .is_err()
        );
        assert!(matches!(
            ca.leaf_at("github.com", t0 + time::Duration::hours(11)),
            Err(CaError::Expired)
        ));
    }

    #[test]
    fn backdating_covers_a_lagging_guest_clock() {
        let ca = ca();
        let now = OffsetDateTime::now_utc();
        let leaf = ca.leaf_at("github.com", now).unwrap();
        let lagging = now - time::Duration::hours(12);
        verify(
            ca.certificate(),
            leaf.end_entity_cert().unwrap(),
            "github.com",
            lagging,
        )
        .unwrap();
    }

    #[test]
    fn builder_refuses_meaningless_settings() {
        let check = |builder: CaBuilder| builder.build().unwrap_err();
        for builder in [
            CaBuilder::new(" "),
            CaBuilder::new(&"n".repeat(65)),
            CaBuilder::new("x").ca_validity(Duration::ZERO),
            CaBuilder::new("x").leaf_validity(Duration::ZERO),
            CaBuilder::new("x")
                .ca_validity(HOUR)
                .leaf_validity(2 * HOUR),
            CaBuilder::new("x").leaf_cache_capacity(0),
            CaBuilder::new("x").ca_validity(Duration::MAX),
            CaBuilder::new("x").backdate(Duration::MAX),
        ] {
            assert!(matches!(check(builder), CaError::InvalidSetting { .. }));
        }
    }

    /// DER of an extension whose OID is `2.5.29.<last>`: `OBJECT IDENTIFIER` (06 03 55 1d <last>).
    fn oid(last: u8) -> [u8; 5] {
        [0x06, 0x03, 0x55, 0x1d, last]
    }

    #[test]
    fn the_ca_certificate_is_a_critical_ca_with_path_length_0_and_no_name_constraint() {
        // Checked in the DER: rustls-webpki reads the name constraints of a trust anchor but not
        // its path length, so a webpki chain test could not tell `pathLen 0` from none. OpenSSL,
        // Go and Node enforce it.
        let ca = ca();
        let der = ca.certificate().der().as_ref();
        // basicConstraints, critical: `01 01 ff`, then the value `SEQUENCE { TRUE, INTEGER 0 }`.
        let basic: Vec<u8> = oid(0x13)
            .into_iter()
            .chain([
                0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00,
            ])
            .collect();
        assert!(der.windows(basic.len()).any(|w| w == basic.as_slice()));
        // nameConstraints (2.5.29.30) is nowhere in the certificate.
        let names = oid(0x1e);
        assert!(!der.windows(names.len()).any(|w| w == names));
        assert!(
            ca.certificate()
                .pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }

    #[test]
    fn no_key_material_leaves_the_ca() {
        let ca = ca();
        // The private scalar inside the PKCS#8 `ECPrivateKey`: `version 1, OCTET STRING (32)`.
        let key = ca.key_der_for_test();
        let marker = [0x02, 0x01, 0x01, 0x04, 0x20];
        let at = key.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
        let needle = &key[at..at + 32];
        let leaf = ca.leaf("github.com").unwrap();
        let bundle = crate::TrustBundle::new().with(ca.certificate().clone());
        let mut seen: Vec<Vec<u8>> = vec![
            format!("{ca:?}").into_bytes(),
            format!("{:?}", ca.certificate()).into_bytes(),
            ca.certificate().pem().as_bytes().to_vec(),
            ca.certificate().der().to_vec(),
            format!("{:?}", ca.leaf("1.2.3.4").unwrap_err()).into_bytes(),
            format!("{leaf:?}").into_bytes(),
        ];
        seen.extend(leaf.cert.iter().map(|c| c.to_vec()));
        seen.extend(bundle.guest_files().iter().map(|f| f.contents().to_vec()));
        for bytes in &seen {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle));
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("PRIVATE KEY"));
        }
        let debug = format!("{ca:?}");
        assert!(
            !debug.contains("issuer") && !debug.contains("cache"),
            "{debug}"
        );
    }

    // Autoref probe: `Probe::<T>::IMPLS` is true only when the inherent impl's bound holds.
    struct Probe<T>(std::marker::PhantomData<T>);
    trait NotImplemented {
        const IMPLS: bool = false;
    }
    impl<T> NotImplemented for Probe<T> {}
    struct CloneProbe<T>(std::marker::PhantomData<T>);
    impl<T> NotImplemented for CloneProbe<T> {}
    impl<T: serde::Serialize> Probe<T> {
        const IMPLS: bool = true;
    }
    impl<T: Clone> CloneProbe<T> {
        const IMPLS: bool = true;
    }

    #[test]
    fn the_ca_can_be_neither_serialised_nor_cloned() {
        const { assert!(!Probe::<WorkspaceCa>::IMPLS) };
        const { assert!(!CloneProbe::<WorkspaceCa>::IMPLS) };
        // The probes do see the traits where they exist.
        const { assert!(Probe::<String>::IMPLS) };
        const { assert!(CloneProbe::<CaCertificate>::IMPLS) };
    }
}
