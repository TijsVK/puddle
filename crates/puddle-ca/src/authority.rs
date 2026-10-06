// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-sandbox CA and its leaf cache.

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

use crate::constraints::Host;
use crate::{CaCertificate, CaError, NameConstraints};

/// X.520's upper bound for a common name.
const MAX_COMMON_NAME: usize = 64;

/// Settings for a new CA. The name constraints are an input, so every kind of puddle CA (the
/// proxy CA now, a localhost-only dev CA later) is built the same way.
///
/// ```
/// use puddle_ca::{CaBuilder, NameConstraints};
///
/// let constraints = NameConstraints::new().permit_dns("github.com")?;
/// let ca = CaBuilder::new("puddle proxy CA (sandbox demo)", constraints).build()?;
/// let leaf = ca.leaf("github.com")?;
/// assert_eq!(leaf.cert.len(), 1);
/// assert!(ca.leaf("example.com").is_err());
/// # Ok::<(), puddle_ca::CaError>(())
/// ```
#[derive(Debug, Clone)]
pub struct CaBuilder {
    common_name: String,
    constraints: NameConstraints,
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
    /// Default number of cached leaves per CA. A guest can ask for any name below a bound host,
    /// so the cache is bounded (HO-7); the least recently used leaf goes first.
    pub const DEFAULT_LEAF_CACHE_CAPACITY: usize = 256;

    /// A CA named `common_name` (visible in the guest's trust store) that may certify only the
    /// names in `constraints`.
    #[must_use]
    pub fn new(common_name: &str, constraints: NameConstraints) -> Self {
        Self {
            common_name: common_name.to_owned(),
            constraints,
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

    /// Generates the CA key (ECDSA P-256) and its self-signed, name-constrained certificate.
    ///
    /// # Errors
    ///
    /// [`CaError::NoPermittedNames`] when the constraints hold no DNS name,
    /// [`CaError::InvalidSetting`] for an empty or over-long common name, a zero validity, a leaf
    /// validity longer than the CA's, or a zero cache capacity, and [`CaError::Generate`] when key
    /// generation or signing fails.
    pub fn build(self) -> Result<SandboxCa, CaError> {
        self.build_at(OffsetDateTime::now_utc())
    }

    pub(crate) fn build_at(self, now: OffsetDateTime) -> Result<SandboxCa, CaError> {
        if !self.constraints.has_dns() {
            return Err(CaError::NoPermittedNames);
        }
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
        params.name_constraints = Some(self.constraints.to_rcgen());
        params.not_before = not_before;
        params.not_after = not_after;

        let key = KeyPair::generate().map_err(CaError::Generate)?;
        let cert = params.self_signed(&key).map_err(CaError::Generate)?;
        Ok(SandboxCa {
            certificate: CaCertificate::new(&cert),
            issuer: Issuer::new(params, key),
            constraints: self.constraints,
            not_before,
            not_after,
            leaf_validity: self.leaf_validity,
            backdate: self.backdate,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            cache: Mutex::new(LeafCache::new(self.leaf_cache_capacity)),
        })
    }
}

/// One sandbox's CA (HO-4: never shared between sandboxes), with the leaves it issued.
///
/// The key stays inside: the type has no accessor for it and implements neither `Clone` nor
/// serde's traits, and `Debug` prints only the certificate and constraints. A later dev CA that
/// must hand its key to the guest (T-020 F-9) is a separate type.
pub struct SandboxCa {
    certificate: CaCertificate,
    issuer: Issuer<'static, KeyPair>,
    constraints: NameConstraints,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    leaf_validity: Duration,
    backdate: Duration,
    provider: Arc<CryptoProvider>,
    cache: Mutex<LeafCache>,
}

impl fmt::Debug for SandboxCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxCa")
            .field("constraints", &self.constraints)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl SandboxCa {
    /// The CA certificate, for the guest's trust bundle.
    #[must_use]
    pub fn certificate(&self) -> &CaCertificate {
        &self.certificate
    }

    /// The names this CA may certify.
    #[must_use]
    pub fn constraints(&self) -> &NameConstraints {
        &self.constraints
    }

    /// A leaf certificate and signing key for `host` (a DNS name, or an IP address if the
    /// constraints permit one), from the cache or newly issued. The chain holds the leaf only;
    /// the guest has the CA as a trust anchor.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidHost`] for a malformed host, [`CaError::NotPermitted`] for a host
    /// outside the constraints, [`CaError::Expired`] once the CA has expired, and
    /// [`CaError::Generate`] / [`CaError::LoadKey`] when issuing fails.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        self.leaf_at(host, OffsetDateTime::now_utc())
    }

    pub(crate) fn leaf_at(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<CertifiedKey>, CaError> {
        let parsed = Host::parse(host).ok_or_else(|| CaError::InvalidHost {
            host: host.to_owned(),
        })?;
        if !self.constraints.permits_host(&parsed) {
            return Err(CaError::NotPermitted {
                host: parsed.to_string(),
            });
        }
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
        host: &Host,
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
        params.subject_alt_names = vec![match host {
            Host::Dns(name) => {
                SanType::DnsName(name.as_str().try_into().map_err(CaError::Generate)?)
            }
            Host::Ip(addr) => SanType::IpAddress(*addr),
        }];
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

    /// Signs arbitrary leaf parameters, bypassing the constraint check: only for tests that
    /// prove the certificate's own constraints stop a wrongly issued leaf.
    #[cfg(test)]
    pub(crate) fn sign_unchecked(&self, params: &CertificateParams) -> rcgen::Certificate {
        let key = KeyPair::generate().unwrap();
        params.signed_by(&key, &self.issuer).unwrap()
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
    entries: HashMap<Host, CachedLeaf>,
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

    fn get(&mut self, host: &Host, now: OffsetDateTime) -> Option<Arc<CertifiedKey>> {
        let tick = self.tick();
        let entry = self.entries.get_mut(host)?;
        if now >= entry.refresh_at {
            return None;
        }
        entry.last_used = tick;
        Some(Arc::clone(&entry.leaf))
    }

    fn insert(&mut self, host: Host, leaf: Arc<CertifiedKey>, refresh_at: OffsetDateTime) {
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
    use std::net::IpAddr;

    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn github() -> NameConstraints {
        NameConstraints::new()
            .permit_dns("github.com")
            .unwrap()
            .permit_dns("dev.azure.com")
            .unwrap()
    }

    fn ca(constraints: NameConstraints) -> SandboxCa {
        CaBuilder::new("puddle proxy CA (sandbox test)", constraints)
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

    fn leaf_params(san: SanType) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![san];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + time::Duration::hours(1);
        params
    }

    #[test]
    fn leaf_for_a_bound_host_verifies_under_the_ca() {
        let ca = ca(github());
        let now = OffsetDateTime::now_utc();
        for host in [
            "github.com",
            "api.github.com",
            "dev.azure.com",
            "GitHub.com.",
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
    fn leaf_for_a_permitted_ip_verifies_under_the_ca() {
        let constraints = NameConstraints::new()
            .permit_dns("localhost")
            .unwrap()
            .permit_ip("127.0.0.1".parse().unwrap(), 32)
            .unwrap();
        let ca = ca(constraints);
        let leaf = ca.leaf("127.0.0.1").unwrap();
        let now = OffsetDateTime::now_utc();
        verify(
            ca.certificate(),
            leaf.end_entity_cert().unwrap(),
            "127.0.0.1",
            now,
        )
        .unwrap();
    }

    #[test]
    fn name_constraints_reject_a_leaf_for_another_name() {
        let ca = ca(github());
        let now = OffsetDateTime::now_utc();
        for other in [
            "example.com",
            "evilgithub.com",
            "github.com.evil.example",
            "azure.com",
        ] {
            let forged =
                ca.sign_unchecked(&leaf_params(SanType::DnsName(other.try_into().unwrap())));
            assert_eq!(
                verify(ca.certificate(), forged.der(), other, now),
                Err(webpki::Error::NameConstraintViolation),
                "{other}"
            );
        }
    }

    #[test]
    fn name_constraints_reject_ip_leaves_when_no_prefix_is_permitted() {
        let ca = ca(github());
        let now = OffsetDateTime::now_utc();
        for addr in ["140.82.112.3", "127.0.0.1", "::1", "2606:50c0:8000::153"] {
            let ip: IpAddr = addr.parse().unwrap();
            let forged = ca.sign_unchecked(&leaf_params(SanType::IpAddress(ip)));
            assert_eq!(
                verify(ca.certificate(), forged.der(), addr, now),
                Err(webpki::Error::NameConstraintViolation),
                "{addr}"
            );
        }
    }

    #[test]
    fn the_api_refuses_names_outside_the_constraints() {
        let ca = ca(github());
        assert!(matches!(
            ca.leaf("example.com"),
            Err(CaError::NotPermitted { host }) if host == "example.com"
        ));
        assert!(matches!(
            ca.leaf("140.82.112.3"),
            Err(CaError::NotPermitted { .. })
        ));
        for bad in ["", "*.github.com", "git hub.com", "github.com:443"] {
            assert!(
                matches!(ca.leaf(bad), Err(CaError::InvalidHost { .. })),
                "{bad:?}"
            );
        }
        assert_eq!(ca.cached_leaves(), 0);
    }

    #[test]
    fn a_leaf_from_one_sandbox_does_not_verify_under_another() {
        let a = ca(github());
        let b = ca(github());
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
        let ca = ca(github());
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
        let ca = CaBuilder::new("puddle test CA", github())
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
        let ca = CaBuilder::new("puddle test CA", github())
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
        let ca = ca(github());
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
    fn builder_refuses_unsafe_or_meaningless_settings() {
        let check = |builder: CaBuilder| builder.build().unwrap_err();
        assert!(matches!(
            check(CaBuilder::new("x", NameConstraints::new())),
            CaError::NoPermittedNames
        ));
        let ip_only = NameConstraints::new()
            .permit_ip("127.0.0.1".parse().unwrap(), 32)
            .unwrap();
        assert!(matches!(
            check(CaBuilder::new("x", ip_only)),
            CaError::NoPermittedNames
        ));
        for builder in [
            CaBuilder::new(" ", github()),
            CaBuilder::new(&"n".repeat(65), github()),
            CaBuilder::new("x", github()).ca_validity(Duration::ZERO),
            CaBuilder::new("x", github()).leaf_validity(Duration::ZERO),
            CaBuilder::new("x", github())
                .ca_validity(HOUR)
                .leaf_validity(2 * HOUR),
            CaBuilder::new("x", github()).leaf_cache_capacity(0),
            CaBuilder::new("x", github()).ca_validity(Duration::MAX),
            CaBuilder::new("x", github()).backdate(Duration::MAX),
        ] {
            assert!(matches!(check(builder), CaError::InvalidSetting { .. }));
        }
    }

    #[test]
    fn the_ca_certificate_carries_critical_ca_and_name_constraints() {
        let ca = ca(github());
        let der = ca.certificate().der().as_ref();
        // basicConstraints and nameConstraints are both present and critical.
        let basic = [0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
        let names = [0x06, 0x03, 0x55, 0x1d, 0x1e, 0x01, 0x01, 0xff];
        assert!(der.windows(basic.len()).any(|w| w == basic));
        assert!(der.windows(names.len()).any(|w| w == names));
        assert!(
            ca.certificate()
                .pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(ca.constraints().permits("github.com"));
    }

    #[test]
    fn no_key_material_leaves_the_ca() {
        let ca = ca(github());
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
            format!("{:?}", ca.leaf("example.com").unwrap_err()).into_bytes(),
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
        const { assert!(!Probe::<SandboxCa>::IMPLS) };
        const { assert!(!CloneProbe::<SandboxCa>::IMPLS) };
        // The probes do see the traits where they exist.
        const { assert!(Probe::<String>::IMPLS) };
        const { assert!(CloneProbe::<CaCertificate>::IMPLS) };
    }
}
