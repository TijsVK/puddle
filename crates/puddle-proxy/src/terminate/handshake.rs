// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading why a handshake with the guest ended, so that a client that refuses puddle's
//! certificate is told apart from one that merely went away.

use std::io;

use rustls::AlertDescription;

/// The certificate alert the guest's client sent, when that is why the handshake failed: it does
/// not trust the workspace's CA (the usual cause: a tool with its own list of roots), or found
/// something else wrong with the certificate. `None` for every other end: the client closed,
/// stalled or reset, or the failure was puddle's own.
pub(crate) fn rejected_certificate(err: &io::Error) -> Option<&'static str> {
    let tls = err.get_ref()?.downcast_ref::<rustls::Error>()?;
    let rustls::Error::AlertReceived(alert) = tls else {
        return None;
    };
    match alert {
        AlertDescription::UnknownCA => Some("unknown_ca"),
        AlertDescription::BadCertificate => Some("bad_certificate"),
        AlertDescription::CertificateUnknown => Some("certificate_unknown"),
        AlertDescription::UnsupportedCertificate => Some("unsupported_certificate"),
        AlertDescription::CertificateExpired => Some("certificate_expired"),
        AlertDescription::CertificateRevoked => Some("certificate_revoked"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(description: AlertDescription) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(description),
        )
    }

    #[test]
    fn a_certificate_alert_from_the_client_is_a_refused_certificate() {
        for (description, name) in [
            (AlertDescription::UnknownCA, "unknown_ca"),
            (AlertDescription::BadCertificate, "bad_certificate"),
            (AlertDescription::CertificateUnknown, "certificate_unknown"),
            (
                AlertDescription::UnsupportedCertificate,
                "unsupported_certificate",
            ),
            (AlertDescription::CertificateExpired, "certificate_expired"),
            (AlertDescription::CertificateRevoked, "certificate_revoked"),
        ] {
            assert_eq!(rejected_certificate(&alert(description)), Some(name));
        }
    }

    #[test]
    fn any_other_end_of_a_handshake_is_not() {
        for other in [
            alert(AlertDescription::HandshakeFailure),
            alert(AlertDescription::ProtocolVersion),
            alert(AlertDescription::CloseNotify),
            io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof"),
            io::Error::from(io::ErrorKind::ConnectionReset),
            io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::General("no server certificate chain resolved".into()),
            ),
        ] {
            assert_eq!(rejected_certificate(&other), None, "{other}");
        }
    }
}
