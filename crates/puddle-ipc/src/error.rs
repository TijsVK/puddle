// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's one error type.

use std::io;
use std::path::PathBuf;

/// What went wrong creating, binding or connecting to an endpoint.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// Something already exists at the endpoint's name. puddle never shares a name with another
    /// process: the workspace must not boot against this endpoint.
    #[error(
        "endpoint {endpoint} already exists; another process may be squatting it, so puddle refuses to use it"
    )]
    NameTaken {
        /// The endpoint that was taken.
        endpoint: PathBuf,
    },
    /// The endpoint was made by a different [`IpcRoot`](crate::IpcRoot).
    #[error("endpoint {endpoint} is not in the ipc root {root}")]
    ForeignEndpoint {
        /// The endpoint passed in.
        endpoint: PathBuf,
        /// The root it was passed to.
        root: PathBuf,
    },
    /// A Unix socket path is longer than the OS allows.
    #[error("socket path {path} is {len} bytes; the limit is {max}")]
    PathTooLong {
        /// The path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
        /// The longest path the OS accepts.
        max: usize,
    },
    /// The root (directory, or the user's security identity on Windows) couldn't be set up.
    #[error("could not set up the ipc root {path}")]
    Root {
        /// The directory, or a description of what was being read.
        path: PathBuf,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// The system random source failed, so no unguessable name could be made.
    #[error("the system random source failed")]
    Random(#[source] getrandom::Error),
    /// Called outside a tokio runtime with I/O enabled.
    #[error("no tokio runtime: endpoints are bound and connected inside one")]
    NoRuntime,
    /// Nothing listens at the endpoint.
    #[error("nothing listens at {endpoint}")]
    NotFound {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// The endpoint refused this process.
    #[error("access to {endpoint} was denied")]
    AccessDenied {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// Every pipe instance stayed busy for the whole connect timeout.
    #[error("every instance of {endpoint} stayed busy")]
    Busy {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// The listener can't accept any more connections.
    #[error("listener {endpoint} is closed")]
    Closed {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// Any other OS error.
    #[error("could not {op} {endpoint}")]
    Io {
        /// What was being done ("bind", "accept on", "connect to", ...).
        op: &'static str,
        /// The endpoint.
        endpoint: PathBuf,
        /// The OS error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn messages_name_the_endpoint_and_keep_the_cause_as_source() {
        let e = IpcError::Io {
            op: "bind",
            endpoint: PathBuf::from("/r/x.sock"),
            source: io::Error::from(io::ErrorKind::AddrInUse),
        };
        assert_eq!(e.to_string(), "could not bind /r/x.sock");
        assert!(e.source().is_some());

        let e = IpcError::NameTaken {
            endpoint: PathBuf::from(r"\\.\pipe\puddle-ab"),
        };
        assert!(e.to_string().contains(r"\\.\pipe\puddle-ab"));
        assert!(e.to_string().contains("squatting"));
    }

    #[test]
    fn every_variant_has_a_lowercase_message_without_a_trailing_period() {
        let p = || PathBuf::from("/p");
        let all = [
            IpcError::NameTaken { endpoint: p() },
            IpcError::ForeignEndpoint {
                endpoint: p(),
                root: p(),
            },
            IpcError::PathTooLong {
                path: p(),
                len: 200,
                max: 107,
            },
            IpcError::Root {
                path: p(),
                source: io::Error::other("x"),
            },
            IpcError::Random(getrandom::Error::UNSUPPORTED),
            IpcError::NoRuntime,
            IpcError::NotFound { endpoint: p() },
            IpcError::AccessDenied { endpoint: p() },
            IpcError::Busy { endpoint: p() },
            IpcError::Closed { endpoint: p() },
            IpcError::Io {
                op: "bind",
                endpoint: p(),
                source: io::Error::other("x"),
            },
        ];
        for e in all {
            let m = e.to_string();
            assert!(m.chars().next().unwrap().is_lowercase(), "{m}");
            assert!(!m.ends_with('.'), "{m}");
        }
    }
}
