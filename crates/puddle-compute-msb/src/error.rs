// SPDX-License-Identifier: GPL-3.0-or-later
//! SDK errors to [`ComputeError`].

use microsandbox::MicrosandboxError;
use puddle_compute::ComputeError;
use puddle_types::SandboxStatus;

/// Maps an SDK error from operation `op` on `target` (a sandbox name, or the image or volume the
/// call was about) to a [`ComputeError`]. Matches on the SDK's variants; anything without a
/// counterpart becomes [`ComputeError::Runtime`] with the SDK's message.
#[must_use]
pub fn map(op: &'static str, target: &str, error: MicrosandboxError) -> ComputeError {
    match error {
        MicrosandboxError::SandboxNotFound(_) => ComputeError::NotFound {
            sandbox: target.to_owned(),
        },
        MicrosandboxError::SandboxAlreadyExists(_) => ComputeError::AlreadyExists {
            sandbox: target.to_owned(),
        },
        MicrosandboxError::SandboxReplaced { .. } => ComputeError::StaleHandle {
            sandbox: target.to_owned(),
        },
        MicrosandboxError::SandboxStillRunning(_) => ComputeError::InvalidState {
            sandbox: target.to_owned(),
            op,
            status: SandboxStatus::Running,
        },
        MicrosandboxError::SandboxNotRunning(_) => ComputeError::InvalidState {
            sandbox: target.to_owned(),
            op,
            status: SandboxStatus::Stopped,
        },
        MicrosandboxError::VolumeNotFound(volume) => ComputeError::VolumeNotFound { volume },
        MicrosandboxError::VolumeAlreadyExists(volume) => ComputeError::VolumeExists { volume },
        e @ (MicrosandboxError::ImageNotFound(_) | MicrosandboxError::Image(_)) => {
            ComputeError::ImagePull {
                image: target.to_owned(),
                reason: e.to_string(),
            }
        }
        MicrosandboxError::InvalidConfig(reason) => ComputeError::InvalidSpec { reason },
        other => runtime(op, &other),
    }
}

/// [`ComputeError::Runtime`] with `error`'s message.
#[must_use]
pub(crate) fn runtime(op: &'static str, error: &dyn std::fmt::Display) -> ComputeError {
    ComputeError::Runtime {
        op,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_variants_map_to_their_counterparts() {
        let m = |e| map("start", "box", e);
        assert_eq!(
            m(MicrosandboxError::SandboxNotFound("box".into())),
            ComputeError::NotFound {
                sandbox: "box".into()
            }
        );
        assert_eq!(
            m(MicrosandboxError::SandboxAlreadyExists("box".into())),
            ComputeError::AlreadyExists {
                sandbox: "box".into()
            }
        );
        assert_eq!(
            m(MicrosandboxError::SandboxReplaced {
                name: "box".into(),
                expected: "1".into(),
                actual: "2".into(),
            }),
            ComputeError::StaleHandle {
                sandbox: "box".into()
            }
        );
        assert_eq!(
            m(MicrosandboxError::SandboxStillRunning("box".into())),
            ComputeError::InvalidState {
                sandbox: "box".into(),
                op: "start",
                status: SandboxStatus::Running
            }
        );
        assert_eq!(
            m(MicrosandboxError::SandboxNotRunning(
                "box is stopped".into()
            )),
            ComputeError::InvalidState {
                sandbox: "box".into(),
                op: "start",
                status: SandboxStatus::Stopped
            }
        );
        assert_eq!(
            m(MicrosandboxError::VolumeNotFound("ws-a".into())),
            ComputeError::VolumeNotFound {
                volume: "ws-a".into()
            }
        );
        assert_eq!(
            m(MicrosandboxError::VolumeAlreadyExists("ws-a".into())),
            ComputeError::VolumeExists {
                volume: "ws-a".into()
            }
        );
        assert_eq!(
            m(MicrosandboxError::InvalidConfig("bad".into())),
            ComputeError::InvalidSpec {
                reason: "bad".into()
            }
        );
    }

    #[test]
    fn image_errors_name_the_image() {
        let e = map(
            "pull image",
            "x.invalid/none:0",
            MicrosandboxError::ImageNotFound("x.invalid/none:0".into()),
        );
        assert!(
            matches!(&e, ComputeError::ImagePull { image, reason }
                if image == "x.invalid/none:0" && reason.contains("image not found")),
            "{e:?}"
        );
    }

    #[test]
    fn everything_else_keeps_the_sdk_message() {
        assert_eq!(
            map("stop", "box", MicrosandboxError::Runtime("vmm gone".into())),
            ComputeError::Runtime {
                op: "stop",
                message: "runtime error: vmm gone".into()
            }
        );
        assert_eq!(
            map("exec", "box", MicrosandboxError::Custom("boom".into())),
            ComputeError::Runtime {
                op: "exec",
                message: "boom".into()
            }
        );
    }
}
