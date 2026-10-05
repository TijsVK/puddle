// SPDX-License-Identifier: GPL-3.0-or-later
//! Compute plane: the traits every microVM runtime implements, and the types they take.
//!
//! Other crates code against [`Runtime`] and [`Sandbox`], never against the msb SDK; the SDK
//! adapter lives in its own crate (`puddle-compute-msb`), so everything else builds and tests
//! without it.
//!
//! # Trait surface
//!
//! | Need | Call |
//! |---|---|
//! | runtime version, workaround flags | [`Runtime::probe`] → [`Capabilities`] |
//! | image cached + its ENTRYPOINT/CMD/ENV | [`Runtime::pull_image`] → [`ImageConfig`] |
//! | create and boot | [`Runtime::create`] with a [`SandboxSpec`] → owning [`Sandbox`] handle |
//! | boot again | [`Runtime::start`] → owning handle |
//! | re-adopt a running sandbox | [`Runtime::get`] → non-owning handle |
//! | list / delete | [`Runtime::list`], [`Runtime::remove`] |
//! | clean up after failed creates | [`Runtime::stale_dirs`], [`Runtime::remove_stale_dir`] |
//! | named disk volumes | [`Runtime::create_volume`], [`Runtime::volume`] (incl. holder), [`Runtime::list_volumes`], [`Runtime::remove_volume`] |
//! | stop, state | [`Sandbox::stop`], [`Sandbox::status`] |
//! | run a command | [`Sandbox::exec`] with an [`ExecRequest`] → [`ExecOutput`] |
//! | SSH on a pipe/socket | [`Sandbox::serve_ssh`] on any [`SshStream`] |
//!
//! A [`SandboxSpec`] carries: image, memory ([`puddle_types::MemoryMib`]), env
//! ([`puddle_types::GuestEnv`]), [`NetworkPolicy::None`] plus [`VsockRoute`]s, read-only
//! [`FileMount`]s, named [`VolumeMount`]s and [`OwnedDisk`]s. Errors are one enum,
//! [`ComputeError`].
//!
//! # Features
//!
//! - `fake`: [`fake::FakeRuntime`], an in-memory msb with fault injection, a call log and a small
//!   command interpreter, for unit tests of the crates above this one.
//! - `contract`: [`contract`], the suite every runtime passes (the fake here, the SDK adapter on
//!   VMs), and the [`contract_tests!`] macro.
//!
//! Crates that test against the fake add
//! `puddle-compute = { workspace = true, features = ["fake"] }` under `[dev-dependencies]`.
//!
//! The traits use `impl Future + Send` returns (no `async-trait`), so implementations can write
//! `async fn` and callers can spawn the futures. They aren't object-safe: be generic over
//! `R: Runtime`.
#![forbid(unsafe_code)]

#[cfg(feature = "contract")]
pub mod contract;
mod error;
mod exec;
#[cfg(feature = "fake")]
pub mod fake;
mod runtime;
mod spec;

pub use error::ComputeError;
pub use exec::{ExecOutput, ExecRequest, ExitStatus};
pub use runtime::{
    Capabilities, ImageConfig, Runtime, Sandbox, SandboxInfo, SshStream, VolumeInfo, VolumeSpec,
};
pub use spec::{
    DiskSize, FileMount, NetworkPolicy, OwnedDisk, SandboxSpec, VolumeMount, VsockRoute,
};
