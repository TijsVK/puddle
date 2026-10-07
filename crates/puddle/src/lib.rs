// SPDX-License-Identifier: GPL-3.0-or-later
//! The puddle host program: CLI and daemon. It wires the compute plane, proxy, store and API
//! together. Today it answers `--version`, `--help`, `doctor` and `ssh-bridge`.
#![forbid(unsafe_code)]

pub mod cli;
pub mod cmd;
