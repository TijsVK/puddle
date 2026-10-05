// SPDX-License-Identifier: GPL-3.0-or-later
//! The puddle host program: CLI and daemon. It wires the compute plane, proxy, store and API
//! together (MWE plan W7). Today it only answers `--version` and `--help`.
#![forbid(unsafe_code)]

pub mod cli;
