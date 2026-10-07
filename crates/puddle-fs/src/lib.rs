// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
//! The two file-system seams that differ per OS (T-150, D-66):
//!
//! - [`data_dir`]: puddle's per-user data folder, resolved by the `dirs` crate in this one place.
//! - [`private`]: owner-only files and folders. On Unix the modes `0600` / `0700`; on Windows the
//!   file inherits its folder's ACL for now, and the explicit owner-only ACL (T-093) lands in
//!   `private/windows.rs`.
//!
//! | OS | `data_dir()` |
//! |---|---|
//! | Windows | `%LOCALAPPDATA%\puddle` (not roaming: it holds a VM disk and a token) |
//! | Linux | `$XDG_DATA_HOME/puddle`, else `~/.local/share/puddle` |
//! | macOS | `~/Library/Application Support/puddle` |

mod data_dir;
pub mod private;

pub use data_dir::{DataDirError, data_dir, data_dir_in};
