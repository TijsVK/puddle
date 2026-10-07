// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg_attr(not(windows), forbid(unsafe_code))]
//! The two file-system seams that differ per OS:
//!
//! - [`data_dir`]: puddle's per-user data folder, resolved by the `dirs` crate in this one place.
//! - [`private`]: owner-only files and folders. On Unix the modes `0600` / `0700`; on Windows an
//!   explicit, protected ACL with one entry, for the current user.
//!
//! | OS | `data_dir()` |
//! |---|---|
//! | Windows | `%LOCALAPPDATA%\puddle` (not roaming: it holds a VM disk and a token) |
//! | Linux | `$XDG_DATA_HOME/puddle`, else `~/.local/share/puddle` |
//! | macOS | `~/Library/Application Support/puddle` |

mod data_dir;
pub mod private;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 calls for the user's SID, security descriptors and ACLs"
)]
pub mod win;

pub use data_dir::{DataDirError, data_dir, data_dir_in};
