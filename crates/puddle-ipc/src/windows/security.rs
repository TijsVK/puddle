// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's only unsafe code: creating a pipe instance with an explicit security descriptor.
//! The user's SID and descriptor helpers live in `puddle_fs::win`.

use std::ffi::{OsStr, c_void};
use std::io;

use puddle_fs::win::LocalBox;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// Creates one pipe instance whose security descriptor is `sddl`.
pub(super) fn create_pipe(
    options: &ServerOptions,
    path: &OsStr,
    sddl: &str,
) -> io::Result<NamedPipeServer> {
    let descriptor = LocalBox::security_descriptor(sddl)?;
    let mut attrs = descriptor.attributes();
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the whole call, and the descriptor it
    // points at (`descriptor`) is freed only after the call returns.
    unsafe { options.create_with_security_attributes_raw(path, (&raw mut attrs).cast::<c_void>()) }
}

#[cfg(test)]
mod tests {
    //! A real pipe: the DACL as the OS reports it, and clients under restricted tokens.

    use std::path::Path;

    use puddle_fs::win::testing::{assert_access_denied, assert_owner_only_dacl, open_restricted};
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    use super::*;
    use crate::IpcRoot;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_restricted_token_client_is_refused() {
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        let path = listener.endpoint().path().to_path_buf();
        assert_access_denied(open_restricted(&path, GENERIC_READ | GENERIC_WRITE, false));
        // Read alone is what the default DACL gives Everyone; ours must not.
        assert_access_denied(open_restricted(&path, GENERIC_READ, false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_restricted_token_with_the_user_sid_gets_in() {
        // Positive control: the same restricted token plus the user's SID opens the pipe, so the
        // refusal above comes from the DACL, not from the restricted-token setup.
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        open_restricted(
            listener.endpoint().path(),
            GENERIC_READ | GENERIC_WRITE,
            true,
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_default_dacl_would_let_the_restricted_client_read() {
        // Negative control: a pipe with Windows' default DACL (what the PoC had) lets the same
        // restricted client open it for reading, so the tests above can tell the difference.
        let path = format!(
            r"\\.\pipe\puddle-control-{}",
            crate::name::random_name::<16>().unwrap()
        );
        let _server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        open_restricted(Path::new(&path), GENERIC_READ, false).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_dacl_has_exactly_one_ace_for_the_current_user() {
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        let client = ClientOptions::new()
            .open(listener.endpoint().path())
            .unwrap();
        assert_owner_only_dacl(&client, FILE_ALL_ACCESS);
    }
}
