// SPDX-License-Identifier: GPL-3.0-or-later
//! Generates Tauri's context and the app ACL manifest .
//!
//! With a manifest, an app command is allowed to nobody until a capability grants it by name.
//! Without one, every app command is open to any local origin in any window. The shell has no
//! app commands today (the SPA uses no Tauri IPC); `ping` is declared so the ACL tests have a
//! real command to be refused, and so the manifest is in force when the first real one arrives.

#![expect(
    clippy::expect_used,
    reason = "a build script has no caller to return an error to; a failure must stop the build"
)]

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["ping"])),
    )
    .expect("tauri-build failed");
}
