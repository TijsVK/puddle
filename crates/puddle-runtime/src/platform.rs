// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-OS runtime table and the guest architecture: the one place that spells the file names
//! of msb and its firmware and the Rust target of the guest agent. `check.sh`'s
//! `platform-literals` gate fails on those names anywhere else in `crates/`.

use std::fmt;

/// A host OS puddle knows the runtime layout of (not necessarily one it supports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostOs {
    /// Windows: `msb.exe` and `libkrunfw.dll` side by side.
    Windows,
    /// Linux: `msb` and a versioned `libkrunfw.so.<n>`.
    Linux,
    /// macOS (Apple Silicon): `msb` and `libkrunfw.<n>.dylib`.
    MacOs,
}

impl HostOs {
    /// The OS this build runs on; Unix systems other than macOS are treated as Linux (msb's
    /// layout there is the same).
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }

    /// From a `std::env::consts::OS` / target OS name (`windows`, `linux`, `macos`).
    #[must_use]
    pub fn from_target_os(name: &str) -> Option<Self> {
        match name {
            "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::MacOs),
            _ => None,
        }
    }

    /// The runtime files of this OS.
    #[must_use]
    pub const fn runtime_files(self) -> RuntimeFiles {
        match self {
            Self::Windows => RuntimeFiles {
                msb: "msb.exe",
                libkrunfw: "libkrunfw.dll",
                libkrunfw_prefix: "libkrunfw.dll",
                firmware_beside_msb: true,
            },
            Self::Linux => RuntimeFiles {
                msb: "msb",
                libkrunfw: "libkrunfw.so.5",
                libkrunfw_prefix: "libkrunfw.so",
                firmware_beside_msb: false,
            },
            Self::MacOs => RuntimeFiles {
                msb: "msb",
                libkrunfw: "libkrunfw.5.dylib",
                libkrunfw_prefix: "libkrunfw.",
                firmware_beside_msb: false,
            },
        }
    }
}

/// The file names of the msb runtime on one OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFiles {
    /// The msb executable.
    pub msb: &'static str,
    /// The firmware library as puddle installs it (the SONAME msb's SDK config can point at).
    pub libkrunfw: &'static str,
    /// What every release name of the firmware library starts with, for finding it in a folder
    /// (`libkrunfw.so.5.6.1`, `libkrunfw.so.5`, `libkrunfw.so`).
    pub libkrunfw_prefix: &'static str,
    /// Whether msb finds the firmware only beside itself, so the runtime folder must hold it
    /// (Windows). Elsewhere msb searches its library paths by version, and puddle doesn't ship
    /// the file yet (v1).
    pub firmware_beside_msb: bool,
}

/// The architecture of the sandbox guests, which is the host's: msb runs guests of its own
/// architecture (macOS Apple Silicon guests are `aarch64`, and have no Rosetta).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuestArch {
    /// 64-bit x86 (`x86_64`): the only guest puddle builds and tests today.
    X86_64,
    /// 64-bit Arm (`aarch64`): named so every table has the row; nothing is built for it yet.
    Aarch64,
}

impl GuestArch {
    /// The guest architecture of this host.
    #[must_use]
    pub fn host() -> Option<Self> {
        Self::parse(std::env::consts::ARCH)
    }

    /// From `std::env::consts::ARCH` / `uname -m` spelling (`x86_64`, `amd64`, `aarch64`,
    /// `arm64`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// The canonical name (`x86_64`, `aarch64`), as the doctor report spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// The Rust target the guest agent is built for: a static musl binary that runs in any guest
    /// image. `ci/build-agent.sh` repeats these (a test keeps them equal).
    #[must_use]
    pub const fn agent_target(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-musl",
            Self::Aarch64 => "aarch64-unknown-linux-musl",
        }
    }

    /// Whether puddle builds and tests guests of this architecture today.
    #[must_use]
    pub const fn is_built(self) -> bool {
        matches!(self, Self::X86_64)
    }
}

impl fmt::Display for GuestArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OS: [HostOs; 3] = [HostOs::Windows, HostOs::Linux, HostOs::MacOs];

    #[test]
    fn the_table_per_os() {
        let w = HostOs::Windows.runtime_files();
        assert_eq!((w.msb, w.libkrunfw), ("msb.exe", "libkrunfw.dll"));
        assert!(w.firmware_beside_msb);
        let l = HostOs::Linux.runtime_files();
        assert_eq!((l.msb, l.libkrunfw), ("msb", "libkrunfw.so.5"));
        assert!(!l.firmware_beside_msb);
        let m = HostOs::MacOs.runtime_files();
        assert_eq!((m.msb, m.libkrunfw), ("msb", "libkrunfw.5.dylib"));
        assert!(!m.firmware_beside_msb);
    }

    #[test]
    fn every_installed_firmware_name_matches_its_prefix() {
        for os in ALL_OS {
            let f = os.runtime_files();
            assert!(f.libkrunfw.starts_with(f.libkrunfw_prefix), "{os:?}");
        }
    }

    #[test]
    fn target_os_names_map_to_the_table() {
        for (name, os) in [
            ("windows", HostOs::Windows),
            ("linux", HostOs::Linux),
            ("macos", HostOs::MacOs),
        ] {
            assert_eq!(HostOs::from_target_os(name), Some(os));
        }
        assert_eq!(HostOs::from_target_os("freebsd"), None);
        assert_eq!(
            HostOs::from_target_os(std::env::consts::OS),
            Some(HostOs::current())
        );
    }

    #[test]
    fn architectures_parse_and_name_their_agent_target() {
        for (spelling, arch) in [
            ("x86_64", GuestArch::X86_64),
            ("amd64", GuestArch::X86_64),
            ("aarch64", GuestArch::Aarch64),
            ("arm64", GuestArch::Aarch64),
        ] {
            assert_eq!(GuestArch::parse(spelling), Some(arch));
        }
        assert_eq!(GuestArch::parse("riscv64"), None);
        assert_eq!(
            GuestArch::X86_64.agent_target(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            GuestArch::Aarch64.agent_target(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(GuestArch::Aarch64.to_string(), "aarch64");
        assert!(GuestArch::X86_64.is_built());
        assert!(!GuestArch::Aarch64.is_built());
    }

    #[test]
    fn the_build_script_knows_every_agent_target() {
        let script = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ci/build-agent.sh"
        ))
        .unwrap();
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            assert!(script.contains(arch.agent_target()), "{arch}");
            assert!(script.contains(arch.name()), "{arch}");
        }
    }
}
