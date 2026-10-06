// SPDX-License-Identifier: GPL-3.0-or-later
//! The test boot: msb boots a microVM from a tiny root file system that holds one program, which
//! exits with [`PROBE_EXIT_CODE`]. That exit code proves the whole path: msb started, the
//! hypervisor made a VM, the guest kernel and msb's agent came up, and a program ran inside.
//!
//! It needs no image download and no network. msb runs with a throwaway `MSB_HOME`, so the test
//! leaves nothing in puddle's real one.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use puddle_runtime::{RuntimeEnv, RuntimeLayout};

use crate::diagnose::PROBE_EXIT_CODE;
use crate::facts::BootFacts;
use crate::launch;

/// The probe's path inside the guest.
const PROBE_GUEST_PATH: &str = "/probe";

/// A statically linked x86-64 Linux program of 132 bytes, without libc or loader: one ELF header,
/// one loadable segment, and the code `mov edi, 42; mov eax, 231 (exit_group); syscall`.
#[must_use]
pub fn probe_x86_64() -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    const EHDR: u16 = 64;
    const PHDR: u16 = 56;
    let exit = u8::try_from(PROBE_EXIT_CODE).unwrap_or(42);
    let code = [
        0xbf, exit, 0, 0, 0, // mov edi, 42
        0xb8, 0xe7, 0, 0, 0, // mov eax, 231 (exit_group)
        0x0f, 0x05, // syscall
    ];
    let total = u64::from(EHDR) + u64::from(PHDR) + code.len() as u64;
    let mut elf = Vec::with_capacity(132);
    // e_ident: magic, 64-bit, little-endian, version 1, System V ABI, padding.
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf.extend_from_slice(&2_u16.to_le_bytes()); // e_type: executable
    elf.extend_from_slice(&0x3e_u16.to_le_bytes()); // e_machine: x86-64
    elf.extend_from_slice(&1_u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&(BASE + u64::from(EHDR + PHDR)).to_le_bytes()); // e_entry
    elf.extend_from_slice(&u64::from(EHDR).to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0_u64.to_le_bytes()); // e_shoff: no sections
    elf.extend_from_slice(&0_u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&EHDR.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&PHDR.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1_u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64_u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0_u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0_u16.to_le_bytes()); // e_shstrndx
    elf.extend_from_slice(&1_u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5_u32.to_le_bytes()); // p_flags: read + execute
    elf.extend_from_slice(&0_u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&total.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&total.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000_u64.to_le_bytes()); // p_align
    elf.extend_from_slice(&code);
    elf
}

/// Writes the guest's root file system into `dir`: the probe, plus the `/etc/passwd` and
/// `/etc/group` msb's agent reads to resolve the user it runs a command as.
///
/// # Errors
///
/// Any file system error.
pub fn write_rootfs(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(PROBE_GUEST_PATH.trim_start_matches('/'));
    std::fs::write(&probe, probe_x86_64())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755))?;
    }
    let etc = dir.join("etc");
    std::fs::create_dir_all(&etc)?;
    std::fs::write(
        etc.join("passwd"),
        format!("root:x:0:0:root:/:{PROBE_GUEST_PATH}\n"),
    )?;
    std::fs::write(etc.join("group"), "root:x:0:\n")?;
    Ok(())
}

/// Boots a test VM with the msb in `runtime_dir`, giving up after `limit`. Uses a throwaway msb
/// home and root file system in the temp dir;.
#[must_use]
pub fn test_boot(runtime_dir: &Path, arch: &str, limit: Duration) -> BootFacts {
    if arch != "x86_64" {
        return BootFacts::UnsupportedArch {
            arch: arch.to_owned(),
        };
    }
    let start = Instant::now();
    let work = match tempfile::Builder::new().prefix("puddle-doctor-").tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return BootFacts::SetupFailed {
                detail: format!("temp dir: {e}"),
            };
        }
    };
    let rootfs = work.path().join("rootfs");
    let prepared = std::fs::create_dir_all(&rootfs).and_then(|()| write_rootfs(&rootfs));
    if let Err(e) = prepared {
        return BootFacts::SetupFailed {
            detail: format!("{}: {e}", rootfs.display()),
        };
    }
    let layout = match RuntimeLayout::new(runtime_dir.to_path_buf(), work.path().join("home")) {
        Ok(layout) => layout,
        Err(e) => {
            return BootFacts::SetupFailed {
                detail: e.to_string(),
            };
        }
    };
    let outcome = launch::run(
        &mut command(&layout, &rootfs),
        limit.saturating_sub(start.elapsed()),
    );
    BootFacts::Ran { outcome }
}

fn command(layout: &RuntimeLayout, rootfs: &Path) -> Command {
    let mut cmd = Command::new(layout.msb_path());
    RuntimeEnv::plan(layout, std::env::vars_os()).apply_to(&mut cmd);
    cmd.arg("run")
        .arg(rootfs)
        .args(["--no-stdin", "--", PROBE_GUEST_PATH]);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_is_a_valid_static_x86_64_executable() {
        use object::{Object, ObjectSegment};
        let bytes = probe_x86_64();
        assert_eq!(bytes.len(), 132);
        let file = object::File::parse(&*bytes).unwrap();
        assert_eq!(file.architecture(), object::Architecture::X86_64);
        assert_eq!(file.kind(), object::ObjectKind::Executable);
        let seg = file.segments().next().unwrap();
        let entry = file.entry();
        assert!(entry >= seg.address() && entry < seg.address() + seg.size());
        // The code at the entry point sets the exit code to PROBE_EXIT_CODE.
        let at = usize::try_from(entry - seg.address()).unwrap();
        assert_eq!(&bytes[at..at + 2], &[0xbf, 42]);
    }

    #[test]
    fn rootfs_holds_the_probe_and_the_root_user() {
        let dir = tempfile::tempdir().unwrap();
        write_rootfs(dir.path()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("probe")).unwrap(),
            probe_x86_64()
        );
        let passwd = std::fs::read_to_string(dir.path().join("etc/passwd")).unwrap();
        assert!(passwd.starts_with("root:x:0:0:"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("probe"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn other_architectures_are_not_booted() {
        assert_eq!(
            test_boot(Path::new("/nonexistent"), "aarch64", Duration::from_secs(1)),
            BootFacts::UnsupportedArch {
                arch: "aarch64".into()
            }
        );
    }

    #[test]
    fn the_command_runs_the_probe_with_a_private_home() {
        let layout = RuntimeLayout::new(
            std::env::temp_dir().join("rt"),
            std::env::temp_dir().join("h"),
        )
        .unwrap();
        let cmd = command(&layout, Path::new("/r"));
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["run", "/r", "--no-stdin", "--", "/probe"]);
        assert!(
            cmd.get_envs()
                .any(|(k, v)| k == "MSB_HOME" && v == Some(layout.home().as_os_str()))
        );
    }
}
