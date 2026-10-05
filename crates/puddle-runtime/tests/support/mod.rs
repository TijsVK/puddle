// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixtures shared by the integration tests: a temp dir per test and fake msb binaries.

use std::path::{Path, PathBuf};

use object::write::{Object, StandardSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind};

/// A directory removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "puddle-runtime-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An object file shaped like msb's binary: a code section plus `.msbver` holding `version`
/// (none when `None`). Only its sections matter to the version reader.
pub(crate) fn fake_msb(version: Option<&str>) -> Vec<u8> {
    let format = if cfg!(windows) {
        BinaryFormat::Coff
    } else {
        BinaryFormat::Elf
    };
    let mut obj = Object::new(format, Architecture::X86_64, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    obj.append_section_data(text, &[0xc3], 1);
    if let Some(v) = version {
        let id = obj.add_section(Vec::new(), b".msbver".to_vec(), SectionKind::ReadOnlyData);
        obj.append_section_data(id, v.as_bytes(), 1);
    }
    obj.write().unwrap()
}
