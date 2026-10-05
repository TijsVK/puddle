// SPDX-License-Identifier: GPL-3.0-or-later
//! Reads the version msb embeds in its own binary, without running it.
//!
//! msb's CLI (since 0.7.6) stores its Cargo package version as plain UTF-8 in a section named
//! `.msbver` (ELF and PE). The SDK's `setup::resolve_runtime_version` reads the same section, but
//! the SDK only exposes it with its `local` feature, i.e. the whole runtime client; this crate
//! stays independent of the SDK so it builds and tests without it (T-107 brief). The two readers
//! agree on the format: the section's bytes are the version, 1 to [`MAX_VERSION_BYTES`] long.

use std::fs::File;
use std::path::Path;

use object::read::ReadCache;
use object::{Object, ObjectSection};

/// The section msb's binary carries its version in.
pub const VERSION_SECTION: &str = ".msbver";

/// The largest version section accepted (msb's own limit).
pub const MAX_VERSION_BYTES: u64 = 256;

/// Reads the embedded runtime version of the executable at `path`.
///
/// Only the headers, the section table and the version section are read (through a cache), never
/// the whole 60 MB binary, and nothing is executed. `Ok(None)` means the file is a valid ELF, PE
/// or COFF file without a version section.
///
/// # Errors
///
/// A message when the file can't be opened, isn't an ELF/PE/COFF file, or has more than one,
/// an empty, an oversized or a non-UTF-8 version section.
pub fn read_embedded_version(path: &Path) -> Result<Option<String>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let cache = ReadCache::new(file);
    let parsed = object::File::parse(&cache).map_err(|e| e.to_string())?;
    let mut sections = parsed.sections().filter(|s| {
        s.name_bytes()
            .is_ok_and(|n| n == VERSION_SECTION.as_bytes())
    });
    let Some(section) = sections.next() else {
        return Ok(None);
    };
    if sections.next().is_some() {
        return Err("more than one version section".into());
    }
    let size = section.size();
    if size == 0 || size > MAX_VERSION_BYTES {
        return Err(format!(
            "version section must hold 1 to {MAX_VERSION_BYTES} bytes, has {size}"
        ));
    }
    let bytes = section.data().map_err(|e| e.to_string())?;
    // PE pads raw section data to the file alignment; the version is the bytes before padding.
    let used = bytes
        .get(..usize::try_from(size).unwrap_or(usize::MAX))
        .unwrap_or(bytes);
    let text = std::str::from_utf8(used).map_err(|_| "version section is not UTF-8".to_owned())?;
    let text = text.trim_end_matches('\0');
    if text.is_empty() {
        return Err("version section is empty".into());
    }
    Ok(Some(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WriteObject, StandardSection};
    use object::{Architecture, BinaryFormat, Endianness, SectionKind};

    fn object_with(format: BinaryFormat, sections: &[&[u8]]) -> Vec<u8> {
        let mut obj = WriteObject::new(format, Architecture::X86_64, Endianness::Little);
        let text = obj.section_id(StandardSection::Text);
        obj.append_section_data(text, &[0xc3], 1);
        for data in sections {
            let id = obj.add_section(
                Vec::new(),
                VERSION_SECTION.into(),
                SectionKind::ReadOnlyData,
            );
            obj.append_section_data(id, data, 1);
        }
        obj.write().unwrap()
    }

    fn read(bytes: &[u8]) -> Result<Option<String>, String> {
        let dir = std::env::temp_dir().join(format!(
            "puddle-runtime-msbver-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("msb");
        std::fs::write(&path, bytes).unwrap();
        let got = read_embedded_version(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        got
    }

    fn unique() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn reads_the_version_from_elf_and_coff() {
        for format in [BinaryFormat::Elf, BinaryFormat::Coff] {
            let bytes = object_with(format, &[b"0.7.7-puddle.1"]);
            assert_eq!(
                read(&bytes),
                Ok(Some("0.7.7-puddle.1".into())),
                "{format:?}"
            );
        }
    }

    #[test]
    fn no_section_is_none() {
        assert_eq!(read(&object_with(BinaryFormat::Elf, &[])), Ok(None));
        assert_eq!(read(&object_with(BinaryFormat::Coff, &[])), Ok(None));
    }

    #[test]
    fn malformed_sections_are_errors() {
        let two = object_with(BinaryFormat::Elf, &[b"0.7.7", b"0.7.8"]);
        assert!(read(&two).unwrap_err().contains("more than one"));
        let big = vec![b'1'; 257];
        let err = read(&object_with(BinaryFormat::Elf, &[&big])).unwrap_err();
        assert!(err.contains("1 to 256 bytes"), "{err}");
        let not_utf8 = object_with(BinaryFormat::Elf, &[&[0xff, 0xfe]]);
        assert!(read(&not_utf8).unwrap_err().contains("UTF-8"));
        let nul = object_with(BinaryFormat::Elf, &[&[0, 0]]);
        assert!(read(&nul).unwrap_err().contains("empty"));
    }

    #[test]
    fn exactly_256_bytes_is_fine() {
        let max = vec![b'7'; 256];
        let got = read(&object_with(BinaryFormat::Elf, &[&max])).unwrap();
        assert_eq!(got.map(|s| s.len()), Some(256));
    }

    #[test]
    fn non_executables_and_missing_files_are_errors() {
        assert!(read(b"#!/bin/sh\necho 0.7.7-puddle.1\n").is_err());
        assert!(read(b"").is_err());
        let missing = read_embedded_version(Path::new("/nonexistent/puddle/msb"));
        assert!(missing.is_err());
    }
}
