// SPDX-License-Identifier: GPL-3.0-or-later
//! The check behind `BUILT_FOR`, shared by the build script and `tests/built_for.rs`: the msb
//! runtime version is the `microsandbox` SDK package's version in `Cargo.lock`, which must come
//! from the fork tag `v<version>`, with every other `microsandbox*` crate from the same source.

/// The fork every `microsandbox*` package must come from.
pub(crate) const FORK: &str = "git+https://github.com/TijsVK/microsandbox?tag=v";

/// The `microsandbox` package's version, checked against its fork tag and its sibling crates.
pub(crate) fn built_for(lock: &str) -> Result<String, String> {
    let mut sdk = None;
    let mut sources = Vec::new();
    for package in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            package.lines().find_map(|line| {
                line.strip_prefix(key)
                    .and_then(|rest| rest.strip_prefix(" = \""))
                    .and_then(|rest| rest.strip_suffix('"'))
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        if !name.starts_with("microsandbox") {
            continue;
        }
        let source = field("source").unwrap_or("(path)");
        sources.push(format!("{name} {version} {source}"));
        if name == "microsandbox" {
            sdk = Some((version, source));
        }
    }
    let (version, source) = sdk.ok_or("no `microsandbox` package in Cargo.lock")?;
    let tag = source
        .strip_prefix(FORK)
        .and_then(|rest| rest.split_once('#'))
        .map(|(tag, _)| tag)
        .ok_or_else(|| format!("the msb SDK must come from {FORK}<version>, not {source}"))?;
    if tag != version {
        return Err(format!(
            "the msb SDK's fork tag v{tag} doesn't match its package version {version}"
        ));
    }
    let odd: Vec<_> = sources
        .iter()
        .filter(|line| !line.ends_with(source) || !line.contains(&format!(" {version} ")))
        .collect();
    if !odd.is_empty() {
        return Err(format!(
            "every microsandbox crate must come from {source}; these don't: {odd:?}"
        ));
    }
    Ok(version.to_owned())
}
