// SPDX-License-Identifier: GPL-3.0-or-later
//! Pulling an image into msb's cache without creating a sandbox, and its config.
//!
//! The SDK 0.7.7 pulls only inside `create`; its image crate does the work, so the adapter calls
//! it the same way `create` does: cache first, then the registry with the backend's registry
//! settings (anonymous unless puddle's `config.json` says otherwise, which it doesn't), plus
//! puddle's registry roots ([`crate::MsbConfig::registry_roots`]).
//!
//! The registry client's proxy is the SDK backend's own setting (`LocalBackendBuilder::registry_proxy`,
//! from [`crate::MsbConfig::registry_proxy`]): puddle's image-pull proxy (`puddle_proxy::PullProxy`,
//! T-116). It comes back in the resolved registry settings and replaces the process environment
//! for the client, so nothing sets `HTTPS_PROXY` (T-144).

use std::collections::BTreeMap;

use microsandbox::LocalBackend;
use microsandbox::config::RegistryOptions;
use microsandbox_image::{GlobalCache, Platform, PullOptions, Reference, Registry};
use puddle_compute::{ComputeError, ImageConfig};
use puddle_types::ImageRef;

/// Makes sure `image` is in `local`'s cache and returns its config.
pub(crate) async fn pull(
    local: &LocalBackend,
    roots: &[String],
    image: &ImageRef,
) -> Result<ImageConfig, ComputeError> {
    let fail = |reason: String| ComputeError::ImagePull {
        image: image.to_string(),
        reason,
    };
    let reference: Reference = image
        .as_str()
        .parse()
        .map_err(|e| fail(format!("invalid image reference: {e}")))?;
    let cache = GlobalCache::new(&local.cache_dir()).map_err(|e| fail(chain(&e)))?;
    let options = PullOptions::default();
    if let Some((result, _)) = Registry::pull_cached_async(&cache, &reference, &options)
        .await
        .map_err(|e| fail(chain(&e)))?
    {
        return Ok(convert(result.config));
    }
    let settings = local
        .registry_config(reference.registry(), RegistryOptions::default())
        .await
        .map_err(|e| fail(chain(&e)))?;
    let mut builder = Registry::builder(Platform::host_linux(), cache)
        .auth(settings.auth)
        .extra_ca_certs(with_roots(settings.ca_certs, roots))
        .add_insecure_registries(settings.insecure_registries);
    if let Some(proxy) = settings.proxy {
        builder = builder.proxy(proxy);
    }
    let registry = builder.build().map_err(|e| fail(chain(&e)))?;
    let result = Box::pin(registry.pull(&reference, &options))
        .await
        .map_err(|e| fail(chain(&e)))?;
    Ok(convert(result.config))
}

/// `err` and its causes, `: `-separated. The registry client's top-level error is only "error
/// sending request"; the cause says why (an unknown certificate issuer behind an intercepting
/// proxy, a refused proxy, a DNS failure), which is what the user needs to see.
fn chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// msb's configured CA certificates (PEM each) followed by puddle's registry roots.
fn with_roots(mut configured: Vec<Vec<u8>>, roots: &[String]) -> Vec<Vec<u8>> {
    configured.extend(roots.iter().map(|pem| pem.as_bytes().to_vec()));
    configured
}

/// The OCI config as puddle's [`ImageConfig`]. `ENV` entries without `=` are kept with an empty
/// value; labels are sorted by key.
pub(crate) fn convert(config: microsandbox_image::ImageConfig) -> ImageConfig {
    ImageConfig {
        entrypoint: config.entrypoint.unwrap_or_default(),
        cmd: config.cmd.unwrap_or_default(),
        env: config
            .env
            .into_iter()
            .map(|entry| match entry.split_once('=') {
                Some((k, v)) => (k.to_owned(), v.to_owned()),
                None => (entry, String::new()),
            })
            .collect(),
        working_dir: config.working_dir.filter(|w| !w.is_empty()),
        user: config.user.filter(|u| !u.is_empty()),
        labels: config.labels.into_iter().collect::<BTreeMap<_, _>>(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn oci_config_becomes_puddles_image_config() {
        let oci = microsandbox_image::ImageConfig {
            env: vec![
                "PATH=/usr/bin:/bin".into(),
                "EMPTY=".into(),
                "A=b=c".into(),
                "BARE".into(),
            ],
            cmd: Some(vec!["bash".into()]),
            entrypoint: Some(vec!["dockerd-entrypoint.sh".into()]),
            working_dir: Some("/src".into()),
            user: Some("vscode".into()),
            labels: HashMap::from([
                ("devcontainer.metadata".to_owned(), "[]".to_owned()),
                ("a".to_owned(), "1".to_owned()),
            ]),
            ..Default::default()
        };
        let c = convert(oci);
        assert_eq!(c.entrypoint, ["dockerd-entrypoint.sh"]);
        assert_eq!(c.cmd, ["bash"]);
        assert_eq!(c.env_var("PATH"), Some("/usr/bin:/bin"));
        assert_eq!(c.env_var("EMPTY"), Some(""));
        assert_eq!(c.env_var("A"), Some("b=c"));
        assert_eq!(c.env_var("BARE"), Some(""));
        assert_eq!(c.working_dir.as_deref(), Some("/src"));
        assert_eq!(c.user.as_deref(), Some("vscode"));
        assert_eq!(
            c.labels.keys().collect::<Vec<_>>(),
            ["a", "devcontainer.metadata"]
        );
    }

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|l| l as _)
        }
    }

    #[test]
    fn an_error_shows_its_causes_once_each() {
        let err = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer(
                    "invalid peer certificate: UnknownIssuer",
                    None,
                ))),
            ))),
        );
        assert_eq!(
            chain(&err),
            "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer"
        );
        let repeats = Layer("registry error: boom", Some(Box::new(Layer("boom", None))));
        assert_eq!(chain(&repeats), "registry error: boom");
    }

    #[test]
    fn puddles_roots_come_after_msbs_own() {
        let roots = ["-----BEGIN CERTIFICATE-----\nA\n".to_owned()];
        assert_eq!(
            with_roots(vec![b"msb".to_vec()], &roots),
            [b"msb".to_vec(), roots[0].as_bytes().to_vec()]
        );
        assert_eq!(with_roots(Vec::new(), &[]), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn missing_and_empty_fields_are_none_or_empty() {
        let c = convert(microsandbox_image::ImageConfig {
            working_dir: Some(String::new()),
            user: Some(String::new()),
            ..Default::default()
        });
        assert!(c.entrypoint.is_empty() && c.cmd.is_empty() && c.env.is_empty());
        assert_eq!(c.working_dir, None);
        assert_eq!(c.user, None);
        assert!(c.labels.is_empty());
    }
}
