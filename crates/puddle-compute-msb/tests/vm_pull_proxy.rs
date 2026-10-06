// SPDX-License-Identifier: GPL-3.0-or-later
//! T-116 on real registries (T-033 P2/P3, tiers K/W): the adapter pulls `alpine:3.20` from
//! Docker Hub and `mcr.microsoft.com/dotnet/sdk:8.0` through puddle's image-pull proxy (process
//! environment from `PullProxyEnv`, per-run token), then boots the pulled alpine image.
//!
//! The proxy's resolver records every name it resolved, so the test proves each registry (and
//! its token and blob hosts) was reached through the proxy. A fresh msb home makes sure nothing
//! comes from an earlier test's cache. The interception half (an untrusted root refused, a given
//! root trusted) is the I test `puddle-e2e/tests/image_pull_proxy.rs`.
//!
//! One test in its own binary: it sets the process environment before any thread starts.
mod support;

use std::collections::BTreeSet;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use puddle_compute::{ExecRequest, Runtime, Sandbox, SandboxSpec};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_netpolicy::PuddleEndpoints;
use puddle_proxy::{BoxFuture, PullProxy, Resolver, SystemResolver};
use puddle_runtime::PullProxyEnv;
use puddle_types::{DomainName, ImageRef, MemoryMib};

/// The OS resolver, recording each name asked for.
#[derive(Default)]
struct Recording(Mutex<BTreeSet<String>>);

impl Resolver for Recording {
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.as_str().to_owned());
        SystemResolver.resolve(name, port)
    }
}

impl Recording {
    fn names(&self) -> BTreeSet<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[expect(
    unsafe_code,
    reason = "the registry client reads its proxy from the process environment"
)]
#[test]
fn vm_image_pulls_through_the_pull_proxy_from_docker_hub_and_mcr() {
    let settings = support::settings();
    let resolver = Arc::new(Recording::default());
    let endpoints = PuddleEndpoints::new();
    let proxy = PullProxy::bind(&endpoints)
        .unwrap()
        .with_resolver(resolver.clone());
    let env = PullProxyEnv::plan(proxy.proxy_url().expose(), std::env::vars_os());
    // SAFETY: this binary's only test, and no runtime or other thread has started yet.
    unsafe { env.apply_to_process() };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let route = proxy.serve().unwrap();
        let pair = settings.prepare().expect("msb runtime pair");
        let home = settings.scratch_home("pp");
        let _ = std::fs::remove_dir_all(&home);
        let msb = MsbRuntime::open(
            MsbConfig::new(&home, pair.msb, pair.libkrunfw, home.join("guest-share"))
                .with_ssh_key(support::TEST_SSH_KEY),
        )
        .await
        .expect("open msb");

        let alpine = ImageRef::new("alpine:3.20").unwrap();
        let config = msb.pull_image(&alpine).await.expect("pull alpine:3.20");
        assert!(config.env_var("PATH").is_some(), "{config:?}");
        let hub = resolver.names();
        assert!(
            // oci-client names Docker Hub `index.docker.io`; the token and the blob CDN hosts
            // follow from its answers (`production.cloudfront.docker.com` on the first K run).
            (hub.contains("index.docker.io") || hub.contains("registry-1.docker.io"))
                && hub.contains("auth.docker.io"),
            "Docker Hub was not reached through the pull proxy: {hub:?}"
        );

        let sdk = ImageRef::new("mcr.microsoft.com/dotnet/sdk:8.0").unwrap();
        let config = msb.pull_image(&sdk).await.expect("pull dotnet/sdk:8.0");
        assert!(
            config
                .env_var("DOTNET_VERSION")
                .is_some_and(|v| v.starts_with("8.")),
            "{config:?}"
        );
        let all = resolver.names();
        assert!(
            all.contains("mcr.microsoft.com"),
            "MCR was not reached through the pull proxy: {all:?}"
        );

        // The pulled image boots: create finds it in the cache.
        let name = settings.prefix.sandbox_name("pp").unwrap();
        let spec = SandboxSpec::new(name.clone(), alpine).with_memory(MemoryMib::new(512).unwrap());
        let sb = msb
            .create(spec)
            .await
            .expect("create from the pulled image");
        let out = sb
            .exec(ExecRequest::sh("cat /etc/alpine-release").as_user("root"))
            .await
            .expect("exec");
        let _ = sb.stop().await;
        let _ = msb.remove(&name).await;
        assert_eq!(out.status.code, 0, "{}", out.stderr_text());
        assert!(
            out.stdout_text().starts_with("3.20"),
            "{}",
            out.stdout_text()
        );
        assert_eq!(resolver.names(), all, "create pulled nothing new");
        route.shutdown().await;
        drop(msb);
        let _ = std::fs::remove_dir_all(&home);
    });
}
