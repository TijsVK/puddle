// SPDX-License-Identifier: GPL-3.0-or-later
//! What every sandbox is built from: puddle's boot files, the egress route and the guest's proxy
//! and trust configuration.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use puddle_boot::{BootHook, BootPlan, GitIdentity, with_boot_mounts, write_assets};
use puddle_ca::{CaCertificate, TrustBundle};
use puddle_certs::{CorporateRoots, GuestTrust};
use puddle_compute::{FileMount, ImageConfig, SandboxSpec, VsockRoute};
use puddle_guest_env::{ProxySettings, guest_proxy_config};
use puddle_ipc::IpcRoot;
use puddle_proxy::{Proxy, Route};
use puddle_types::{GuestEnv, ImageRef, MemoryMib, WorkspaceName};

use crate::git_hosts::Authors;
use crate::{GuestSettings, HostError};

/// The guest vsock port the agent connects to; the route of every sandbox listens behind it.
pub(crate) const AGENT_ROUTE_PORT: u32 = 5000;

/// Folder below the guest-share root that holds the files every sandbox mounts.
const ASSET_DIR: &str = "puddle";

/// The pieces shared by every sandbox of this host.
pub(crate) struct BootKit {
    proxy: Arc<Proxy>,
    ipc: IpcRoot,
    hook: BootHook,
    assets: Vec<FileMount>,
    agent: PathBuf,
    roots: CorporateRoots,
    git: Option<GitIdentity>,
}

/// What differs from one sandbox to the next, besides the image: the CA the sandbox's guest
/// trusts, and who commits.
pub(crate) struct GuestInputs<'a> {
    /// This start's CA certificate (public), added to the guest's trust bundle.
    pub(crate) ca: &'a CaCertificate,
    /// The commit authors: the fallback and the rules by remote.
    pub(crate) authors: &'a Authors,
}

impl BootKit {
    /// Writes the boot files and a copy of the agent below `guest_share` (the only place msb
    /// mounts from) and gathers the rest.
    pub(crate) fn new(
        guest_share: &Path,
        guest: &GuestSettings,
        proxy: Arc<Proxy>,
        roots: &CorporateRoots,
    ) -> Result<Self, HostError> {
        let io = |what: &str, e: std::io::Error| HostError::GuestFiles(format!("{what}: {e}"));
        if !guest.agent_binary.is_file() {
            return Err(HostError::AgentMissing {
                path: guest.agent_binary.clone(),
            });
        }
        let dir = guest_share.join(ASSET_DIR);
        let assets = write_assets(&dir).map_err(|e| io("write the boot files", e))?;
        let agent = dir.join("puddle-agent");
        // Copy beside the target and rename over it, so a sandbox booting from the old file
        // never sees half of the new one.
        let partial = dir.join("puddle-agent.partial");
        std::fs::copy(&guest.agent_binary, &partial).map_err(|e| io("copy the agent", e))?;
        std::fs::rename(&partial, &agent).map_err(|e| io("install the agent", e))?;
        let ipc = IpcRoot::new().map_err(|e| HostError::GuestFiles(e.to_string()))?;
        Ok(Self {
            proxy,
            ipc,
            hook: BootHook::new().with_timeout(guest.boot_timeout),
            assets,
            agent,
            roots: roots.clone(),
            git: guest.git_identity.clone(),
        })
    }

    pub(crate) fn hook(&self) -> &BootHook {
        &self.hook
    }

    /// Starts the egress route of `sandbox`: a fresh owner-only endpoint served by the shared
    /// proxy. It lives as long as the returned [`Route`].
    pub(crate) fn route(&self, workspace: &WorkspaceName) -> Result<Route, String> {
        let listener = self.ipc.listen().map_err(|e| e.to_string())?;
        Ok(self.proxy.serve_route(listener, workspace.clone()))
    }

    /// The boot plan and the environment for a sandbox of `image`. The same inputs give the same
    /// plan, so running it again in the running guest changes only what `guest` changed.
    pub(crate) fn plan(
        &self,
        image: &ImageConfig,
        guest: &GuestInputs<'_>,
    ) -> Result<(BootPlan, GuestEnv), String> {
        let proxy =
            guest_proxy_config(&ProxySettings::default(), &image.env).map_err(|e| e.to_string())?;
        let trust = GuestTrust::new(&self.roots, &TrustBundle::new().with(guest.ca.clone()));
        let mut env = proxy.env;
        env.extend(&trust.env());
        let mut builder = BootPlan::builder(image)
            .env(&env)
            .files(proxy.files)
            .files(trust.guest_files());
        if let Some(step) = trust.boot_step() {
            builder = builder.step(step);
        }
        // The first identity's author, else the one the host was configured with.
        if let Some(author) = guest.authors.fallback.as_ref().or(self.git.as_ref()) {
            builder = builder.git_identity(author.clone());
        }
        for rule in &guest.authors.rules {
            builder = builder.git_author_rule(rule.clone());
        }
        let plan = builder.build().map_err(|e| e.to_string())?;
        Ok((plan, env))
    }

    /// The spec of a new sandbox: image, memory, environment, the route and puddle's mounts.
    pub(crate) fn spec(
        &self,
        name: &WorkspaceName,
        image: ImageRef,
        memory: MemoryMib,
        env: &GuestEnv,
        route: &Route,
    ) -> SandboxSpec {
        let spec = SandboxSpec::new(name.sandbox_name(), image)
            .with_memory(memory)
            .with_env(env)
            .with_route(VsockRoute::new(AGENT_ROUTE_PORT, route.endpoint().path()));
        with_boot_mounts(spec, self.assets.clone(), Some(&self.agent))
    }

    pub(crate) fn ipc(&self) -> &IpcRoot {
        &self.ipc
    }
}
