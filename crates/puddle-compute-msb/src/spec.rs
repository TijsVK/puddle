// SPDX-License-Identifier: GPL-3.0-or-later
//! [`puddle_compute::SandboxSpec`] to the SDK's `SandboxBuilder`, and the list of every SDK option
//! puddle sets or leaves at its default ([`SDK_OPTIONS`], input for the D-27 escape review).

use microsandbox::Sandbox;
use microsandbox::sandbox::{DeploymentProfile, PullPolicy, SandboxBuilder, SecurityProfile};
use puddle_compute::{NetworkPolicy, SandboxSpec};

use crate::{OWNER_LABEL, OWNER_LABEL_VALUE};

/// Whether puddle sets an SDK option, and to what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkSetting {
    /// puddle sets it, to this.
    Set(&'static str),
    /// puddle leaves it; this is the SDK's default (msb 0.7.7).
    Default(&'static str),
}

/// One SDK option and what puddle does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdkOption {
    /// Where the option lives: `SandboxBuilder::<method>`, `MountBuilder::…`, `exec`, `ssh`,
    /// `LocalBackend`, `config.json`.
    pub option: &'static str,
    /// What puddle does.
    pub setting: SdkSetting,
    /// Why.
    pub why: &'static str,
}

const fn set(option: &'static str, value: &'static str, why: &'static str) -> SdkOption {
    SdkOption {
        option,
        setting: SdkSetting::Set(value),
        why,
    }
}

const fn default(option: &'static str, value: &'static str, why: &'static str) -> SdkOption {
    SdkOption {
        option,
        setting: SdkSetting::Default(value),
        why,
    }
}

/// Every `SandboxBuilder` option of SDK 0.7.7 (and the mount, exec, SSH and backend options the
/// adapter touches), with what puddle does. `SandboxBuilder` entries are kept in step with
/// [`builder`] by a unit test: every method it calls is listed as [`SdkSetting::Set`] and
/// nothing else is.
pub const SDK_OPTIONS: &[SdkOption] = &[
    // SandboxBuilder: set
    set(
        "SandboxBuilder::image",
        "spec image (OCI reference)",
        "the workspace image",
    ),
    set(
        "SandboxBuilder::memory",
        "spec memory (MiB, default 8 GiB)",
        "the memory setting, applied at create; changes apply at the next start via modify().memory().next_start()",
    ),
    set(
        "SandboxBuilder::cpus",
        "spec cpus, only when given",
        "otherwise msb's default (1 vCPU)",
    ),
    set(
        "SandboxBuilder::env",
        "spec env (proxy vars, git identity, ...)",
        "reaches exec, SSH and the boot hook",
    ),
    set(
        "SandboxBuilder::label",
        "dev.puddle.owner=puddle",
        "reconcile touches only puddle's sandboxes (T-113)",
    ),
    set(
        "SandboxBuilder::disable_network",
        "no network device; policy none",
        "D-1: the guest's only way out is the vsock route (HG-01)",
    ),
    set(
        "SandboxBuilder::vsock",
        "one stream route per spec route (port -> named pipe / Unix socket)",
        "only routed ports reach the host (HG-02)",
    ),
    set(
        "SandboxBuilder::volume",
        "file mounts: bind + readonly; named volumes: named / named_with(ensure_exists, disk, size); owned disks: owned_with(disk, size)",
        "read-only mounts only (HO-6); sources under the guest-share root (C-7)",
    ),
    set(
        "SandboxBuilder::security",
        "SecurityProfile::Default (guest root keeps CAP_SYS_ADMIN, no no_new_privs)",
        "root in the VM is intended; Restricted breaks sudo and Docker-in-Docker",
    ),
    set(
        "SandboxBuilder::deployment_profile",
        "DeploymentProfile::SingleTenant",
        "one user's laptop; MultiTenant is for shared hosting",
    ),
    set(
        "SandboxBuilder::pull_policy",
        "PullPolicy::IfMissing",
        "the image was pulled just before by pull_image",
    ),
    set(
        "SandboxBuilder::ephemeral",
        "false",
        "the root disk survives stop/start; removal is explicit",
    ),
    // SandboxBuilder: left at the default
    default(
        "SandboxBuilder::max_memory",
        "unset: the SDK makes it equal to memory (no hotplug reserve)",
        "never above memory (T-106 bar); set_memory pins it to the new size via modify(); VM test checks the stored config",
    ),
    default("SandboxBuilder::max_cpus", "unset", "no CPU hotplug"),
    default(
        "SandboxBuilder::cpu_placement / placement_profile",
        "unset",
        "no pinning on a laptop",
    ),
    default(
        "SandboxBuilder::root_disk / root_disk_with / oci_upper_size",
        "msb default writable upper",
        "ADR 0006: workspace data lives on the named volume",
    ),
    default("SandboxBuilder::thp", "Madvise", "msb default"),
    default(
        "SandboxBuilder::guest_clock",
        "Sync",
        "guest clock follows the host",
    ),
    default(
        "SandboxBuilder::log_level / quiet_logs",
        "global default",
        "msb logs under the private home",
    ),
    default(
        "SandboxBuilder::detached",
        "false",
        "VMs die with puddle (D-20 A, T-028 L2)",
    ),
    default(
        "SandboxBuilder::disable_metrics_sample / metrics_sample_interval",
        "msb default sampling",
        "not used yet",
    ),
    default(
        "SandboxBuilder::workdir",
        "image WORKDIR",
        "the boot hook and exec choose their own",
    ),
    default(
        "SandboxBuilder::shell",
        "/bin/sh",
        "the boot hook needs a POSIX sh",
    ),
    default(
        "SandboxBuilder::registry",
        "anonymous, system roots",
        "the adapter pulls first (pull_image), so create finds the image cached",
    ),
    set(
        "RegistryBuilder::extra_ca_certs (pull_image)",
        "msb's configured roots + MsbConfig::registry_roots",
        "corporate roots, so pulls work behind a TLS-intercepting proxy (T-116)",
    ),
    set(
        "registry client proxy (process env HTTPS_PROXY / HTTP_PROXY / NO_PROXY)",
        "puddle's image-pull proxy with a per-run token (puddle_runtime::PullProxyEnv)",
        "pulls take puddle's way out; msb has no proxy setting of its own (T-116)",
    ),
    default("SandboxBuilder::slug", "unset", "cloud only"),
    default(
        "SandboxBuilder::replace / replace_with_timeout",
        "off",
        "a taken name is refused (AlreadyExists), never replaced",
    ),
    default(
        "SandboxBuilder::entrypoint / cmd",
        "image's, not run",
        "SDK create/start run no image workload (T-028); the boot hook chains the ENTRYPOINT",
    ),
    default(
        "SandboxBuilder::foreground_command / background_command",
        "unset",
        "no workload at create",
    ),
    default(
        "SandboxBuilder::init / init_with",
        "msb's init",
        "T-028 rejected the init handoff (race, stop hang)",
    ),
    default("SandboxBuilder::hostname", "msb default", "not used yet"),
    default(
        "SandboxBuilder::user",
        "image USER",
        "puddle runs its exec calls as root explicitly",
    ),
    default(
        "SandboxBuilder::network / proxy / prepend_network_policy_rules",
        "unset (network disabled)",
        "puddle's own proxy is the chokepoint (D-1)",
    ),
    default(
        "SandboxBuilder::port / port_bind / port_udp / port_udp_bind",
        "none",
        "no published ports; forwards go through puddle (W5)",
    ),
    default(
        "SandboxBuilder::vsock_dgram / vsock_route",
        "none",
        "stream routes only",
    ),
    default(
        "SandboxBuilder::secret / secret_entry / secret_env / secret_violation_action",
        "none",
        "credentials are injected by puddle's proxy (W2)",
    ),
    default(
        "SandboxBuilder::envs / labels",
        "unset",
        "env and label are set one by one",
    ),
    default(
        "SandboxBuilder::rlimit / rlimit_range",
        "msb defaults",
        "not used yet",
    ),
    default(
        "SandboxBuilder::script / scripts / config_scripts",
        "none",
        "the boot hook is a mounted file",
    ),
    default(
        "SandboxBuilder::max_duration / idle_timeout",
        "none",
        "sandboxes live until stopped",
    ),
    default(
        "SandboxBuilder::patch / add_patch",
        "none",
        "guest files are written by the boot hook",
    ),
    default(
        "SandboxBuilder::overlay / from_spec_json / override_image / override_snapshot / snapshot_resolved",
        "unset",
        "no snapshots or overlays",
    ),
    default(
        "SandboxBuilder::image_with / add_volume_mount",
        "unset",
        "plain image reference; mounts via volume()",
    ),
    default(
        "MountBuilder::noexec / nosuid / nodev",
        "off",
        "the agent binary runs from its mount; root in the guest anyway",
    ),
    default(
        "MountBuilder::stat_virtualization / host_permissions / owner",
        "Strict / Private / none",
        "msb defaults for virtiofs",
    ),
    default(
        "MountBuilder::follow_root_symlinks",
        "false",
        "a planted symlink can't redirect a mount; sources are also resolved by puddle (C-7)",
    ),
    // exec, SSH, backend, config.json
    set(
        "exec",
        "args, env, cwd, user, stdin bytes, timeout from ExecRequest; tty off",
        "one call per ExecRequest",
    ),
    set(
        "ssh::server_with",
        "authorized keys from MsbConfig; inactivity timeout off unless configured",
        "IDE sessions sit idle (T-114)",
    ),
    default(
        "ssh::host_key",
        "per-sandbox ed25519 key under the sandbox directory, created on first use",
        "msb default",
    ),
    default(
        "ssh::sftp / user",
        "sftp on; guest user msb default",
        "scp/sftp for the IDE (T-114)",
    ),
    set(
        "LocalBackend::home / config_path",
        "puddle's private msb home and its config.json",
        "never the user's ~/.microsandbox (D-19)",
    ),
    default(
        "LocalBackend::default_cpus / default_memory_mib / ca_certs / registry_hosts / ssh_inactivity_timeout_secs / deployment_profile",
        "msb defaults",
        "every sandbox sets what it needs",
    ),
    set(
        "config.json",
        "version 1 + paths.msb + paths.libkrunfw only",
        "no other global defaults can creep in",
    ),
];

/// The SDK builder for `spec`: every option puddle sets, nothing else (see [`SDK_OPTIONS`]).
/// File mount sources must already have passed [`crate::MsbConfig::check_mount_source`].
#[must_use]
pub fn builder(spec: &SandboxSpec) -> SandboxBuilder {
    let mut b = Sandbox::builder(spec.name.as_str())
        .image(spec.image.as_str())
        .memory(spec.memory.get())
        .label(OWNER_LABEL, OWNER_LABEL_VALUE)
        .security(SecurityProfile::Default)
        .deployment_profile(DeploymentProfile::SingleTenant)
        .pull_policy(PullPolicy::IfMissing)
        .ephemeral(false);
    if let Some(cpus) = spec.cpus {
        b = b.cpus(cpus);
    }
    for (name, value) in spec.env.iter() {
        b = b.env(name, value);
    }
    // `NetworkPolicy::None` is the only policy; a variant added later stays disabled here
    // (fail closed) until it is mapped on purpose.
    debug_assert_eq!(spec.network, NetworkPolicy::None);
    b = b.disable_network();
    for route in &spec.routes {
        b = b.vsock(&route.host, route.guest_port);
    }
    for mount in &spec.file_mounts {
        b = b.volume(mount.guest.as_str(), |m| m.bind(&mount.host).readonly());
    }
    for mount in &spec.volumes {
        let volume = mount.volume.as_str();
        b = b.volume(mount.guest.as_str(), |m| match mount.ensure_size {
            None => m.named(volume),
            Some(size) => m.named_with(volume, |v| v.ensure_exists().disk().size(size.as_mib())),
        });
    }
    for disk in &spec.owned_disks {
        b = b.volume(disk.guest.as_str(), |m| {
            m.owned_with(|v| v.disk().size(disk.size.as_mib()))
        });
    }
    b
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The `SandboxBuilder` methods [`builder`] calls, read from this file's source.
    fn methods_called_by_builder() -> BTreeSet<String> {
        let source = include_str!("spec.rs");
        let start = source.find("pub fn builder(").unwrap();
        let body = &source[start..];
        let end = body.find("\n}\n").unwrap();
        let body = &body[..end];
        let mut called = BTreeSet::new();
        for (i, _) in body.match_indices('.') {
            let rest = &body[i + 1..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() && rest[name.len()..].starts_with('(') {
                called.insert(name);
            }
        }
        // Calls on puddle's own types and on the nested mount/volume builders.
        for ours in [
            "get",
            "as_str",
            "iter",
            "as_mib",
            "bind",
            "readonly",
            "named",
            "named_with",
            "ensure_exists",
            "disk",
            "size",
            "owned_with",
        ] {
            called.remove(ours);
        }
        called
    }

    fn listed(setting: fn(&SdkSetting) -> bool) -> BTreeSet<String> {
        SDK_OPTIONS
            .iter()
            .filter(|o| setting(&o.setting))
            .filter_map(|o| o.option.strip_prefix("SandboxBuilder::"))
            .flat_map(|names| names.split(" / ").map(str::to_owned))
            .collect()
    }

    #[test]
    fn the_option_list_matches_what_the_builder_sets() {
        let called = methods_called_by_builder();
        let set = listed(|s| matches!(s, SdkSetting::Set(_)));
        assert_eq!(
            called, set,
            "SDK_OPTIONS `Set` entries differ from builder()"
        );
        let defaulted = listed(|s| matches!(s, SdkSetting::Default(_)));
        assert!(
            set.is_disjoint(&defaulted),
            "an option is both set and default"
        );
    }

    #[test]
    fn max_memory_is_only_ever_pinned_to_the_memory_size() {
        // Creation never sets it (the SDK then makes it equal to memory); the only call is in
        // set_memory, with the same value as memory.
        let spec_source = include_str!("spec.rs");
        let builder_fn = &spec_source[spec_source.find("pub fn builder(").unwrap()..];
        assert!(!builder_fn[..builder_fn.find("\n}\n").unwrap()].contains("max_memory"));
        let call = format!(".{}(", "max_memory");
        for (file, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("config.rs", include_str!("config.rs")),
            ("error.rs", include_str!("error.rs")),
            ("image.rs", include_str!("image.rs")),
            ("sandbox.rs", include_str!("sandbox.rs")),
            ("volume.rs", include_str!("volume.rs")),
        ] {
            assert!(!source.contains(&call), "{file} sets max-memory");
        }
        let runtime = include_str!("runtime.rs");
        assert_eq!(runtime.matches(&call).count(), 1);
        assert!(runtime.contains(&format!(".memory(mib){call}mib)")));
    }

    #[test]
    fn every_option_says_why() {
        let mut seen = BTreeSet::new();
        for o in SDK_OPTIONS {
            assert!(!o.why.is_empty(), "{}", o.option);
            assert!(seen.insert(o.option), "{} listed twice", o.option);
            match o.setting {
                SdkSetting::Set(v) | SdkSetting::Default(v) => assert_ne!(v, ""),
            }
        }
    }
}
