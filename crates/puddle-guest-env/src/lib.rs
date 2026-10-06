// SPDX-License-Identifier: GPL-3.0-or-later
//! Boot-time proxy config for the guest (T-030 §4, T-109).
//!
//! Every tool in the guest reaches the network through the agent's proxy listener. Most tools
//! follow `HTTP(S)_PROXY`; the rest need their own variable or config file. This crate is a pure
//! function, [`guest_proxy_config`], from [`ProxySettings`] (and the image's `ENV`) to a
//! [`GuestEnv`](puddle_types::GuestEnv) and a list of [`GuestFile`](puddle_types::GuestFile)s.
//! The boot hook (`puddle-boot`) applies them like any provider's; the caller also puts the env
//! into the sandbox spec, so exec and SSH sessions get it without a login shell.
//!
//! | Tool | Delivery |
//! |---|---|
//! | curl, wget, git, pip, npm, pnpm, Yarn 1, Go, Python, Ruby, dockerd | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, each also in lower case |
//! | Node ≥ 22.21 `fetch`/`http` | `NODE_USE_ENV_PROXY=1` |
//! | Yarn Berry | `YARN_HTTP_PROXY`, `YARN_HTTPS_PROXY` |
//! | Electron downloads | `ELECTRON_GET_USE_PROXY`, `GLOBAL_AGENT_*` |
//! | Java (every JVM) | `JAVA_TOOL_OPTIONS` (appended to the image's) |
//! | Gradle | `JAVA_TOOL_OPTIONS`, plus an init script in the Gradle user home |
//! | Maven ≥ 3.9 | `MAVEN_ARGS=-gs <file>` (appended to the image's) and that settings file |
//! | Cargo git dependencies | `CARGO_NET_GIT_FETCH_WITH_CLI=true` |
//! | apt | `/etc/apt/apt.conf.d/99puddle-proxy` |
//! | sudo | `/etc/sudoers.d/puddle-proxy`: `env_keep` for every variable above |
//! | containers (Docker CLI) | `~/.docker/config.json` `proxies.default`, at the bridge gateway, merged |
//!
//! Every file is one puddle owns outright, except the Docker CLI config, where puddle owns only
//! `proxies.default` and the boot hook merges it in (`docker login`'s `auths` survive a restart,
//! T-097). No other user file is touched (Maven's goes in through `-gs`, Gradle's is an init
//! script next to the user's).

#![forbid(unsafe_code)]

mod error;
mod render;
mod settings;

pub use error::ConfigError;
pub use render::{
    APT_CONF_GUEST, GRADLE_INIT_RELATIVE, GuestProxyConfig, MAVEN_SETTINGS_GUEST, SUDOERS_GUEST,
    guest_proxy_config,
};
pub use settings::{
    DEFAULT_CONTAINER_PROXY, DEFAULT_HOME, DEFAULT_PROXY, NoProxyEntry, ProxySettings,
};
