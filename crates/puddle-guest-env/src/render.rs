// SPDX-License-Identifier: GPL-3.0-or-later
//! Settings in, [`GuestEnv`] and [`GuestFile`]s out.

use std::fmt::Write as _;
use std::net::SocketAddr;

use puddle_types::{GuestEnv, GuestFile, GuestPath, MergeEntry, MergeFormat, MergeSpec};

use crate::settings::{java_ip, loopback_entries};
use crate::{ConfigError, NoProxyEntry, ProxySettings};

/// apt's proxy drop-in (T-030 §4, S7). apt ignores `*_proxy` under `sudo` and in its `_apt`
/// sandbox, so it gets its own file.
pub const APT_CONF_GUEST: &str = "/etc/apt/apt.conf.d/99puddle-proxy";

/// Keeps the proxy variables under `sudo` (whose `env_reset` drops them). Mode 0440, as sudo
/// requires.
pub const SUDOERS_GUEST: &str = "/etc/sudoers.d/puddle-proxy";

/// Maven settings with the proxy, passed as Maven's global settings through `MAVEN_ARGS`, so the
/// user's own `~/.m2/settings.xml` stays untouched and still applies on top.
pub const MAVEN_SETTINGS_GUEST: &str = "/etc/puddle/maven/settings.xml";

/// Gradle init script below the Gradle user home; sets the proxy system properties in every
/// build, so Gradle keeps the proxy when a tool clears `JAVA_TOOL_OPTIONS`.
pub const GRADLE_INIT_RELATIVE: &str = "init.d/puddle-proxy.gradle";

const SUDOERS_MODE: u32 = 0o440;

/// Mode of a Docker CLI config puddle creates: `docker login` stores credentials in it later.
const DOCKER_CONFIG_MODE: u32 = 0o600;

/// Header of every generated file (the boot hook rewrites them at every boot).
const GENERATED: &str = "Written by puddle at every boot; changes here are overwritten.";

/// Java's own `http.nonProxyHosts` default, repeated because setting the property replaces it.
const JDK_NON_PROXY_DEFAULTS: [&str; 5] = ["localhost", "127.*", "[::1]", "0.0.0.0", "[::0]"];

/// What the boot hook applies: the env (also given to the sandbox spec for the exec/SSH path)
/// and the files, in a fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProxyConfig {
    /// Proxy variables for every process in the guest.
    pub env: GuestEnv,
    /// Tool config files.
    pub files: Vec<GuestFile>,
}

/// Builds the guest's proxy config from `settings` and the image's `ENV` (as
/// `ImageConfig::env`: `(name, value)` in image order, the last one wins).
///
/// The image env matters for three things: `JAVA_TOOL_OPTIONS` and `MAVEN_ARGS` keep the image's
/// value with puddle's appended, and `GRADLE_USER_HOME` / `DOCKER_CONFIG` move the per-user
/// files. The image's own `*_PROXY` values are replaced: the agent is the guest's only route out.
///
/// ```
/// use puddle_guest_env::{ProxySettings, guest_proxy_config};
/// let config = guest_proxy_config(&ProxySettings::default(), &[]).unwrap();
/// assert_eq!(config.env.get("https_proxy"), Some("http://127.0.0.1:3128"));
/// assert_eq!(config.env.get("NO_PROXY"), Some("localhost,127.0.0.1,::1,172.17.0.1"));
/// assert!(config.files.iter().any(|f| f.path().as_str() == "/etc/apt/apt.conf.d/99puddle-proxy"));
/// ```
///
/// # Errors
///
/// [`ConfigError::ImageEnv`] when an image value that is passed on can't be an env value;
/// [`ConfigError::GuestPath`] when a per-user path built from `settings.home` is too long.
pub fn guest_proxy_config(
    settings: &ProxySettings,
    image_env: &[(String, String)],
) -> Result<GuestProxyConfig, ConfigError> {
    let image = |name: &str| {
        image_env
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let proxy_url = url(settings.proxy);
    let bypass = bypass_entries(settings);
    let no_proxy = join(bypass.iter().map(NoProxyEntry::as_str), ",");
    let java_bypass = java_non_proxy_hosts(settings);

    let mut env = Vars::default();
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.set(name, &proxy_url);
    }
    env.set("NO_PROXY", &no_proxy);
    env.set("no_proxy", &no_proxy);
    // Node >= 22.21 / 24: built-in fetch and http(s) read the variables above (T-030, verified).
    env.set("NODE_USE_ENV_PROXY", "1");
    // Yarn Berry reads only its own variables.
    env.set("YARN_HTTP_PROXY", &proxy_url);
    env.set("YARN_HTTPS_PROXY", &proxy_url);
    // Electron's downloader (@electron/get) through global-agent.
    env.set("ELECTRON_GET_USE_PROXY", "1");
    env.set("GLOBAL_AGENT_HTTP_PROXY", &proxy_url);
    env.set("GLOBAL_AGENT_HTTPS_PROXY", &proxy_url);
    env.set("GLOBAL_AGENT_NO_PROXY", &no_proxy);
    // Java ignores *_proxy; every JVM reads this (Gradle, Maven's JVM, IDE servers).
    let java = format!(
        "-Dhttp.proxyHost={host} -Dhttp.proxyPort={port} -Dhttps.proxyHost={host} \
         -Dhttps.proxyPort={port} -Dhttp.nonProxyHosts={java_bypass}",
        host = java_ip(settings.proxy.ip()),
        port = settings.proxy.port(),
    );
    env.set(
        "JAVA_TOOL_OPTIONS",
        &appended(image("JAVA_TOOL_OPTIONS"), &java),
    );
    // Maven >= 3.9 reads MAVEN_ARGS; the settings file holds the <proxy> entries.
    env.set(
        "MAVEN_ARGS",
        &appended(image("MAVEN_ARGS"), &format!("-gs {MAVEN_SETTINGS_GUEST}")),
    );
    // Cargo fetches git dependencies with the git CLI, which follows the variables and, later,
    // ssh_config's ProxyCommand (T-021).
    env.set("CARGO_NET_GIT_FETCH_WITH_CLI", "true");
    let env = env.finish()?;

    let gradle_home = image_dir(image("GRADLE_USER_HOME"))
        .map_or_else(|| format!("{}/.gradle", home(settings)), str::to_owned);
    let mut files = vec![
        file(APT_CONF_GUEST, apt_conf(&proxy_url, &bypass))?,
        file(SUDOERS_GUEST, sudoers(&env))?
            .with_mode(SUDOERS_MODE)
            .map_err(|e| path_error(&e))?,
        file(
            MAVEN_SETTINGS_GUEST,
            maven_settings(settings.proxy, &java_bypass),
        )?,
        file(
            &format!("{gradle_home}/{GRADLE_INIT_RELATIVE}"),
            gradle_init(settings.proxy, &java_bypass),
        )?,
    ];
    if let Some(container) = settings.container_proxy {
        let docker_dir = image_dir(image("DOCKER_CONFIG"))
            .map_or_else(|| format!("{}/.docker", home(settings)), str::to_owned);
        let path =
            GuestPath::new(&format!("{docker_dir}/config.json")).map_err(|e| path_error(&e))?;
        files.push(
            GuestFile::merged(path, docker_cli_config(container, &no_proxy)?)
                .with_mode(DOCKER_CONFIG_MODE)
                .map_err(|e| path_error(&e))?,
        );
    }
    Ok(GuestProxyConfig { env, files })
}

/// The settings' home without a trailing `/` (only `/` itself has one).
fn home(settings: &ProxySettings) -> &str {
    settings.home.as_str().trim_end_matches('/')
}

/// An absolute, normalised directory from the image env, or `None` to use the default.
fn image_dir(value: Option<&str>) -> Option<&str> {
    value.filter(|v| *v != "/" && GuestPath::new(v).is_ok())
}

fn url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// Loopback, the container gateway (the guest itself, seen from a container), then the user's.
fn bypass_entries(settings: &ProxySettings) -> Vec<NoProxyEntry> {
    let mut all: Vec<NoProxyEntry> = loopback_entries().into();
    if let Some(c) = settings.container_proxy {
        all.push(NoProxyEntry::ip(c.ip()));
    }
    for e in &settings.no_proxy {
        if !all.contains(e) {
            all.push(e.clone());
        }
    }
    all
}

fn java_non_proxy_hosts(settings: &ProxySettings) -> String {
    let mut all: Vec<String> = JDK_NON_PROXY_DEFAULTS.map(str::to_owned).into();
    let extra = settings
        .container_proxy
        .map(|c| NoProxyEntry::ip(c.ip()))
        .into_iter()
        .chain(settings.no_proxy.iter().cloned());
    for p in extra.flat_map(|e| e.java_patterns()) {
        if !all.contains(&p) {
            all.push(p);
        }
    }
    all.join("|")
}

fn join(items: impl Iterator<Item = String>, sep: &str) -> String {
    items.collect::<Vec<_>>().join(sep)
}

/// `ours` after the image's value, unless the image's value already carries it.
fn appended(image: Option<&str>, ours: &str) -> String {
    match image.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if v.contains(ours) => v.to_owned(),
        Some(v) => format!("{v} {ours}"),
        None => ours.to_owned(),
    }
}

fn file(path: &str, contents: String) -> Result<GuestFile, ConfigError> {
    let path = GuestPath::new(path).map_err(|e| path_error(&e))?;
    Ok(GuestFile::new(path, contents.into_bytes()))
}

fn path_error(e: &puddle_types::ValidationError) -> ConfigError {
    ConfigError::GuestPath {
        reason: e.to_string(),
    }
}

/// Env under construction; the first invalid value is reported by [`Vars::finish`].
#[derive(Default)]
struct Vars {
    env: GuestEnv,
    error: Option<ConfigError>,
}

impl Vars {
    fn set(&mut self, name: &str, value: &str) {
        if let Err(e) = self.env.set(name, value)
            && self.error.is_none()
        {
            self.error = Some(ConfigError::ImageEnv {
                name: name.to_owned(),
                reason: e.reason().to_owned(),
            });
        }
    }

    fn finish(self) -> Result<GuestEnv, ConfigError> {
        self.error.map_or(Ok(self.env), Err)
    }
}

fn apt_conf(proxy_url: &str, bypass: &[NoProxyEntry]) -> String {
    let mut out = format!(
        "// {GENERATED}\n\
         // apt's downloads go through puddle's proxy, whatever environment apt starts with.\n\
         Acquire::http::Proxy \"{proxy_url}\";\n\
         Acquire::https::Proxy \"{proxy_url}\";\n"
    );
    for host in bypass.iter().filter_map(NoProxyEntry::apt_host) {
        // Writing to a String can't fail.
        let _ = write!(
            out,
            "Acquire::http::Proxy::{host} \"DIRECT\";\nAcquire::https::Proxy::{host} \"DIRECT\";\n"
        );
    }
    out
}

fn sudoers(env: &GuestEnv) -> String {
    let names = join(env.iter().map(|(k, _)| k.to_owned()), " ");
    format!(
        "# {GENERATED}\n# Keeps puddle's proxy variables under sudo.\nDefaults env_keep += \"{names}\"\n"
    )
}

fn maven_settings(proxy: SocketAddr, java_bypass: &str) -> String {
    let host = proxy.ip();
    let port = proxy.port();
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- {GENERATED}\n     \
         Maven's global settings through MAVEN_ARGS (-gs); ~/.m2/settings.xml still applies on top. -->\n\
         <settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\"\n          \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n          \
         xsi:schemaLocation=\"http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd\">\n  \
         <proxies>\n"
    );
    for protocol in ["http", "https"] {
        // Writing to a String can't fail.
        let _ = write!(
            out,
            "    <proxy>\n      \
             <id>puddle-{protocol}</id>\n      \
             <active>true</active>\n      \
             <protocol>{protocol}</protocol>\n      \
             <host>{host}</host>\n      \
             <port>{port}</port>\n      \
             <nonProxyHosts>{java_bypass}</nonProxyHosts>\n    \
             </proxy>\n"
        );
    }
    out.push_str("  </proxies>\n</settings>\n");
    out
}

fn gradle_init(proxy: SocketAddr, java_bypass: &str) -> String {
    let host = java_ip(proxy.ip());
    let port = proxy.port();
    format!(
        "// {GENERATED}\n\
         // Gradle keeps puddle's proxy even when JAVA_TOOL_OPTIONS is cleared.\n\
         [\n    \
         'http.proxyHost': '{host}',\n    \
         'http.proxyPort': '{port}',\n    \
         'https.proxyHost': '{host}',\n    \
         'https.proxyPort': '{port}',\n    \
         'http.nonProxyHosts': '{java_bypass}',\n    \
         'https.nonProxyHosts': '{java_bypass}'\n\
         ].each {{ key, value -> System.setProperty(key, value) }}\n"
    )
}

/// The Docker CLI passes these to every container and build it starts. Containers reach the
/// guest's proxy at the bridge gateway, not at loopback; the bypass list is the guest's.
///
/// The file is the user's (`docker login` keeps `auths` and `credHelpers` in it), so puddle owns
/// only `proxies.default` and merges it in (T-097); other daemons' `proxies` entries stay too.
fn docker_cli_config(container: SocketAddr, no_proxy: &str) -> Result<MergeSpec, ConfigError> {
    let proxy = url(container);
    let default = serde_json::json!({
        "httpProxy": proxy,
        "httpsProxy": proxy,
        "noProxy": no_proxy,
    });
    MergeSpec::new(
        MergeFormat::Json,
        vec![MergeEntry::json(&["proxies", "default"], &default)],
    )
    .map_err(|e| path_error(&e))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;

    const PROXY: &str = "http://127.0.0.1:3128";
    const BYPASS: &str = "localhost,127.0.0.1,::1,172.17.0.1";
    const JAVA_BYPASS: &str = "localhost|127.*|[::1]|0.0.0.0|[::0]|172.17.0.1";

    fn default_config() -> GuestProxyConfig {
        guest_proxy_config(&ProxySettings::default(), &[]).unwrap()
    }

    fn file_at<'a>(config: &'a GuestProxyConfig, path: &str) -> &'a GuestFile {
        config
            .files
            .iter()
            .find(|f| f.path().as_str() == path)
            .unwrap_or_else(|| panic!("no file at {path}"))
    }

    fn text(f: &GuestFile) -> &str {
        std::str::from_utf8(f.contents()).unwrap()
    }

    fn image(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn env_snapshot() {
        let config = default_config();
        let env: Vec<(&str, &str)> = config.env.iter().collect();
        let java = format!(
            "-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=3128 -Dhttps.proxyHost=127.0.0.1 \
             -Dhttps.proxyPort=3128 -Dhttp.nonProxyHosts={JAVA_BYPASS}"
        );
        let expected = vec![
            ("CARGO_NET_GIT_FETCH_WITH_CLI", "true"),
            ("ELECTRON_GET_USE_PROXY", "1"),
            ("GLOBAL_AGENT_HTTPS_PROXY", PROXY),
            ("GLOBAL_AGENT_HTTP_PROXY", PROXY),
            ("GLOBAL_AGENT_NO_PROXY", BYPASS),
            ("HTTPS_PROXY", PROXY),
            ("HTTP_PROXY", PROXY),
            ("JAVA_TOOL_OPTIONS", java.as_str()),
            ("MAVEN_ARGS", "-gs /etc/puddle/maven/settings.xml"),
            ("NODE_USE_ENV_PROXY", "1"),
            ("NO_PROXY", BYPASS),
            ("YARN_HTTPS_PROXY", PROXY),
            ("YARN_HTTP_PROXY", PROXY),
            ("http_proxy", PROXY),
            ("https_proxy", PROXY),
            ("no_proxy", BYPASS),
        ];
        assert_eq!(env, expected);
    }

    #[test]
    fn files_come_in_a_fixed_order_with_their_modes() {
        let c = default_config();
        let files: Vec<(&str, u32)> = c
            .files
            .iter()
            .map(|f| (f.path().as_str(), f.mode()))
            .collect();
        assert_eq!(
            files,
            [
                (APT_CONF_GUEST, 0o644),
                (SUDOERS_GUEST, 0o440),
                (MAVEN_SETTINGS_GUEST, 0o644),
                ("/root/.gradle/init.d/puddle-proxy.gradle", 0o644),
                ("/root/.docker/config.json", 0o600),
            ]
        );
    }

    #[test]
    fn apt_snapshot() {
        let c = default_config();
        assert_eq!(
            text(file_at(&c, APT_CONF_GUEST)),
            "\
// Written by puddle at every boot; changes here are overwritten.
// apt's downloads go through puddle's proxy, whatever environment apt starts with.
Acquire::http::Proxy \"http://127.0.0.1:3128\";
Acquire::https::Proxy \"http://127.0.0.1:3128\";
Acquire::http::Proxy::localhost \"DIRECT\";
Acquire::https::Proxy::localhost \"DIRECT\";
Acquire::http::Proxy::127.0.0.1 \"DIRECT\";
Acquire::https::Proxy::127.0.0.1 \"DIRECT\";
Acquire::http::Proxy::172.17.0.1 \"DIRECT\";
Acquire::https::Proxy::172.17.0.1 \"DIRECT\";
"
        );
    }

    #[test]
    fn sudoers_snapshot() {
        let c = default_config();
        assert_eq!(
            text(file_at(&c, SUDOERS_GUEST)),
            "\
# Written by puddle at every boot; changes here are overwritten.
# Keeps puddle's proxy variables under sudo.
Defaults env_keep += \"CARGO_NET_GIT_FETCH_WITH_CLI ELECTRON_GET_USE_PROXY \
GLOBAL_AGENT_HTTPS_PROXY GLOBAL_AGENT_HTTP_PROXY GLOBAL_AGENT_NO_PROXY HTTPS_PROXY HTTP_PROXY \
JAVA_TOOL_OPTIONS MAVEN_ARGS NODE_USE_ENV_PROXY NO_PROXY YARN_HTTPS_PROXY YARN_HTTP_PROXY \
http_proxy https_proxy no_proxy\"
"
        );
    }

    #[test]
    fn sudo_keeps_every_variable_puddle_sets() {
        let c = default_config();
        let sudoers = text(file_at(&c, SUDOERS_GUEST));
        let kept = sudoers
            .lines()
            .find_map(|l| l.strip_prefix("Defaults env_keep += \""))
            .unwrap()
            .trim_end_matches('"');
        let kept: Vec<&str> = kept.split(' ').collect();
        let set: Vec<&str> = c.env.iter().map(|(k, _)| k).collect();
        assert_eq!(kept, set);
    }

    #[test]
    fn maven_snapshot() {
        let c = default_config();
        let proxy = |protocol: &str| {
            format!(
                "    <proxy>
      <id>puddle-{protocol}</id>
      <active>true</active>
      <protocol>{protocol}</protocol>
      <host>127.0.0.1</host>
      <port>3128</port>
      <nonProxyHosts>{JAVA_BYPASS}</nonProxyHosts>
    </proxy>
"
            )
        };
        let expected = format!(
            "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!-- Written by puddle at every boot; changes here are overwritten.
     Maven's global settings through MAVEN_ARGS (-gs); ~/.m2/settings.xml still applies on top. -->
<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\"
          xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
          xsi:schemaLocation=\"http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd\">
  <proxies>
{}{}  </proxies>
</settings>
",
            proxy("http"),
            proxy("https")
        );
        assert_eq!(text(file_at(&c, MAVEN_SETTINGS_GUEST)), expected);
    }

    #[test]
    fn gradle_snapshot() {
        let c = default_config();
        assert_eq!(
            text(file_at(&c, "/root/.gradle/init.d/puddle-proxy.gradle")),
            format!(
                "\
// Written by puddle at every boot; changes here are overwritten.
// Gradle keeps puddle's proxy even when JAVA_TOOL_OPTIONS is cleared.
[
    'http.proxyHost': '127.0.0.1',
    'http.proxyPort': '3128',
    'https.proxyHost': '127.0.0.1',
    'https.proxyPort': '3128',
    'http.nonProxyHosts': '{JAVA_BYPASS}',
    'https.nonProxyHosts': '{JAVA_BYPASS}'
].each {{ key, value -> System.setProperty(key, value) }}
"
            )
        );
    }

    #[test]
    fn docker_cli_snapshot() {
        let c = default_config();
        assert_eq!(
            text(file_at(&c, "/root/.docker/config.json")),
            "\
{
\t\"proxies\": {
\t\t\"default\": {
\t\t\t\"httpProxy\": \"http://172.17.0.1:3128\",
\t\t\t\"httpsProxy\": \"http://172.17.0.1:3128\",
\t\t\t\"noProxy\": \"localhost,127.0.0.1,::1,172.17.0.1\"
\t\t}
\t}
}
"
        );
    }

    #[test]
    fn docker_cli_config_is_merged_so_a_docker_login_survives() {
        let c = default_config();
        let f = file_at(&c, "/root/.docker/config.json");
        let puddle_types::ApplyKind::Merge(spec) = f.apply() else {
            panic!("the Docker CLI config must be merged, not replaced")
        };
        assert_eq!(
            spec.keys(),
            [vec!["proxies".to_owned(), "default".to_owned()]]
        );
        let login = "{\n\t\"auths\": {\n\t\t\"registry.example.test\": {\n\t\t\t\"auth\": \"dTpw\"\n\t\t}\n\t}\n}\n";
        let puddle_types::Merged::Write(out) = spec.apply(Some(login.as_bytes()), &[]).unwrap()
        else {
            panic!("nothing merged")
        };
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("{\n\t\"auths\": {\n\t\t\"registry.example.test\": {\n\t\t\t\"auth\": \"dTpw\"\n\t\t}\n\t},\n\t\"proxies\": {"), "{out}");
        // Only puddle's other files are written whole.
        assert!(
            c.files
                .iter()
                .filter(|g| g.path() != f.path())
                .all(|g| *g.apply() == puddle_types::ApplyKind::Replace)
        );
    }

    #[test]
    fn user_entries_reach_every_bypass_list() {
        let settings = ProxySettings {
            no_proxy: [
                "git.corp.example",
                ".corp.example",
                "10.1.2.3",
                "fd00::1",
                "localhost",
            ]
            .into_iter()
            .map(|e| NoProxyEntry::new(e).unwrap())
            .collect(),
            ..ProxySettings::default()
        };
        let c = guest_proxy_config(&settings, &[]).unwrap();
        let bypass = format!("{BYPASS},git.corp.example,.corp.example,10.1.2.3,fd00::1");
        assert_eq!(c.env.get("NO_PROXY"), Some(bypass.as_str()));
        assert_eq!(c.env.get("no_proxy"), Some(bypass.as_str()));
        assert_eq!(c.env.get("GLOBAL_AGENT_NO_PROXY"), Some(bypass.as_str()));
        let java = format!(
            "{JAVA_BYPASS}|git.corp.example|*.git.corp.example|*.corp.example|10.1.2.3|[fd00::1]|*.localhost"
        );
        assert!(c.env.get("JAVA_TOOL_OPTIONS").unwrap().ends_with(&java));
        assert!(text(file_at(&c, MAVEN_SETTINGS_GUEST)).contains(&java));
        let apt = text(file_at(&c, APT_CONF_GUEST));
        assert!(apt.contains("Acquire::https::Proxy::git.corp.example \"DIRECT\";"));
        assert!(apt.contains("Acquire::http::Proxy::10.1.2.3 \"DIRECT\";"));
        assert!(!apt.contains("corp.example \"DIRECT\";\nAcquire::https::Proxy::.corp"));
        assert!(!apt.contains("fd00"));
        assert!(text(file_at(&c, "/root/.docker/config.json")).contains(&bypass));
    }

    #[test]
    fn image_java_and_maven_values_are_kept_with_puddles_appended() {
        let env = image(&[
            ("JAVA_TOOL_OPTIONS", "-Xmx1g"),
            ("MAVEN_ARGS", "-B"),
            ("JAVA_TOOL_OPTIONS", " -Xss2m "),
        ]);
        let c = guest_proxy_config(&ProxySettings::default(), &env).unwrap();
        let java = c.env.get("JAVA_TOOL_OPTIONS").unwrap();
        assert!(
            java.starts_with("-Xss2m -Dhttp.proxyHost=127.0.0.1 "),
            "{java}"
        );
        assert_eq!(
            c.env.get("MAVEN_ARGS"),
            Some("-B -gs /etc/puddle/maven/settings.xml")
        );

        // A value that already carries puddle's (an image built from a puddle sandbox) isn't doubled.
        let again = image(&[
            ("JAVA_TOOL_OPTIONS", java),
            ("MAVEN_ARGS", c.env.get("MAVEN_ARGS").unwrap()),
        ]);
        let c2 = guest_proxy_config(&ProxySettings::default(), &again).unwrap();
        assert_eq!(c2.env.get("JAVA_TOOL_OPTIONS"), Some(java));
        assert_eq!(c2.env.get("MAVEN_ARGS"), c.env.get("MAVEN_ARGS"));

        // Blank image values count as unset.
        let blank = image(&[("JAVA_TOOL_OPTIONS", "  "), ("MAVEN_ARGS", "")]);
        let c3 = guest_proxy_config(&ProxySettings::default(), &blank).unwrap();
        assert_eq!(c3.env, default_config().env);
    }

    #[test]
    fn image_proxy_values_are_replaced() {
        let env = image(&[
            ("HTTPS_PROXY", "http://corp-proxy:8080"),
            ("NO_PROXY", "*.corp"),
        ]);
        let c = guest_proxy_config(&ProxySettings::default(), &env).unwrap();
        assert_eq!(c.env, default_config().env);
    }

    #[test]
    fn image_dirs_move_the_per_user_files() {
        let env = image(&[
            ("GRADLE_USER_HOME", "/opt/gradle-home"),
            ("DOCKER_CONFIG", "/etc/docker-cli"),
        ]);
        let c = guest_proxy_config(&ProxySettings::default(), &env).unwrap();
        file_at(&c, "/opt/gradle-home/init.d/puddle-proxy.gradle");
        file_at(&c, "/etc/docker-cli/config.json");

        // Unusable values (relative, `..`, the root) fall back to the home.
        for bad in ["relative", "/a/../b", "/", "/trailing/"] {
            let env = image(&[("GRADLE_USER_HOME", bad), ("DOCKER_CONFIG", bad)]);
            let c = guest_proxy_config(&ProxySettings::default(), &env).unwrap();
            file_at(&c, "/root/.gradle/init.d/puddle-proxy.gradle");
            file_at(&c, "/root/.docker/config.json");
        }
    }

    #[test]
    fn another_home_moves_the_per_user_files() {
        for (home, gradle) in [
            (
                "/home/vscode",
                "/home/vscode/.gradle/init.d/puddle-proxy.gradle",
            ),
            ("/", "/.gradle/init.d/puddle-proxy.gradle"),
        ] {
            let settings = ProxySettings {
                home: GuestPath::new(home).unwrap(),
                ..ProxySettings::default()
            };
            let c = guest_proxy_config(&settings, &[]).unwrap();
            file_at(&c, gradle);
        }
    }

    #[test]
    fn a_home_too_long_for_a_guest_path_is_an_error() {
        let settings = ProxySettings {
            home: GuestPath::new(&format!("/{}", "h".repeat(4090))).unwrap(),
            ..ProxySettings::default()
        };
        let err = guest_proxy_config(&settings, &[]).unwrap_err();
        assert!(matches!(err, ConfigError::GuestPath { .. }), "{err}");
        assert!(err.to_string().contains("4096"), "{err}");
    }

    #[test]
    fn an_image_value_with_nul_is_an_error() {
        let env = image(&[("JAVA_TOOL_OPTIONS", "-Da=\0")]);
        let err = guest_proxy_config(&ProxySettings::default(), &env).unwrap_err();
        assert_eq!(
            err,
            ConfigError::ImageEnv {
                name: "JAVA_TOOL_OPTIONS".to_owned(),
                reason: "must not contain NUL".to_owned(),
            }
        );
        assert!(err.to_string().contains("JAVA_TOOL_OPTIONS"));
    }

    #[test]
    fn without_a_container_proxy_there_is_no_docker_config_or_bridge_entry() {
        let settings = ProxySettings {
            container_proxy: None,
            ..ProxySettings::default()
        };
        let c = guest_proxy_config(&settings, &[]).unwrap();
        assert!(
            c.files
                .iter()
                .all(|f| !f.path().as_str().contains("docker"))
        );
        assert_eq!(c.env.get("NO_PROXY"), Some("localhost,127.0.0.1,::1"));
        assert!(
            c.env
                .get("JAVA_TOOL_OPTIONS")
                .unwrap()
                .ends_with("-Dhttp.nonProxyHosts=localhost|127.*|[::1]|0.0.0.0|[::0]")
        );
    }

    #[test]
    fn an_ipv6_proxy_is_bracketed_where_a_url_or_java_needs_it() {
        let settings = ProxySettings {
            proxy: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 3128),
            ..ProxySettings::default()
        };
        let c = guest_proxy_config(&settings, &[]).unwrap();
        assert_eq!(c.env.get("HTTPS_PROXY"), Some("http://[::1]:3128"));
        assert!(
            c.env
                .get("JAVA_TOOL_OPTIONS")
                .unwrap()
                .starts_with("-Dhttp.proxyHost=[::1] ")
        );
        assert!(text(file_at(&c, MAVEN_SETTINGS_GUEST)).contains("<host>::1</host>"));
    }
}
