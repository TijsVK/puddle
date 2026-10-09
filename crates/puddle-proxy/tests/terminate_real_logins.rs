// SPDX-License-Identifier: GPL-3.0-or-later
//! The real Claude Code, `gh` and GitHub Copilot command-line tools logging in through the proxy
//! and the real login capture, against fake servers that speak the three logins' wire formats.
//! No account is involved and nothing leaves the machine.
//!
//! These prove what the tests with hand-written requests cannot: that each tool accepts the
//! stand-ins it is given, keeps working with them (an API call, a refresh, Git's credential
//! helper) and never holds a real token. The tools are the user's own installs: a test skips when
//! its tool is not found, unless `PUDDLE_LOGIN_TOOLS_REQUIRED` is set. `claude` and `gh` come from
//! the path, Copilot CLI from `PUDDLE_COPILOT_BIN` (its VS Code shim installs the real program on
//! first use, so the path alone is not enough). Unix only.
#![cfg(unix)]
#![expect(
    clippy::print_stderr,
    clippy::unwrap_used,
    reason = "a skipped test says so; helpers outside #[test] functions fail the test by panicking"
)]
mod git_support;
mod terminate_support;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puddle_logins::{LoginNotices, Logins, Problem, Profile, builtin};
use puddle_proxy::{InjectDecision, StandIns};
use puddle_secrets::{MemoryStore, SecretStore};
use puddle_types::WorkspaceName;
use serde_json::{Value, json};
use terminate_support::{
    FakeServer, Flaw, Guest, Handler, LOCAL, Pki, Recorded, Reply, Rig, RigBuilder, TestInjector,
    captured_logs,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;

const ACCESS: &str =
    "sk-ant-oat01-CANARYrealaccess0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
const REFRESH: &str =
    "sk-ant-ort01-CANARYrealrefresh0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";
const ACCESS_2: &str =
    "sk-ant-oat01-CANARYsecondaccess0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ";
const REFRESH_2: &str =
    "sk-ant-ort01-CANARYsecondrefresh0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
const API_KEY: &str = "sk-ant-api03-CANARYrealapikey0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL-end-of-the-key";
const GITHUB: &str = "gho_CANARYrealgithub0123456789abcdefgh";
const SHA: &str = "1111111111111111111111111111111111111111";
const REALS: [&str; 6] = [ACCESS, REFRESH, ACCESS_2, REFRESH_2, API_KEY, GITHUB];

const HOSTS: [&str; 7] = [
    "platform.claude.com",
    "api.anthropic.com",
    "claude.ai",
    "github.com",
    "api.github.com",
    "api.individual.githubcopilot.com",
    "telemetry.individual.githubcopilot.com",
];

#[derive(Default)]
struct Notices(Mutex<Vec<Problem>>);

impl LoginNotices for Notices {
    fn problem(&self, _: &WorkspaceName, _: &Profile, problem: Problem) {
        self.0.lock().unwrap().push(problem);
    }
}

fn tool_missing(what: &str) -> bool {
    assert!(
        std::env::var_os("PUDDLE_LOGIN_TOOLS_REQUIRED").is_none(),
        "PUDDLE_LOGIN_TOOLS_REQUIRED is set but {what} was not found"
    );
    eprintln!("skipped: {what} not found");
    true
}

fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn json_reply(value: &Value) -> Reply {
    let body = value.to_string();
    Reply::raw(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn form_reply(body: &str) -> Reply {
    Reply::raw(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/x-www-form-urlencoded; charset=utf-8\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn not_found() -> Reply {
    Reply::status(404, "content-type: application/json\r\n", "{}")
}

fn path_of(request: &Recorded) -> &str {
    request.target.split('?').next().unwrap_or_default()
}

fn pkt(text: &str) -> String {
    format!("{:04x}{text}", text.len() + 4)
}

/// Claude Code's token endpoint: the code exchange, then one refresh.
fn claude_token(request: &Recorded, console: bool) -> Reply {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
    let tokens = |access: &str, refresh: &str| {
        json_reply(&json!({
            "token_type": "Bearer",
            "access_token": access,
            "expires_in": 28800,
            "refresh_token": refresh,
            // A console login has no inference scope and so asks for an API key; a subscription
            // login does not.
            "scope": if console {
                "org:create_api_key user:profile"
            } else {
                "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
            },
            "account": {"uuid": "u-1", "email_address": "standin@example.invalid"},
            "organization": {"uuid": "o-1", "name": "standin-org"},
        }))
    };
    match body.get("grant_type").and_then(Value::as_str) {
        Some("authorization_code") => tokens(ACCESS, REFRESH),
        Some("refresh_token")
            if body.get("refresh_token").and_then(Value::as_str) == Some(REFRESH) =>
        {
            tokens(ACCESS_2, REFRESH_2)
        }
        _ => Reply::status(
            400,
            "content-type: application/json\r\n",
            r#"{"error":"invalid_grant"}"#,
        ),
    }
}

fn claude_api(request: &Recorded) -> Reply {
    match path_of(request) {
        "/api/oauth/profile" => json_reply(&json!({
            "account": {"uuid": "u-1", "email": "standin@example.invalid"},
            "organization": {"uuid": "o-1"},
        })),
        "/api/oauth/claude_cli/roles" => {
            json_reply(&json!({"organization_role": "admin", "workspace_role": null}))
        }
        "/api/oauth/claude_cli/create_api_key" => json_reply(&json!({"raw_key": API_KEY})),
        _ => not_found(),
    }
}

/// GitHub's OAuth endpoints, answering in the format the request's `Accept` asks for. The device
/// flow says "pending" once per login before the token.
fn github_com(request: &Recorded, pending: &Mutex<bool>) -> Reply {
    let json = request
        .header("accept")
        .is_some_and(|accept| accept.contains("json"));
    match path_of(request) {
        "/login/device/code" if json => json_reply(&json!({
            "device_code": "d".repeat(40), "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 1,
        })),
        "/login/device/code" => form_reply(&format!(
            "device_code={}&expires_in=900&interval=1&user_code=ABCD-1234&verification_uri=https%3A%2F%2Fgithub.com%2Flogin%2Fdevice",
            "d".repeat(40)
        )),
        "/login/oauth/access_token" => {
            let mut waiting = pending.lock().unwrap();
            if !*waiting {
                *waiting = true;
                return if json {
                    json_reply(&json!({"error": "authorization_pending"}))
                } else {
                    form_reply("error=authorization_pending&interval=1")
                };
            }
            *waiting = false;
            if json {
                json_reply(
                    &json!({"access_token": GITHUB, "token_type": "bearer", "scope": "repo,gist"}),
                )
            } else {
                form_reply(&format!(
                    "access_token={GITHUB}&scope=repo%2Cread%3Aorg%2Cgist&token_type=bearer"
                ))
            }
        }
        path if path.ends_with("/info/refs") => {
            // Git's Basic credentials carry the user name the helper gave and the token as the
            // password.
            let password = request
                .header("authorization")
                .and_then(|a| a.strip_prefix("Basic "))
                .and_then(|b| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.decode(b).ok()
                })
                .and_then(|d| String::from_utf8(d).ok())
                .and_then(|d| d.split_once(':').map(|(_, password)| password.to_owned()));
            if password.as_deref() != Some(GITHUB) {
                return Reply::status(401, "www-authenticate: Basic realm=\"GitHub\"\r\n", "no");
            }
            let body = format!(
                "{}0000{}0000",
                pkt("# service=git-upload-pack\n"),
                pkt(&format!(
                    "{SHA} refs/heads/main\0side-band-64k ofs-delta agent=test\n"
                ))
            );
            Reply::raw(format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/x-git-upload-pack-advertisement\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            ))
        }
        _ => not_found(),
    }
}

fn github_api(request: &Recorded) -> Reply {
    let scopes = "X-OAuth-Scopes: gist, read:org, repo\r\n";
    let with_scopes = |body: &Value| {
        let text = body.to_string();
        Reply::raw(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{scopes}content-length: {}\r\n\r\n{text}",
            text.len()
        ))
    };
    match path_of(request) {
        "/" => with_scopes(&json!({})),
        "/user" => with_scopes(&json!({"login": "standin-user", "id": 1, "type": "User"})),
        "/graphql" => with_scopes(&json!({"data": {"viewer": {"login": "standin-user"}}})),
        "/copilot_internal/user" => json_reply(&json!({
            "login": "standin-user", "copilot_plan": "individual", "chat_enabled": true,
            "endpoints": {
                "api": "https://api.individual.githubcopilot.com",
                "telemetry": "https://telemetry.individual.githubcopilot.com",
            },
        })),
        _ => not_found(),
    }
}

struct Tools {
    rig: Rig,
    home: tempfile::TempDir,
    port: u16,
    servers: Vec<(&'static str, FakeServer)>,
    notices: Arc<Notices>,
    store: Arc<MemoryStore>,
    _guest: Guest,
    _bridge: JoinHandle<()>,
}

/// A loopback port that is a tool's HTTP proxy: each connection becomes a stream into the
/// guest's route, as the guest agent relays the proxy port.
async fn proxy_port(guest: &Guest) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut control = guest.control.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let Ok(mut stream) = control.open_stream().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
            });
        }
    });
    (port, task)
}

/// What one run of a tool printed.
struct Ran {
    ok: bool,
    out: String,
}

impl Tools {
    async fn new(console: bool) -> Self {
        let pki = Pki::new();
        let pending = Arc::new(Mutex::new(false));
        let mut servers = Vec::new();
        let mut rig = RigBuilder::new(&pki);
        let mut bound = Vec::new();
        for host in HOSTS {
            let handler: Handler = match host {
                "platform.claude.com" => Arc::new(move |r: &Recorded| claude_token(r, console)),
                "api.anthropic.com" => Arc::new(|r: &Recorded| claude_api(r)),
                "github.com" => {
                    let pending = Arc::clone(&pending);
                    Arc::new(move |r: &Recorded| github_com(r, &pending))
                }
                "api.github.com" => Arc::new(|r: &Recorded| github_api(r)),
                _ => Arc::new(|r: &Recorded| {
                    if path_of(r) == "/models" {
                        json_reply(&json!({"data": []}))
                    } else {
                        not_found()
                    }
                }),
            };
            let server = FakeServer::tls(pki.server_config(host, Flaw::None), handler).await;
            rig = rig.name(host, server.addr);
            bound.push(host);
            servers.push((host, server));
        }
        let store = Arc::new(MemoryStore::new());
        let notices = Arc::new(Notices::default());
        let registry = Arc::new(StandIns::new());
        let logins = Logins::new(
            WorkspaceName::new("box").unwrap(),
            true,
            builtin(),
            Arc::clone(&registry),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            Arc::clone(&notices) as Arc<dyn LoginNotices>,
        );
        let rig = rig
            .bound(bound.clone())
            .allow(bound)
            .injector(TestInjector::new(|_| InjectDecision::PassThrough))
            .stand_ins(&registry)
            .exchanges(Arc::new(logins))
            .build();
        let guest = rig.guest().await;
        let (port, bridge) = proxy_port(&guest).await;
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("ca.pem"), rig.ca.certificate().pem()).unwrap();
        Self {
            rig,
            home,
            port,
            servers,
            notices,
            store,
            _guest: guest,
            _bridge: bridge,
        }
    }

    fn server(&self, host: &str) -> &FakeServer {
        &self
            .servers
            .iter()
            .find(|(name, _)| *name == host)
            .unwrap()
            .1
    }

    fn command(&self, program: &Path) -> Command {
        let home = self.home.path();
        let ca = home.join("ca.pem");
        let proxy = format!("http://127.0.0.1:{}", self.port);
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("TERM", "dumb")
            .env("HTTPS_PROXY", &proxy)
            .env("https_proxy", &proxy)
            .env("SSL_CERT_FILE", &ca)
            .env("NODE_EXTRA_CA_CERTS", &ca)
            .env("GIT_SSL_CAINFO", &ca)
            .env("GH_BROWSER", "true")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("DO_NOT_TRACK", "1")
            .current_dir(home)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    async fn run(&self, mut command: Command, stdin: &str, limit: Duration) -> Ran {
        let mut child = command.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let text = stdin.to_owned();
        tokio::spawn(async move {
            let _ = input.write_all(text.as_bytes()).await;
            // Left open: a tool that waits for more input is cut off by the time limit.
            tokio::time::sleep(Duration::from_secs(300)).await;
            drop(input);
        });
        match tokio::time::timeout(limit, child.wait_with_output()).await {
            Ok(Ok(output)) => Ran {
                ok: output.status.success(),
                out: format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            },
            Ok(Err(err)) => Ran {
                ok: false,
                out: err.to_string(),
            },
            Err(_) => Ran {
                ok: false,
                out: "timed out".to_owned(),
            },
        }
    }

    /// Every file under the tool's home, as text (binary files are skipped).
    fn home_text(&self) -> String {
        fn walk(dir: &Path, out: &mut String) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(text) = std::fs::read_to_string(&path) {
                    let _ = write!(out, "\n--- {}\n{text}", path.display());
                }
            }
        }
        let mut out = String::new();
        walk(self.home.path(), &mut out);
        out
    }

    /// Nothing of a real token is anywhere the workspace can read it, or in a log.
    fn assert_no_real_token_in_the_workspace(&self) {
        let home = self.home_text();
        for real in REALS {
            assert!(!home.contains(real), "{real} is in the tool's home");
            assert!(!captured_logs().contains(real), "{real} is in a log");
        }
    }
}

fn authorizations(server: &FakeServer) -> Vec<String> {
    server
        .recorded()
        .iter()
        .filter_map(|r| r.header("authorization").map(str::to_owned))
        .collect()
}

// ------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claude_code_logs_in_calls_the_api_and_refreshes_with_stand_ins_only() {
    let Some(claude) = on_path("claude") else {
        tool_missing("claude");
        return;
    };
    let tools = Tools::new(false).await;

    // `claude auth login`, the code pasted on stdin as the browser page would give it.
    let mut login = tools.command(&claude);
    login.args(["auth", "login"]);
    let ran = tools
        .run(login, "fakecode#fakestate\n", Duration::from_secs(90))
        .await;
    let credentials = tools.home.path().join(".claude/.credentials.json");
    let saved: Value = serde_json::from_str(
        &std::fs::read_to_string(&credentials)
            .unwrap_or_else(|err| panic!("no credentials ({err}): {}", ran.out)),
    )
    .unwrap();
    let oauth = &saved["claudeAiOauth"];
    let access = oauth["accessToken"].as_str().unwrap().to_owned();
    let refresh = oauth["refreshToken"].as_str().unwrap().to_owned();
    assert!(
        access.starts_with("sk-ant-oat01-") && access != ACCESS,
        "{access}"
    );
    assert!(
        refresh.starts_with("sk-ant-ort01-") && refresh != REFRESH,
        "{refresh}"
    );
    assert_eq!(access.len(), ACCESS.len());
    tools.assert_no_real_token_in_the_workspace();
    assert_eq!(*tools.notices.0.lock().unwrap(), []);

    // A call with the access stand-in reaches the API as the real token.
    let mut ask = tools.command(&claude);
    ask.args(["-p", "say hi", "--output-format", "json"]);
    let ran = tools.run(ask, "", Duration::from_secs(90)).await;
    let seen = authorizations(tools.server("api.anthropic.com"));
    assert!(
        seen.contains(&format!("Bearer {ACCESS}")),
        "{seen:?}\n{}",
        ran.out
    );
    assert!(
        !seen.iter().any(|a| a.contains(&access)),
        "the stand-in went out: {seen:?}"
    );

    // An expired access token makes the tool refresh with the refresh stand-in.
    let mut aged = saved.clone();
    aged["claudeAiOauth"]["expiresAt"] = json!(1_000);
    std::fs::write(&credentials, aged.to_string()).unwrap();
    let mut ask = tools.command(&claude);
    ask.args(["-p", "say hi again", "--output-format", "json"]);
    let ran = tools.run(ask, "", Duration::from_secs(90)).await;
    let refreshes: Vec<Value> = tools
        .server("platform.claude.com")
        .recorded()
        .iter()
        .filter_map(|r| serde_json::from_slice::<Value>(&r.body).ok())
        .filter(|b| b["grant_type"] == "refresh_token")
        .collect();
    assert!(!refreshes.is_empty(), "no refresh was made: {}", ran.out);
    assert!(
        refreshes.iter().all(|b| b["refresh_token"] == REFRESH),
        "{refreshes:?}"
    );
    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&credentials).unwrap()).unwrap();
    assert_eq!(after["claudeAiOauth"]["accessToken"], access.as_str());
    assert_eq!(after["claudeAiOauth"]["refreshToken"], refresh.as_str());
    tools.assert_no_real_token_in_the_workspace();
    let _ = &tools.store;
    let _ = &tools.rig;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claude_code_console_login_keeps_the_api_key_it_creates_and_sends_it_only_as_the_real_key()
{
    let Some(claude) = on_path("claude") else {
        tool_missing("claude");
        return;
    };
    let tools = Tools::new(true).await;
    let mut login = tools.command(&claude);
    login.args(["auth", "login"]);
    let ran = tools
        .run(login, "fakecode#fakestate\n", Duration::from_secs(90))
        .await;
    assert!(
        tools
            .server("api.anthropic.com")
            .recorded()
            .iter()
            .any(|r| r.target.contains("create_api_key")),
        "the tool did not ask for an API key: {}",
        ran.out
    );
    // The tool kept the end of the key it was given, which is the end of the real key too, and
    // nothing more of it anywhere.
    let config = std::fs::read_to_string(tools.home.path().join(".claude.json")).unwrap();
    assert!(config.contains(&API_KEY[API_KEY.len() - 20..]), "{config}");
    tools.assert_no_real_token_in_the_workspace();
    assert_eq!(*tools.notices.0.lock().unwrap(), []);

    // A call made with it carries the real key.
    let mut ask = tools.command(&claude);
    ask.args(["-p", "say hi", "--output-format", "json"]);
    let ran = tools.run(ask, "", Duration::from_secs(90)).await;
    let keys: Vec<String> = tools
        .server("api.anthropic.com")
        .recorded()
        .iter()
        .filter_map(|r| r.header("x-api-key").map(str::to_owned))
        .collect();
    assert!(keys.contains(&API_KEY.to_owned()), "{keys:?}\n{}", ran.out);
    assert_eq!(
        keys.iter()
            .filter(|k| k.starts_with("sk-ant-api03-") && *k != API_KEY)
            .count(),
        0
    );
    tools.assert_no_real_token_in_the_workspace();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gh_logs_in_with_the_device_flow_and_its_token_works_for_the_api_and_for_git_through_the_helper()
 {
    let Some(gh) = on_path("gh") else {
        tool_missing("gh");
        return;
    };
    let Some(git) = on_path("git") else {
        tool_missing("git");
        return;
    };
    let tools = Tools::new(false).await;

    let mut login = tools.command(&gh);
    login
        .args([
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
        ])
        .env("GH_PROMPT_DISABLED", "1");
    let ran = tools.run(login, "\n", Duration::from_secs(120)).await;
    assert!(ran.ok, "{}", ran.out);
    let hosts = std::fs::read_to_string(tools.home.path().join(".config/gh/hosts.yml")).unwrap();
    assert!(hosts.contains("oauth_token: gho_"), "{hosts}");
    assert!(!hosts.contains(GITHUB), "the real token is in hosts.yml");
    tools.assert_no_real_token_in_the_workspace();
    assert_eq!(*tools.notices.0.lock().unwrap(), []);

    // The API sees the real token.
    let mut status = tools.command(&gh);
    status.args(["api", "/user"]);
    let ran = tools.run(status, "", Duration::from_secs(60)).await;
    assert!(ran.ok, "{}", ran.out);
    assert!(
        authorizations(tools.server("api.github.com")).contains(&format!("token {GITHUB}")),
        "{:?}",
        authorizations(tools.server("api.github.com"))
    );

    // Git, with `gh auth git-credential` as its helper, sends the real token as the password.
    let helper = format!("!{} auth git-credential", gh.display());
    let mut ls = tools.command(&git);
    ls.args([
        "-c",
        "credential.helper=",
        "-c",
        &format!("credential.helper={helper}"),
        "-c",
        &format!("http.proxy=http://127.0.0.1:{}", tools.port),
        "-c",
        &format!(
            "http.sslCAInfo={}",
            tools.home.path().join("ca.pem").display()
        ),
        "ls-remote",
        "https://github.com/acme/web.git",
    ]);
    let ran = tools.run(ls, "", Duration::from_secs(60)).await;
    assert!(ran.ok && ran.out.contains(SHA), "{}", ran.out);
    tools.assert_no_real_token_in_the_workspace();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn copilot_cli_uses_the_stand_in_from_a_gh_login_on_the_copilot_hosts() {
    let Some(gh) = on_path("gh") else {
        tool_missing("gh");
        return;
    };
    let Some(copilot) = std::env::var_os("PUDDLE_COPILOT_BIN").map(PathBuf::from) else {
        tool_missing("PUDDLE_COPILOT_BIN");
        return;
    };
    let tools = Tools::new(false).await;
    let mut login = tools.command(&gh);
    login
        .args([
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
        ])
        .env("GH_PROMPT_DISABLED", "1");
    assert!(tools.run(login, "\n", Duration::from_secs(120)).await.ok);
    let hosts = std::fs::read_to_string(tools.home.path().join(".config/gh/hosts.yml")).unwrap();
    let stand_in = hosts
        .lines()
        .find_map(|l| l.trim().strip_prefix("oauth_token: "))
        .unwrap()
        .to_owned();
    assert!(stand_in.starts_with("gho_") && stand_in != GITHUB);

    // One GitHub login covers the Copilot service: the same stand-in is the Copilot token.
    let mut ask = tools.command(&copilot);
    ask.args(["-p", "say hi"])
        .env("COPILOT_GITHUB_TOKEN", &stand_in);
    let ran = tools.run(ask, "", Duration::from_secs(90)).await;
    let api = authorizations(tools.server("api.github.com"));
    assert!(
        api.iter().any(|a| a.contains(GITHUB)),
        "{api:?}\n{}",
        ran.out
    );
    let copilot_hosts = authorizations(tools.server("api.individual.githubcopilot.com"));
    assert!(
        copilot_hosts.contains(&format!("Bearer {GITHUB}")),
        "{copilot_hosts:?}\n{}",
        ran.out
    );
    assert!(
        !api.iter()
            .chain(&copilot_hosts)
            .any(|a| a.contains(&stand_in)),
        "the stand-in went out"
    );
    tools.assert_no_real_token_in_the_workspace();
}
