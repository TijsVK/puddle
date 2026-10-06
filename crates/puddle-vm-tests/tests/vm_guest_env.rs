// SPDX-License-Identifier: GPL-3.0-or-later
//! T-109's VM bar (tier K): with puddle's boot-time proxy config (`puddle-guest-env`) in a tools
//! image, each tool by name reaches a local fixture through the proxy route.
//!
//! The guest's proxy listener is played by a fixture in the guest on the agent's address
//! (127.0.0.1:3128): it logs every request line and answers with a fixed response (or 502 to a
//! CONNECT). Every probe targets a name under `.test`, which never resolves, so a tool that
//! ignores the config fails instead of reaching the fixture another way. The VM keeps msb's
//! default network only for installing the tools first.
//!
//! The config goes in the way the boot hook would apply it: the files written as root with their
//! modes, the env given to each exec. Until the boot hook runs in VMs (T-106), the files are
//! written by this test; the content is exactly `guest_proxy_config`'s.
//!
//! Tools that still fail are listed in [`KNOWN_GAPS`] (capture gaps for W2): the test fails when
//! a tool outside the list fails, and also when a listed one starts working, so the list stays
//! true.
#![expect(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "VM test: a failed step fails the test; the probe table goes to stderr"
)]

use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use puddle_guest_env::{GuestProxyConfig, ProxySettings, guest_proxy_config};
use puddle_vm_tests::{HarnessError, VmEnv, within};

/// Node 24 (`NODE_USE_ENV_PROXY`), Debian 13 (Maven 3.9 for `MAVEN_ARGS`, `OpenJDK` 21).
const TOOLS_IMAGE: &str = "node:24-trixie-slim";
const GRADLE_VERSION: &str = "8.14.3";
const PNPM: &str = "pnpm@10.12.1";
const YARN_BERRY: &str = "yarn@4.9.2";

const CREATE_BUDGET: Duration = Duration::from_secs(300);
const SETUP_BUDGET: Duration = Duration::from_secs(420);
const PROBE_BUDGET: Duration = Duration::from_secs(150);
const STEP_BUDGET: Duration = Duration::from_secs(60);

/// Probes expected to fail today, by name (see the module docs).
const KNOWN_GAPS: &[&str] = &[];

const SETUP: &str = r#"set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl wget git sudo unzip \
  python3-pip openjdk-21-jdk-headless maven >/dev/null
curl -fsSL -o /tmp/gradle.zip "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
unzip -q /tmp/gradle.zip -d /opt
ln -sf "/opt/gradle-$GRADLE_VERSION/bin/gradle" /usr/local/bin/gradle
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
corepack enable pnpm
corepack install -g "$PNPM"
mkdir -p /tmp/warm && cd /tmp/warm && corepack "$YARN_BERRY" --version
mvn -v | head -1; gradle --version -q | grep Gradle; node -v; pnpm -v; yarn -v; java -version 2>&1 | head -1
"#;

/// The guest side of the route: logs `<request line> host=<Host>` per request.
const FIXTURE: &str = r"
const net = require('net'), fs = require('fs');
const log = fs.openSync('/tmp/fixture.log', 'a');
net.createServer((s) => {
  let buf = '';
  s.on('error', () => {});
  s.on('data', (d) => {
    buf += d.toString('latin1');
    const end = buf.indexOf('\r\n\r\n');
    if (end < 0) return;
    s.removeAllListeners('data');
    const lines = buf.slice(0, end).split('\r\n');
    const host = (lines.find((l) => /^host:/i.test(l)) || 'host:').slice(5).trim();
    fs.writeSync(log, lines[0] + ' host=' + host + '\n');
    if (lines[0].startsWith('CONNECT ')) {
      s.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    } else {
      s.end('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\npuddle-fixture\n');
    }
  });
}).listen(3128, '127.0.0.1');
";

const JAVA_FETCH: &str = r#"
public class Fetch {
  public static void main(String[] a) throws Exception {
    var uri = java.net.URI.create(a[0]);
    if (a[1].equals("url")) {
      var c = (java.net.HttpURLConnection) uri.toURL().openConnection();
      c.setConnectTimeout(20000);
      System.out.println(c.getResponseCode());
    } else {
      var c = java.net.http.HttpClient.newHttpClient();
      var r = c.send(java.net.http.HttpRequest.newBuilder(uri).build(),
          java.net.http.HttpResponse.BodyHandlers.ofString());
      System.out.println(r.statusCode());
    }
  }
}
"#;

/// One tool reaching the fixture: passes when a request for one of `hosts` reaches the fixture
/// while `script` runs.
struct Probe {
    name: &'static str,
    hosts: &'static [&'static str],
    script: String,
}

fn probe(name: &'static str, hosts: &'static [&'static str], script: &str) -> Probe {
    Probe {
        name,
        hosts,
        script: script.to_owned(),
    }
}

fn node_project(dir: &str, extra: &str) -> String {
    format!(
        "mkdir -p {dir} && cd {dir} && printf '%s' \
         '{{\"name\":\"p\",\"version\":\"1.0.0\",{extra}\"dependencies\":{{\"left-pad\":\"1.3.0\"}}}}' \
         > package.json"
    )
}

fn maven_project(dir: &str, repo: &str) -> String {
    format!(
        "mkdir -p {dir} && cd {dir} && cat > pom.xml <<'EOF'
<project xmlns=\"http://maven.apache.org/POM/4.0.0\">
  <modelVersion>4.0.0</modelVersion>
  <groupId>t</groupId><artifactId>p</artifactId><version>1</version>
  <repositories><repository><id>fx</id><url>{repo}</url></repository></repositories>
  <dependencies><dependency><groupId>org.example</groupId><artifactId>thing</artifactId><version>1.0</version></dependency></dependencies>
</project>
EOF
mvn -B -U -Dmaven.repo.local={dir}/m2 compile"
    )
}

fn gradle_project(dir: &str, repo: &str) -> String {
    format!(
        "mkdir -p {dir} && cd {dir} && : > settings.gradle && cat > build.gradle <<'EOF'
repositories {{ maven {{ url = '{repo}' }} }}
configurations {{ fetch }}
dependencies {{ fetch 'org.example:thing:1.0' }}
tasks.register('fetch') {{ doLast {{ configurations.fetch.resolve() }} }}
EOF
gradle --no-daemon --refresh-dependencies -q fetch"
    )
}

fn apt_update(list: &str) -> String {
    format!(
        "mkdir -p /tmp/apt-empty && echo '{list}' > /tmp/apt-probe.list && \
         env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin apt-get -o Dir::Etc::SourceList=/tmp/apt-probe.list \
         -o Dir::Etc::SourceParts=/tmp/apt-empty -o Acquire::Retries=0 update"
    )
}

#[expect(clippy::too_many_lines, reason = "one flat list of probes reads best")]
fn probes() -> Vec<Probe> {
    let node_fetch = |url: &str| {
        format!(
            "node -e \"fetch('{url}').then(r => r.text()).then(console.log)\
             .catch(e => {{ console.error(e); process.exit(1); }})\""
        )
    };
    vec![
        probe(
            "curl http",
            &["curl.fixture.test"],
            "curl -sS -m 20 http://curl.fixture.test/a",
        ),
        probe(
            "curl https",
            &["curl-tls.fixture.test"],
            "curl -sS -m 20 https://curl-tls.fixture.test/a",
        ),
        probe(
            "wget http",
            &["wget.fixture.test"],
            "wget -q -O- -T 20 -t 1 http://wget.fixture.test/a",
        ),
        probe(
            "wget https",
            &["wget-tls.fixture.test"],
            "wget -q -O- -T 20 -t 1 https://wget-tls.fixture.test/a",
        ),
        probe(
            "git http",
            &["git.fixture.test"],
            "git ls-remote http://git.fixture.test/r.git",
        ),
        probe(
            "git https",
            &["git-tls.fixture.test"],
            "git ls-remote https://git-tls.fixture.test/r.git",
        ),
        probe(
            "apt http (file only)",
            &["apt.fixture.test"],
            &apt_update("deb http://apt.fixture.test/debian trixie main"),
        ),
        probe(
            "apt https (file only)",
            &["apt-tls.fixture.test"],
            &apt_update("deb https://apt-tls.fixture.test/debian trixie main"),
        ),
        probe(
            "npm http",
            &["npm.fixture.test"],
            "npm view left-pad --registry=http://npm.fixture.test/ --fetch-retries=0",
        ),
        probe(
            "npm https",
            &["npm-tls.fixture.test"],
            "npm view left-pad --registry=https://npm-tls.fixture.test/ --fetch-retries=0",
        ),
        probe(
            "pnpm http",
            &["pnpm.fixture.test"],
            &format!(
                "{} && pnpm install --registry=http://pnpm.fixture.test/ --fetch-retries=0",
                node_project("/tmp/pnpm-a", "")
            ),
        ),
        probe(
            "pnpm https",
            &["pnpm-tls.fixture.test"],
            &format!(
                "{} && pnpm install --registry=https://pnpm-tls.fixture.test/ --fetch-retries=0",
                node_project("/tmp/pnpm-b", "")
            ),
        ),
        probe(
            "yarn 1 http",
            &["yarn.fixture.test"],
            "cd /tmp && yarn info left-pad --registry http://yarn.fixture.test/ --non-interactive",
        ),
        probe(
            "yarn 1 https",
            &["yarn-tls.fixture.test"],
            "cd /tmp && yarn info left-pad --registry https://yarn-tls.fixture.test/ --non-interactive",
        ),
        probe(
            "yarn berry http",
            &["berry.fixture.test"],
            &format!(
                "{} && touch yarn.lock && YARN_NPM_REGISTRY_SERVER=http://berry.fixture.test \
             YARN_UNSAFE_HTTP_WHITELIST=berry.fixture.test YARN_ENABLE_IMMUTABLE_INSTALLS=false \
             COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack yarn install",
                node_project(
                    "/tmp/berry-a",
                    &format!("\"packageManager\":\"{YARN_BERRY}\",")
                )
            ),
        ),
        probe(
            "yarn berry https",
            &["berry-tls.fixture.test"],
            &format!(
                "{} && touch yarn.lock && YARN_NPM_REGISTRY_SERVER=https://berry-tls.fixture.test \
             YARN_ENABLE_IMMUTABLE_INSTALLS=false COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack yarn install",
                node_project(
                    "/tmp/berry-b",
                    &format!("\"packageManager\":\"{YARN_BERRY}\",")
                )
            ),
        ),
        probe(
            "pip http",
            &["pip.fixture.test"],
            "python3 -m pip download --no-deps --retries 0 --timeout 20 -d /tmp/pipd \
            --index-url http://pip.fixture.test/simple --trusted-host pip.fixture.test left-pad",
        ),
        probe(
            "pip https",
            &["pip-tls.fixture.test"],
            "python3 -m pip download --no-deps --retries 0 --timeout 20 -d /tmp/pipd \
            --index-url https://pip-tls.fixture.test/simple left-pad",
        ),
        probe(
            "maven",
            &["repo.maven.apache.org", "mvn-tls.fixture.test"],
            &maven_project("/tmp/mvn-a", "https://mvn-tls.fixture.test/m2"),
        ),
        probe(
            "maven (settings file only)",
            &["repo.maven.apache.org", "mvn2-tls.fixture.test"],
            &format!(
                "unset JAVA_TOOL_OPTIONS && {}",
                maven_project("/tmp/mvn-b", "https://mvn2-tls.fixture.test/m2")
            ),
        ),
        probe(
            "gradle",
            &["gradle-tls.fixture.test"],
            &gradle_project("/tmp/gradle-a", "https://gradle-tls.fixture.test/m2"),
        ),
        probe(
            "gradle (init script only)",
            &["gradle2-tls.fixture.test"],
            &format!(
                "unset JAVA_TOOL_OPTIONS && {}",
                gradle_project("/tmp/gradle-b", "https://gradle2-tls.fixture.test/m2")
            ),
        ),
        probe(
            "node fetch http",
            &["node.fixture.test"],
            &node_fetch("http://node.fixture.test/a"),
        ),
        probe(
            "node fetch https",
            &["node-tls.fixture.test"],
            &node_fetch("https://node-tls.fixture.test/a"),
        ),
        probe(
            "java HttpURLConnection http",
            &["java.fixture.test"],
            "java /tmp/Fetch.java http://java.fixture.test/a url",
        ),
        probe(
            "java HttpURLConnection https",
            &["java-tls.fixture.test"],
            "java /tmp/Fetch.java https://java-tls.fixture.test/a url",
        ),
        probe(
            "java HttpClient https",
            &["javahc-tls.fixture.test"],
            "java /tmp/Fetch.java https://javahc-tls.fixture.test/a client",
        ),
        probe(
            "sudo keeps the vars (curl)",
            &["sudo.fixture.test"],
            "sudo -u node curl -sS -m 20 http://sudo.fixture.test/a",
        ),
        probe(
            "sudo keeps the vars (node fetch)",
            &["sudo-node.fixture.test"],
            &format!(
                "sudo -u node {}",
                node_fetch("https://sudo-node.fixture.test/a")
            ),
        ),
    ]
}

/// Runs `script` as root with `config`'s env; returns exit code and the output's tail.
async fn run(sb: &Sandbox, config: &GuestProxyConfig, script: &str) -> (i32, String) {
    let env: Vec<(String, String)> = config
        .env
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let script = format!("exec 2>&1; timeout 120 sh -c {}", sh_quote(script));
    let out = within(
        "probe",
        PROBE_BUDGET,
        sb.shell_with(script, |e| e.user("root").envs(env).timeout(PROBE_BUDGET)),
    )
    .await
    .unwrap()
    .unwrap();
    let text = out.stdout().unwrap_or_default();
    let tail: String = text
        .lines()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    (out.status().code, tail)
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Writes `contents` to `path` as root with `mode`, creating the directory.
async fn write_file(sb: &Sandbox, path: &str, mode: u32, contents: &[u8]) {
    let out = within(
        "write file",
        STEP_BUDGET,
        sb.exec_with("/bin/sh", |e| {
            e.args([
                "-c",
                "mkdir -p \"$(dirname \"$1\")\" && cat > \"$1\" && chmod \"$2\" \"$1\"",
                "sh",
                path,
                &format!("{mode:o}"),
            ])
            .user("root")
            .stdin_bytes(contents.to_vec())
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out.status().code, 0, "writing {path}: {:?}", out.stderr());
}

async fn fixture_log(sb: &Sandbox) -> Vec<String> {
    let out = within(
        "read log",
        STEP_BUDGET,
        sb.shell("cat /tmp/fixture.log 2>/dev/null || true"),
    )
    .await
    .unwrap()
    .unwrap();
    out.stdout().unwrap().lines().map(str::to_owned).collect()
}

struct Outcome {
    name: &'static str,
    reached: bool,
    code: i32,
    seen: Vec<String>,
    tail: String,
    secs: f32,
}

async fn tools_reach_the_fixture(env: &VmEnv) -> Result<Vec<Outcome>, HarnessError> {
    let config = guest_proxy_config(&ProxySettings::default(), &[]).unwrap();
    let builder = env
        .sandbox("guestenv", TOOLS_IMAGE)?
        .cpus(2)
        .memory(3072u32);
    env.scope(Box::pin(async {
        let started = Instant::now();
        let sb = within("create", CREATE_BUDGET, builder.create()).await??;
        eprintln!("create (pull + boot) {} s", started.elapsed().as_secs());

        let started = Instant::now();
        let setup = within(
            "setup",
            SETUP_BUDGET,
            sb.shell_with(SETUP, |e| {
                e.user("root")
                    .env("GRADLE_VERSION", GRADLE_VERSION)
                    .env("PNPM", PNPM)
                    .env("YARN_BERRY", YARN_BERRY)
                    .timeout(SETUP_BUDGET)
            }),
        )
        .await??;
        assert_eq!(
            setup.status().code,
            0,
            "tool setup failed:\n{}\n{}",
            setup.stdout().unwrap_or_default(),
            setup.stderr().unwrap_or_default()
        );
        eprintln!("setup {} s:\n{}", started.elapsed().as_secs(), setup.stdout().unwrap_or_default());

        for f in &config.files {
            write_file(&sb, f.path().as_str(), f.mode(), f.contents()).await;
        }
        write_file(&sb, "/tmp/fixture.js", 0o644, FIXTURE.as_bytes()).await;
        write_file(&sb, "/tmp/Fetch.java", 0o644, JAVA_FETCH.as_bytes()).await;
        let up = within(
            "fixture",
            STEP_BUDGET,
            sb.shell(
                "setsid node /tmp/fixture.js >/tmp/fixture.out 2>&1 </dev/null & \
                 for i in $(seq 50); do \
                   curl -s --noproxy '*' -o /dev/null http://127.0.0.1:3128/ready && exit 0; sleep 0.2; \
                 done; cat /tmp/fixture.out; exit 1",
            ),
        )
        .await??;
        assert_eq!(up.status().code, 0, "fixture: {:?}", up.stdout());

        let mut outcomes = Vec::new();
        for p in probes() {
            let before = fixture_log(&sb).await.len();
            let started = Instant::now();
            let (code, tail) = run(&sb, &config, &p.script).await;
            let secs = started.elapsed().as_secs_f32();
            let seen: Vec<String> = fixture_log(&sb).await.split_off(before);
            let reached = seen.iter().any(|l| p.hosts.iter().any(|h| l.contains(h)));
            outcomes.push(Outcome { name: p.name, reached, code, seen, tail, secs });
        }

        within("stop", STEP_BUDGET, sb.stop()).await??;
        within("remove", STEP_BUDGET, Sandbox::remove(sb.name())).await??;
        Ok(outcomes)
    }))
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_guest_env_tools_reach_the_proxy() {
    let env = VmEnv::from_env().await.expect("VM test environment");
    let result = Box::pin(tools_reach_the_fixture(&env)).await;
    let cleaned = Box::pin(env.cleanup()).await;
    let outcomes = result.expect("probes");

    eprintln!(
        "\n| probe | reached the proxy | exit | time | fixture saw | output tail |\n|---|---|---|---|---|---|"
    );
    for o in &outcomes {
        eprintln!(
            "| {} | {} | {} | {:.1} s | {} | {} |",
            o.name,
            if o.reached { "yes" } else { "**no**" },
            o.code,
            o.secs,
            o.seen.join("; "),
            o.tail.replace('|', "/")
        );
    }
    let failing: Vec<&str> = outcomes
        .iter()
        .filter(|o| !o.reached)
        .map(|o| o.name)
        .collect();
    let unexpected: Vec<&&str> = failing.iter().filter(|n| !KNOWN_GAPS.contains(n)).collect();
    let fixed: Vec<&&str> = KNOWN_GAPS.iter().filter(|n| !failing.contains(n)).collect();
    assert!(
        unexpected.is_empty(),
        "tools that did not reach the proxy: {unexpected:?}"
    );
    assert!(
        fixed.is_empty(),
        "known gaps that now work (remove them from KNOWN_GAPS): {fixed:?}"
    );

    cleaned.expect("cleanup");
    env.remove_home().await.expect("remove the private home");
}
