// SPDX-License-Identifier: GPL-3.0-or-later
//! Transparent capture on a real microVM (K on Linux KVM, W on Windows WHP), with no proxy
//! setting in play: the host's boot hook turns capture on, and tools that ignore proxy settings
//! reach the internet only the way a rule allows, by name or by address, through the agent and
//! the proxy.
//!
//! The first test is the battery from the spike's list that needs only what the workspace image
//! ships (`curl`, `bash`, `ssh`, `xargs`): a scrubbed environment, raw TCP, a direct address (a
//! deny row, then an approval and a retry with no restart), UDP and IPv6 failing at once, the
//! stub's answers, SSH refused with the message, 256 parallel fetches. The second is the
//! hostile one: a root process that deletes the capture rules gets nothing through, and the
//! agent puts them back.
//!
//! Every guest command runs as root through the runtime's exec, which carries the workspace's
//! proxy settings; the probes that must not use them say `env -i` or `--noproxy '*'`.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "VM test: a failed step fails the test"
)]

mod support;
mod vm_support;

use std::time::Duration;

use puddle_store::{Actor, Effect, NewRule, Pattern, Resolution, Scope};
use puddle_types::WorkspaceName;
use serde_json::json;
use support::{Api, ended};
use vm_support::{VmHost, guest, start_vm_host};

/// A public host that answers plain HTTP and HTTPS, and a small public repository to create the
/// workspace from.
const SITE: &str = "example.com";
const REPO_HOST: &str = "github.com";
const REPO: &str = "https://github.com/octocat/Hello-World.git";

/// Creates a workspace on `host` whose sandbox may reach `allowed` and returns its name.
async fn create_workspace(vm: &VmHost, api: &Api, tag: &str, allowed: &[&str]) -> WorkspaceName {
    let name = format!("{}-{tag}", vm.settings.prefix.as_str());
    let workspace = WorkspaceName::new(&name).unwrap();
    for site in allowed {
        vm.host
            .store()
            .add_rule(&NewRule {
                scope: Scope::Workspace(workspace.clone()),
                pattern: Pattern::parse(site).unwrap(),
                effect: Effect::Allow,
                expires_at: None,
                created_by: Actor::Cli,
            })
            .unwrap();
    }
    let mut events = api.events().await;
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let name: &'static str = Box::leak(name.into_boxed_str());
    let end = events.until(ended(name), Duration::from_secs(600)).await;
    assert_eq!(end["step"], "done", "{end}");
    workspace
}

/// A guest script's clock: `now` prints the milliseconds since the epoch.
const CLOCK: &str = "now() { local t=${EPOCHREALTIME/[.,]/}; echo $((t / 1000)); }";

/// `script` as a command that runs it with bash and an empty stdin (so no tool in it reads the
/// script), after [`CLOCK`], and always ends well: the test reads what it printed.
fn bash_script(script: &str) -> String {
    format!(
        "cat > /tmp/probe.sh <<'PUDDLE_EOF'\n{CLOCK}\n{script}\ntrue\nPUDDLE_EOF\nbash /tmp/probe.sh </dev/null"
    )
}

/// The value after `key=` on the first line of `text` that has it.
fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.split_whitespace().find_map(|w| w.strip_prefix(key)))
        .unwrap_or_else(|| panic!("no {key} in: {text}"))
}

/// The open inbox rows of `workspace`, as `host:port`.
fn open_rows(vm: &VmHost, workspace: &WorkspaceName) -> Vec<String> {
    vm.host
        .store()
        .open_pending(Some(workspace))
        .unwrap()
        .iter()
        .map(|r| format!("{}:{}", r.host, r.port))
        .collect()
}

/// Waits for the open row of `workspace` for `wanted` and returns its id.
async fn wait_for_row(
    vm: &VmHost,
    workspace: &WorkspaceName,
    wanted: &str,
) -> puddle_types::PendingId {
    for _ in 0..100 {
        let rows = vm.host.store().open_pending(Some(workspace)).unwrap();
        if let Some(row) = rows.iter().find(|r| r.host.to_string() == wanted) {
            return row.id;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no open row for {wanted}: {:?}", open_rows(vm, workspace));
}

/// The number of allowed connection records to `host:port` in the audit.
fn allowed_connections(vm: &VmHost, host: &str, port: u16) -> usize {
    vm.host
        .store()
        .audit_lines(0, 100_000)
        .unwrap()
        .iter()
        .filter(|(_, line)| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            record["type"] == "connection"
                && record["host"] == host
                && record["port"] == port
                && record["decision"] == "allow"
        })
        .count()
}

/// Waits until the audit holds more allowed connection records to `host:port` than `before`.
///
/// The proxy writes a connection's record when the connection ends, which is after the guest
/// tool that opened it has exited and the test has read its output, so reading the audit
/// right away races the proxy's write.
async fn wait_for_connection_record(vm: &VmHost, host: &str, port: u16, before: usize) {
    for _ in 0..200 {
        if allowed_connections(vm, host, port) > before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let lines: Vec<String> = vm
        .host
        .store()
        .audit_lines(0, 100_000)
        .unwrap()
        .into_iter()
        .map(|(_, line)| line)
        .filter(|line| line.contains(host))
        .collect();
    panic!("no connection record for {host}:{port} after 20 s; audit lines naming it: {lines:#?}");
}

/// With capture on from the boot and no proxy setting in the command, tools that never look at
/// one still work for what a rule allows and fail at once for the rest.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_capture_reaches_what_a_rule_allows_with_no_proxy_setting_and_refuses_the_rest_at_once()
{
    let vm = start_vm_host("capt").await;
    let api = Api::new(vm.host.url(), vm.host.token());
    let workspace = create_workspace(&vm, &api, "capt", &[REPO_HOST, SITE]).await;
    let run = |script: String| {
        let (runtime, workspace) = (&vm.runtime, &workspace);
        async move { guest(runtime, workspace, &bash_script(&script)).await }
    };

    // The boot wrote the stub's line first and kept the others.
    let resolv = run("head -1 /etc/resolv.conf; echo; cat /etc/resolv.conf".into()).await;
    eprintln!("{resolv}");
    assert!(resolv.starts_with("nameserver 198.18.0.1\n"), "{resolv}");

    // A tool with an empty environment: the name resolves to a stand-in through the stub, the
    // connection is redirected, and the host sees `CONNECT example.com:443`.
    let before = allowed_connections(&vm, SITE, 443);
    let scrubbed = run(format!(
        "env -i PATH=/usr/bin:/bin curl -sS -o /dev/null --max-time 30 \
         -w 'http=%{{http_code}} ip=%{{remote_ip}}\\n' https://{SITE}/ 2>&1; echo \"exit=$?\""
    ))
    .await;
    eprintln!("{scrubbed}");
    assert_eq!(field(&scrubbed, "http="), "200", "{scrubbed}");
    assert!(field(&scrubbed, "ip=").starts_with("198.1"), "{scrubbed}");
    wait_for_connection_record(&vm, SITE, 443, before).await;

    // Raw TCP: bash's /dev/tcp, no HTTP library, port 80.
    let raw = run(format!(
        "exec 3<>/dev/tcp/{SITE}/80 && printf 'GET / HTTP/1.0\\r\\nHost: {SITE}\\r\\n\\r\\n' >&3 \
         && IFS= read -r -t 20 line <&3; echo \"first-line=${{line%$'\\r'}}\""
    ))
    .await;
    eprintln!("{raw}");
    assert!(raw.contains("first-line=HTTP/1."), "{raw}");

    // A client that does use the proxy settings still works, and the stub answers lookups for
    // names nothing allows without any inbox row (the connect is what asks).
    let proxied = run(format!(
        "curl -sS -o /dev/null --max-time 30 -w 'http=%{{http_code}}\\n' https://{SITE}/ 2>&1"
    ))
    .await;
    assert_eq!(field(&proxied, "http="), "200", "{proxied}");
    let denied_name = run("getent hosts puddle-nothing-allows-this.example.net".into()).await;
    eprintln!("{denied_name}");
    assert!(denied_name.starts_with("198.1"), "{denied_name}");
    assert!(
        !open_rows(&vm, &workspace)
            .iter()
            .any(|r| r.contains("puddle-nothing-allows-this")),
        "a lookup alone made an inbox row: {:?}",
        open_rows(&vm, &workspace)
    );

    // HG-01 rerun: a direct address nothing allows is a deny row, never a way around the proxy.
    // Approve it, and the retry works with no restart.
    let direct = |label: &str| {
        run(format!(
            "s=$(now); curl --noproxy '*' -sS -k -o /dev/null --connect-timeout 10 --max-time 20 \
             -w 'http=%{{http_code}}\\n' https://1.1.1.1/ 2>&1; echo \"{label} exit=$? ms=$(($(now) - s))\""
        ))
    };
    let refused = direct("first").await;
    eprintln!("{refused}");
    assert!(!refused.contains("exit=0 "), "{refused}");
    assert!(
        field(&refused, "ms=").parse::<u64>().unwrap() < 5000,
        "{refused}"
    );
    let id = wait_for_row(&vm, &workspace, "1.1.1.1").await;
    vm.host
        .store()
        .resolve_pending(id, &Resolution::allow(), Actor::Cli)
        .unwrap();
    let approved = direct("retry").await;
    eprintln!("{approved}");
    assert!(approved.contains("retry exit=0 "), "{approved}");
    assert_ne!(field(&approved, "http="), "000", "{approved}");

    // UDP (not DNS) and IPv6 literals fail at once, with a refusal and not a timeout.
    let fast = run(
        r#"for t in 1.1.1.1 192.0.2.5 198.18.0.9; do
             s=$(now); if (echo x > /dev/udp/$t/123) 2>/dev/null; then r=sent; else r=failed; fi
             echo "udp $t $r ms=$(($(now) - s))"
           done
           s=$(now)
           if timeout 10 bash -c 'echo > /dev/tcp/2606:4700:4700::1111/443' 2>/dev/null; then r=connected; else r=failed; fi
           echo "v6 $r ms=$(($(now) - s))""#
            .into(),
    )
    .await;
    eprintln!("{fast}");
    for line in fast.lines().filter(|l| l.starts_with("udp ")) {
        assert!(line.contains(" failed "), "{fast}");
        assert!(field(line, "ms=").parse::<u64>().unwrap() < 100, "{fast}");
    }
    let v6 = fast.lines().find(|l| l.starts_with("v6 ")).unwrap();
    assert!(v6.contains(" failed "), "{fast}");
    assert!(field(v6, "ms=").parse::<u64>().unwrap() < 1000, "{fast}");

    // SSH from a client that ignores ssh_config is refused with the message, and never asks. The
    // message goes out as a line ahead of the identification string; OpenSSH shows such lines only
    // at debug level (`-v`), and at the default level says just "Connection closed".
    let ssh = run(
        "ssh -v -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=20 \
         -T git@github.com 2>&1; echo \"exit=$?\""
            .into(),
    )
    .await;
    eprintln!("{ssh}");
    assert!(ssh.contains("SSH is not supported yet"), "{ssh}");
    assert!(
        !open_rows(&vm, &workspace)
            .iter()
            .any(|r| r.ends_with(":22")),
        "a captured SSH client made an inbox row: {:?}",
        open_rows(&vm, &workspace)
    );

    // 256 fetches in parallel from a scrubbed environment: none fails, none stalls.
    let parallel = run(format!(
        "seq 256 | xargs -P 32 -I{{}} env -i PATH=/usr/bin:/bin curl -sS -o /dev/null --max-time 30 \
         -w '%{{http_code}} %{{time_total}}\\n' http://{SITE}/ > /tmp/parallel.txt 2>&1
         echo \"ok=$(grep -c '^200 ' /tmp/parallel.txt) lines=$(wc -l < /tmp/parallel.txt) \
         slowest=$(awk '{{print $2}}' /tmp/parallel.txt | sort -n | tail -1)\"
         grep -v '^200 ' /tmp/parallel.txt | head -5"
    ))
    .await;
    eprintln!("{parallel}");
    assert_eq!(field(&parallel, "ok="), "256", "{parallel}");
    let slowest: f64 = field(&parallel, "slowest=").parse().unwrap();
    assert!(slowest < 5.0, "a fetch took {slowest} s: {parallel}");

    let down = vm.host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// EG-4: capture is not enforcement, so a root process that deletes the rules gets nothing new
/// through (the VM has no route of its own), and the agent puts the rules back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_capture_survives_a_root_that_deletes_the_rules() {
    let vm = start_vm_host("flush").await;
    let api = Api::new(vm.host.url(), vm.host.token());
    let workspace = create_workspace(
        &vm,
        &api,
        "flush",
        &[REPO_HOST, SITE, "deb.debian.org", "security.debian.org"],
    )
    .await;
    let run = |script: String| {
        let (runtime, workspace) = (&vm.runtime, &workspace);
        async move { guest(runtime, workspace, &bash_script(&script)).await }
    };

    // The image ships no nft; the test brings one, through the proxy, as any tool would.
    let installed = run("export DEBIAN_FRONTEND=noninteractive
         apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq nftables >/dev/null 2>&1
         command -v nft || echo 'no nft'"
        .into())
    .await;
    assert!(installed.trim_end().ends_with("/nft"), "{installed}");

    for attack in ["nft flush ruleset", "nft delete table inet puddle"] {
        let out = run(format!(
            "nft list table inet puddle >/dev/null 2>&1 && echo before=present || echo before=absent
             {attack}
             echo \"after-attack=$(nft list table inet puddle >/dev/null 2>&1 && echo present || echo absent)\"
             curl --noproxy '*' -sS -k -o /dev/null --connect-timeout 3 --max-time 8 \
               -w 'http=%{{http_code}}\\n' http://1.0.0.1/ 2>&1
             for i in 1 2 3 4 5 6 7 8 9 10; do
               nft list table inet puddle >/dev/null 2>&1 && break
               sleep 0.5
             done
             echo \"restored=$(nft list table inet puddle >/dev/null 2>&1 && echo yes || echo no)\"
             env -i PATH=/usr/bin:/bin curl -sS -o /dev/null --max-time 30 \
               -w 'again http=%{{http_code}}\\n' http://{SITE}/ 2>&1"
        ))
        .await;
        eprintln!("{attack}: {out}");
        assert!(out.contains("before=present"), "{attack}: {out}");
        // Whether the agent had put the rules back by the time curl ran or not, an address no
        // rule allows never answered: it is a deny row or no route.
        assert_eq!(field(&out, "http="), "000", "{attack}: {out}");
        assert!(out.contains("restored=yes"), "{attack}: {out}");
        assert!(out.contains("again http=200"), "{attack}: {out}");
    }
    assert!(
        allowed_connections(&vm, "1.0.0.1", 80) == 0,
        "a connection to 1.0.0.1 was allowed"
    );

    let down = vm.host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}
