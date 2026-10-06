// SPDX-License-Identifier: GPL-3.0-or-later
//! The adapter's own VM bars (T-106), beyond the contract suite: HG-01 (no direct network from
//! the guest), HG-02 (only the routed vsock port reaches the host), ext4 volumes and owned disks,
//! three sandboxes at once with their own routes, `--max-memory` never set, and (fork, T-117) SSH
//! reporting a signal-killed command as a failure.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "VM test helpers: a failed step fails the test"
)]

mod support;

use std::path::Path;
use std::time::Duration;

use microsandbox::Sandbox as SdkSandbox;
use puddle_compute::{
    DiskSize, ExecOutput, ExecRequest, FileMount, OwnedDisk, Runtime, Sandbox, SandboxSpec,
    VolumeMount, VsockRoute,
};
use puddle_compute_msb::MsbRuntime;
use puddle_ipc::{IpcRoot, Listener};
use puddle_types::{GuestPath, ImageRef, MemoryMib, SandboxName, VolumeName};
use puddle_vm_tests::{DEBIAN_DEVCONTAINER, Settings, VmEnv};
use tokio::io::AsyncReadExt;

/// The guest port puddle routes (T-020 C-5).
const ROUTE_PORT: u32 = 5000;

/// Connects to host CID 2 on each port given and prints the ones that accepted. perl-base is
/// in every Debian image and can open an `AF_VSOCK` socket by number.
const VSOCK_PROBE: &str = r#"
use strict; use Socket;
my $msg = shift @ARGV;
for my $port (@ARGV) {
  socket(my $s, 40, SOCK_STREAM, 0) or die "socket: $!";
  my $ok = eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 3;
    my $r = connect($s, pack("S S L L x4", 40, 0, $port, 2));
    alarm 0;
    $r;
  };
  if ($ok) {
    select((select($s), $| = 1)[0]);
    print {$s} "$msg\n"; print "$port\n";
    # Linger before closing: msb on Windows can lose the last bytes of a stream the guest closes
    # at once (tail loss, T-119), which is not what this probe tests.
    select(undef, undef, undef, 0.3);
  }
  close $s;
}
"#;

fn name(settings: &Settings, tag: &str) -> SandboxName {
    SandboxName::new(&format!("{}-{tag}", settings.prefix)).unwrap()
}

fn path(p: &str) -> GuestPath {
    GuestPath::new(p).unwrap()
}

fn spec(settings: &Settings, tag: &str) -> SandboxSpec {
    SandboxSpec::new(
        name(settings, tag),
        ImageRef::new(DEBIAN_DEVCONTAINER).unwrap(),
    )
    .with_memory(MemoryMib::new(512).unwrap())
}

async fn sh<S: Sandbox>(sb: &S, script: &str) -> ExecOutput {
    sb.exec(ExecRequest::sh(script).as_user("root"))
        .await
        .expect("exec")
}

/// Runs [`VSOCK_PROBE`] for `ports` and returns the ports that accepted.
async fn vsock_accepting<S: Sandbox>(sb: &S, message: &str, ports: &[u32]) -> Vec<u32> {
    let mut args = vec!["-e".to_owned(), VSOCK_PROBE.to_owned(), message.to_owned()];
    args.extend(ports.iter().map(u32::to_string));
    let out = sb
        .exec(
            ExecRequest::new("perl", args)
                .as_user("root")
                .with_timeout(Duration::from_secs(600)),
        )
        .await
        .expect("vsock probe");
    assert_eq!(out.status.code, 0, "probe failed: {}", out.stderr_text());
    out.stdout_text()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect()
}

/// Accepts connections on `listener` and returns the first line of each.
fn collect_lines(mut listener: Listener) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut lines = Vec::new();
        while let Ok(Ok(mut conn)) =
            tokio::time::timeout(Duration::from_secs(20), listener.accept()).await
        {
            let mut buf = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut buf)).await;
            lines.push(String::from_utf8_lossy(&buf).trim_end().to_owned());
        }
        lines
    })
}

async fn cleanup(rt: &MsbRuntime, names: &[&SandboxName]) {
    for n in names {
        if let Ok(sb) = rt.get(n).await {
            let _ = sb.stop().await;
        }
        let _ = rt.remove(n).await;
    }
}

/// HG-01: no network interface is up but loopback (msb's guest kernel has a `dummy0` sink
/// device, down), and direct DNS, IPv4 TCP, UDP and IPv6 all fail. Loopback works (the agent
/// listens on 127.0.0.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_hg01_guest_has_no_direct_network() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let s = spec(&settings, "hg01");
    let n = s.name.clone();
    let sb = rt.create(s).await.expect("create");
    let script = r#"
fail=0
for i in /sys/class/net/*; do
  n=${i##*/}; [ "$n" = lo ] && continue
  # Only loopback may be up; the kernel's dummy0 (a sink device) may exist, down.
  flags=$(cat "$i/flags"); [ $((flags & 1)) -eq 0 ] || { echo "interface $n is up"; fail=1; }
done
timeout 5 getent hosts github.com && { echo "DNS resolved"; fail=1; }
timeout 5 bash -c 'echo > /dev/tcp/140.82.121.4/443' && { echo "direct IPv4 TCP connected"; fail=1; }
timeout 5 bash -c 'echo > /dev/udp/1.1.1.1/53' && { echo "direct UDP sent"; fail=1; }
timeout 5 bash -c 'echo > /dev/tcp/2606:4700:4700::1111/443' && { echo "direct IPv6 connected"; fail=1; }
out=$(timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/1' 2>&1)
case "$out" in *refused*) ;; *) echo "loopback unusable: $out"; fail=1 ;; esac
exit $fail
"#;
    let out = sh(&sb, script).await;
    eprintln!("{}{}", out.stdout_text(), out.stderr_text());
    sb.stop().await.unwrap();
    cleanup(&rt, &[&n]).await;
    assert_eq!(out.status.code, 0, "{}", out.stdout_text());
}

/// HG-02: of a sweep over guest-to-host vsock ports, only the routed one accepts, and what the
/// guest sends arrives on puddle's endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_hg02_only_the_routed_vsock_port_accepts() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let root = IpcRoot::new().unwrap();
    let listener = root.listen().unwrap();
    let s =
        spec(&settings, "hg02").with_route(VsockRoute::new(ROUTE_PORT, listener.endpoint().path()));
    let n = s.name.clone();
    let lines = collect_lines(listener);
    let sb = rt.create(s).await.expect("create");
    let mut ports: Vec<u32> = (1..=1100).collect();
    ports.extend(4990..=5010);
    ports.extend([8080, 9000, 10_000, 49_152, 65_535, u32::MAX - 1]);
    let accepted = vsock_accepting(&sb, "hello-hg02", &ports).await;
    sb.stop().await.unwrap();
    cleanup(&rt, &[&n]).await;
    assert_eq!(accepted, [ROUTE_PORT], "ports that accepted");
    assert_eq!(lines.await.unwrap(), ["hello-hg02"]);
}

/// Named volumes and owned disks are ext4 in the guest (T-028 `volume.ext4`, `owned_disk.ext4`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_volume_and_owned_disk_are_ext4() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let vol = VolumeName::new(&format!("{}-ext4", settings.prefix)).unwrap();
    let s = spec(&settings, "ext4")
        .with_volume(
            VolumeMount::named(vol.clone(), path("/workspaces/ws")).ensure_size(DiskSize::mib(256)),
        )
        .with_owned_disk(OwnedDisk {
            guest: path("/var/lib/docker"),
            size: DiskSize::mib(256),
        });
    let n = s.name.clone();
    let sb = rt.create(s).await.expect("create");
    let out = sh(
        &sb,
        r#"awk '$2 == "/workspaces/ws" || $2 == "/var/lib/docker" { print $2, $3 }' /proc/mounts | sort"#,
    )
    .await;
    sb.stop().await.unwrap();
    cleanup(&rt, &[&n]).await;
    let _ = rt.remove_volume(&vol).await;
    assert_eq!(
        out.stdout_text(),
        "/var/lib/docker ext4\n/workspaces/ws ext4\n"
    );
}

/// Three sandboxes at once, each with its own route and file mount: every one runs commands,
/// keeps its mount read-only, and what it sends arrives on its own endpoint only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_three_sandboxes_at_once_each_with_its_own_route() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let root = IpcRoot::new().unwrap();
    let share = rt.config().guest_share.join("three");
    std::fs::create_dir_all(&share).unwrap();
    let mut specs = Vec::new();
    let mut collectors = Vec::new();
    for i in 0..3 {
        let listener = root.listen().unwrap();
        let file = share.join(format!("id-{i}"));
        std::fs::write(&file, format!("sandbox-{i}\n")).unwrap();
        let s = spec(&settings, &format!("three-{i}"))
            .with_route(VsockRoute::new(ROUTE_PORT, listener.endpoint().path()))
            .with_file_mount(FileMount::read_only(&file, path("/puddle/id")));
        collectors.push(collect_lines(listener));
        specs.push(s);
    }
    let names: Vec<SandboxName> = specs.iter().map(|s| s.name.clone()).collect();
    let mut specs = specs.into_iter();
    let (a, b, c) = tokio::join!(
        rt.create(specs.next().unwrap()),
        rt.create(specs.next().unwrap()),
        rt.create(specs.next().unwrap()),
    );
    let sandboxes = [
        a.expect("create 0"),
        b.expect("create 1"),
        c.expect("create 2"),
    ];
    let mut failures = Vec::new();
    for (i, sb) in sandboxes.iter().enumerate() {
        let id = sh(sb, "cat /puddle/id").await.stdout_text().into_owned();
        if id != format!("sandbox-{i}\n") {
            failures.push(format!("{i}: mount reads {id:?}"));
        }
        if sh(sb, "exit 3").await.status.code != 3 {
            failures.push(format!("{i}: exit code lost"));
        }
        let write = sh(sb, "echo x > /puddle/id").await;
        if !write.stderr_text().contains("Read-only file system") {
            failures.push(format!("{i}: mount writable: {}", write.stderr_text()));
        }
        let accepted = vsock_accepting(sb, &format!("from-{i}"), &[ROUTE_PORT]).await;
        if accepted != [ROUTE_PORT] {
            failures.push(format!("{i}: route refused"));
        }
    }
    for sb in &sandboxes {
        sb.stop().await.unwrap();
    }
    cleanup(&rt, &names.iter().collect::<Vec<_>>()).await;
    for (i, collector) in collectors.into_iter().enumerate() {
        let lines = collector.await.unwrap();
        if lines != [format!("from-{i}")] {
            failures.push(format!("{i}: endpoint got {lines:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The created sandbox has `--memory` from the spec and no hotplug reserve (msb stores
/// max-memory = memory when it isn't set); a memory change, up or down, is persisted for the
/// next start and keeps max-memory equal to memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_memory_is_set_and_max_memory_never() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let harness = VmEnv::new(settings.clone()).await.unwrap();
    let s = spec(&settings, "mem");
    let n = s.name.clone();
    let sb = rt.create(s).await.expect("create");
    let harness = &harness;
    let resources = |name: String| async move {
        let handle = harness
            .scope(Box::pin(SdkSandbox::get(&name)))
            .await
            .unwrap();
        let config = handle.config().unwrap();
        (
            config.spec.resources.memory_mib,
            config.spec.resources.max_memory_mib,
        )
    };
    let created = resources(n.to_string()).await;
    rt.set_memory(&n, MemoryMib::new(768).unwrap())
        .await
        .unwrap();
    let raised = resources(n.to_string()).await;
    sb.stop().await.unwrap();
    rt.set_memory(&n, MemoryMib::new(384).unwrap())
        .await
        .unwrap();
    let lowered = resources(n.to_string()).await;
    cleanup(&rt, &[&n]).await;
    assert_eq!(created, (512, 512), "(memory, max memory) after create");
    assert_eq!(raised, (768, 768), "(memory, max memory) after raising it");
    assert_eq!(
        lowered,
        (384, 384),
        "(memory, max memory) after lowering it"
    );
}

/// A mount source outside the guest-share root is refused before anything is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_mount_sources_outside_the_share_are_refused() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let outside = settings.home().join("config.json");
    assert!(Path::new(&outside).is_file());
    let s = spec(&settings, "c7").with_file_mount(FileMount::read_only(&outside, path("/x")));
    let n = s.name.clone();
    let err = rt.create(s).await.unwrap_err();
    assert!(
        err.to_string().contains("outside the guest-share root"),
        "{err}"
    );
    assert!(
        rt.list()
            .await
            .unwrap()
            .iter()
            .all(|i| i.name != n.as_str())
    );
}

/// The fork's SSH server (SDK, in puddle's process) reports a signal-killed command as a failure:
/// it sends no exit status, so OpenSSH exits 255 and the SDK client reads `-1`; a normal exit
/// code still arrives as is (msb fork `359f1585`, T-028 `ssh.signal_kill9_exit`). The reason
/// [`puddle_compute::Capabilities::ssh_reports_signal_exit`] is `true` on the fork.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ssh_reports_a_signal_killed_command_as_a_failure() {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let harness = VmEnv::new(settings.clone()).await.unwrap();
    let s = spec(&settings, "sshsig");
    let n = s.name.clone();
    let sb = rt.create(s).await.expect("create");
    let statuses = harness
        .scope(Box::pin(async {
            let live = SdkSandbox::get(n.as_str()).await?.connect().await?;
            let client = live.ssh().open_client().await?;
            let killed = client.exec("kill -9 $$").await?.status;
            let seven = client.exec("exit 7").await?.status;
            client.close().await?;
            Ok::<_, microsandbox::MicrosandboxError>((killed, seven))
        }))
        .await;
    assert!(rt.probe().await.unwrap().ssh_reports_signal_exit);
    sb.stop().await.unwrap();
    cleanup(&rt, &[&n]).await;
    let (killed, seven) = statuses.expect("SSH exec through the SDK client");
    assert_eq!(
        killed, -1,
        "a signal-killed command must not report a status"
    );
    assert_eq!(seven, 7, "a normal exit code is reported as is");
}
