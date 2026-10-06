// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle ssh-bridge` as `ssh` runs it: the built binary as the `ProxyCommand`.
//!
//! On Unix the endpoint serves each client with a real OpenSSH server (`sshd -i`, as the test
//! user, standing in for msb's server), so real `ssh`, `scp`, `sftp` and `-L` run through the
//! bridge and the endpoint. The same with Windows OpenSSH and msb is the VM bar (T-114 brief).
#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::process::Command;

fn puddle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_puddle"))
        .args(args)
        .output()
        .expect("the puddle binary runs")
}

#[test]
fn without_an_endpoint_it_is_a_usage_error() {
    let out = puddle(&["ssh-bridge"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("missing argument: ssh-bridge <endpoint>"),
        "{stderr}"
    );
}

#[test]
fn a_missing_endpoint_fails_with_a_message_on_stderr() {
    let gone = if cfg!(windows) {
        r"\\.\pipe\puddle-t114-nothing-listens-here".to_owned()
    } else {
        let dir = tempfile::tempdir().unwrap();
        dir.path().join("gone.sock").display().to_string()
    };
    let out = puddle(&["ssh-bridge", &gone]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!("puddle: no puddle SSH endpoint at {gone}")),
        "{stderr}"
    );
}

#[cfg(unix)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]
mod openssh {
    use std::path::{Path, PathBuf};
    use std::process::{Output, Stdio};
    use std::sync::Arc;
    use std::time::Duration;

    use puddle_compute::SshStream;
    use puddle_ipc::IpcRoot;
    use puddle_ssh::{SshEndpoint, SshTarget};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::process::Command;
    use tokio::time::timeout;

    const SSHD: &str = "/usr/sbin/sshd";
    const WAIT: Duration = Duration::from_secs(60);

    /// Serves each client with its own `sshd -i` (inetd mode: SSH on stdin/stdout).
    struct Sshd {
        config: PathBuf,
    }

    impl SshTarget for Sshd {
        type Error = std::io::Error;

        fn label(&self) -> String {
            "sshd".into()
        }

        fn admit(&self) -> impl Future<Output = Result<(), String>> {
            std::future::ready(Ok(()))
        }

        async fn serve<S: SshStream>(&self, stream: S) -> Result<(), std::io::Error> {
            let mut child = Command::new(SSHD)
                .arg("-i")
                .arg("-f")
                .arg(&self.config)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            let mut to_sshd = child.stdin.take().unwrap();
            let mut from_sshd = child.stdout.take().unwrap();
            let (mut rd, mut wr) = tokio::io::split(stream);
            let up = async {
                let _ignored = tokio::io::copy(&mut rd, &mut to_sshd).await;
                drop(to_sshd);
            };
            let down = async {
                tokio::io::copy(&mut from_sshd, &mut wr).await?;
                wr.shutdown().await
            };
            // The session ends when sshd's output does, as it does with msb's server.
            tokio::select! {
                () = up => {}
                r = down => r?,
            }
            child.wait().await?;
            Ok(())
        }
    }

    struct Rig {
        dir: tempfile::TempDir,
        endpoint: SshEndpoint,
        config: PathBuf,
    }

    async fn keygen(path: &Path) {
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t114", "-f"])
            .arg(path)
            .status()
            .await
            .expect("ssh-keygen runs");
        assert!(st.success());
    }

    async fn rig() -> Rig {
        assert!(
            Path::new(SSHD).exists(),
            "{SSHD} is missing: these tests need OpenSSH's server (package openssh-server)"
        );
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        keygen(&d.join("host")).await;
        keygen(&d.join("id")).await;
        std::fs::copy(d.join("id.pub"), d.join("authorized_keys")).unwrap();
        let sshd_config = d.join("sshd_config");
        std::fs::write(
            &sshd_config,
            format!(
                "HostKey {host}\nAuthorizedKeysFile {ak}\nStrictModes no\nUsePAM no\n\
                 PidFile none\nSubsystem sftp internal-sftp\nAllowTcpForwarding yes\n\
                 LogLevel ERROR\n",
                host = d.join("host").display(),
                ak = d.join("authorized_keys").display(),
            ),
        )
        .unwrap();
        let root = IpcRoot::new().unwrap();
        let endpoint = SshEndpoint::start(
            root.listen().unwrap(),
            Arc::new(Sshd {
                config: sshd_config,
            }),
        )
        .unwrap();
        let config = d.join("ssh_config");
        std::fs::write(
            &config,
            format!(
                "Host box\n  User {user}\n  ProxyCommand \"{puddle}\" ssh-bridge \"{endpoint}\"\n  \
                 IdentityFile {id}\n  IdentitiesOnly yes\n  IdentityAgent none\n  \
                 UserKnownHostsFile {kh}\n  StrictHostKeyChecking accept-new\n  BatchMode yes\n  \
                 LogLevel ERROR\n",
                user = whoami(),
                puddle = env!("CARGO_BIN_EXE_puddle"),
                endpoint = endpoint.endpoint().path().display(),
                id = d.join("id").display(),
                kh = d.join("known_hosts").display(),
            ),
        )
        .unwrap();
        Rig {
            dir,
            endpoint,
            config,
        }
    }

    fn whoami() -> String {
        let out = std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    async fn run(program: &str, args: &[&str]) -> Output {
        timeout(
            WAIT,
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap_or_else(|_| panic!("{program} {args:?} timed out"))
        .unwrap()
    }

    fn cfg(rig: &Rig) -> &str {
        rig.config.to_str().unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ssh_exit_codes_come_through() {
        let rig = rig().await;
        let ok = run("ssh", &["-F", cfg(&rig), "box", "echo hello"]).await;
        assert_eq!(ok.status.code(), Some(0), "{ok:?}");
        assert_eq!(ok.stdout, b"hello\n");
        let seven = run("ssh", &["-F", cfg(&rig), "box", "exit 7"]).await;
        assert_eq!(seven.status.code(), Some(7), "{seven:?}");
        rig.endpoint.close().await;
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 7).to_le_bytes()[0])
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn scp_and_sftp_copy_files_both_ways() {
        let rig = rig().await;
        let d = rig.dir.path();
        let data = payload(8 * 1024 * 1024);
        let src = d.join("src.bin");
        std::fs::write(&src, &data).unwrap();
        let s = |p: &Path| p.to_str().unwrap().to_owned();
        // scp over SFTP (the default) and over the legacy protocol.
        for (flags, name) in [(vec![], "scp"), (vec!["-O"], "scp-legacy")] {
            let up = d.join(format!("{name}-up.bin"));
            let back = d.join(format!("{name}-back.bin"));
            let mut args = vec!["-F", cfg(&rig), "-q"];
            args.extend(flags.iter().copied());
            let remote_up = format!("box:{}", s(&up));
            let o = run("scp", &[&args[..], &[&s(&src), &remote_up]].concat()).await;
            assert_eq!(o.status.code(), Some(0), "{name} up: {o:?}");
            let o = run("scp", &[&args[..], &[&remote_up, &s(&back)]].concat()).await;
            assert_eq!(o.status.code(), Some(0), "{name} down: {o:?}");
            assert!(
                std::fs::read(&back).unwrap() == data,
                "{name} changed the file"
            );
        }
        let batch = d.join("batch");
        let (put, got) = (d.join("sftp-put.bin"), d.join("sftp-got.bin"));
        std::fs::write(
            &batch,
            format!("put {} {}\nget {} {}\n", s(&src), s(&put), s(&put), s(&got)),
        )
        .unwrap();
        let o = run("sftp", &["-F", cfg(&rig), "-q", "-b", &s(&batch), "box"]).await;
        assert_eq!(o.status.code(), Some(0), "sftp: {o:?}");
        assert!(
            std::fs::read(&got).unwrap() == data,
            "sftp changed the file"
        );
        rig.endpoint.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_local_forward_carries_data_both_ways() {
        let rig = rig().await;
        // The "guest" service: an echo server.
        let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = service.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ignored = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let local_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let forward = format!("{local_port}:127.0.0.1:{service_port}");
        let mut ssh = Command::new("ssh")
            .args([
                "-F",
                cfg(&rig),
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
            ])
            .arg(&forward)
            .arg("box")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut conn = timeout(WAIT, async {
            loop {
                if let Ok(c) = TcpStream::connect(("127.0.0.1", local_port)).await {
                    break c;
                }
                assert!(ssh.try_wait().unwrap().is_none(), "ssh -L exited early");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let data = payload(1024 * 1024);
        let (mut r, mut w) = conn.split();
        let mut back = vec![0_u8; data.len()];
        let ((), ()) = timeout(WAIT, async {
            tokio::join!(async { w.write_all(&data).await.unwrap() }, async {
                r.read_exact(&mut back).await.unwrap();
            })
        })
        .await
        .unwrap();
        assert!(back == data, "the forward changed the data");
        ssh.kill().await.unwrap();
        rig.endpoint.close().await;
    }
}
