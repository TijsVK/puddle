// SPDX-License-Identifier: GPL-3.0-or-later
use std::io::Write;
use std::path::PathBuf;

use proptest::prelude::*;

use super::*;

#[expect(
    clippy::unnecessary_wraps,
    reason = "compared with parse results, which are Options"
)]
fn kill(pid: u32, process: &str) -> Option<Kill> {
    Some(Kill {
        pid,
        process: process.into(),
    })
}

#[test]
fn global_and_memcg_kill_lines_are_parsed() {
    assert_eq!(
        parse_kmsg_record(
            "3,1,2,-;Out of memory: Killed process 2406 (tail) total-vm:7280204kB, anon-rss:7274112kB, file-rss:0kB\n"
        ),
        kill(2406, "tail")
    );
    assert_eq!(
        parse_kmsg_record(
            "3,99,123456,-,caller=T42;Memory cgroup out of memory: Killed process 77 (node) total-vm:1kB\n SUBSYSTEM=memory\n"
        ),
        kill(77, "node")
    );
    // Older kernels: no total-vm field after the name.
    assert_eq!(
        parse_kmsg_record("0,5,6,-;Killed process 9 (a b)\n"),
        kill(9, "a b")
    );
}

#[test]
fn a_name_with_parentheses_and_spaces_is_kept_whole() {
    assert_eq!(
        parse_kmsg_record("3,1,2,-;Out of memory: Killed process 5 (x) (y) total-vm:1kB\n"),
        kill(5, "x) (y")
    );
}

#[test]
fn records_that_are_not_kernel_kill_lines_are_ignored() {
    for record in [
        // Userspace writes to /dev/kmsg never get facility 0 (here user.err = 11).
        "11,1,2,-;Out of memory: Killed process 1 (fake) total-vm:1kB\n",
        "3,1,2,-;oom_reaper: reaped process 2406 (tail), now anon-rss:0kB\n",
        "3,1,2,-;Killed process x (tail) total-vm:1kB\n",
        "3,1,2,-;Killed process 1 tail\n",
        "3,1,2,-;Killed process 1 (tail\n",
        "3,1,2,-;Killed process 1\n",
        "no header here Killed process 1 (a)\n",
        "x,1,2,-;Killed process 1 (a)\n",
        "6,2,3,-;eth0: link up\n",
        " SUBSYSTEM=memory\n",
        "",
    ] {
        assert_eq!(parse_kmsg_record(record), None, "{record:?}");
    }
    // A kill line only in a continuation line doesn't count either.
    assert_eq!(
        parse_kmsg_record("6,1,2,-;hello\n Killed process 1 (a)\n"),
        None
    );
}

#[test]
fn the_vmstat_counter_is_found_or_missing() {
    assert_eq!(
        parse_vmstat("nr_free_pages 1\noom_kill 12\nx 3\n"),
        Some(12)
    );
    assert_eq!(parse_vmstat("nr_free_pages 1\n"), None);
    assert_eq!(parse_vmstat("oom_kill lots\n"), None);
    assert_eq!(parse_vmstat("oom_kill_other 3\n"), None);
}

proptest! {
    #[test]
    fn any_record_parses_or_is_ignored_without_panicking(s in "\\PC{0,200}") {
        let _ = parse_kmsg_record(&s);
        let _ = parse_vmstat(&s);
    }

    #[test]
    fn a_formatted_kill_line_round_trips(pid in any::<u32>(), name in "[a-zA-Z0-9_./ ()-]{1,15}") {
        let record = format!("3,7,8,-;Out of memory: Killed process {pid} ({name}) total-vm:10kB, anon-rss:1kB\n");
        prop_assert_eq!(parse_kmsg_record(&record), kill(pid, &name));
    }
}

#[test]
fn a_kill_logged_first_then_counted_is_reported_once() {
    let t0 = Instant::now();
    let mut c = Correlator::new(Duration::from_secs(1));
    c.on_logged();
    c.on_counted(1, t0);
    assert_eq!(c.due(t0 + Duration::from_secs(10)), 0);
}

#[test]
fn a_kill_counted_first_then_logged_is_reported_once() {
    let t0 = Instant::now();
    let mut c = Correlator::new(Duration::from_secs(1));
    c.on_counted(1, t0);
    assert_eq!(c.due(t0), 0);
    c.on_logged();
    assert_eq!(c.due(t0 + Duration::from_secs(10)), 0);
}

#[test]
fn a_counted_kill_without_a_log_line_is_due_after_the_grace_period() {
    let t0 = Instant::now();
    let mut c = Correlator::new(Duration::from_secs(1));
    c.on_counted(3, t0);
    c.on_logged();
    assert_eq!(c.due(t0 + Duration::from_millis(999)), 0);
    c.on_counted(1, t0 + Duration::from_millis(500));
    assert_eq!(c.due(t0 + Duration::from_secs(1)), 2);
    assert_eq!(c.due(t0 + Duration::from_millis(1500)), 1);
    assert_eq!(c.due(t0 + Duration::from_secs(9)), 0);
}

#[test]
fn log_lines_ahead_of_the_counter_claim_later_increases() {
    let t0 = Instant::now();
    let mut c = Correlator::new(Duration::ZERO);
    c.on_logged();
    c.on_logged();
    c.on_counted(3, t0);
    assert_eq!(c.due(t0), 1);
}

/// A temp dir with a fake `vmstat` and `kmsg`, removed on drop.
struct Fake {
    dir: PathBuf,
}

impl Fake {
    fn new(tag: &str, counter: u64) -> Self {
        let dir =
            std::env::temp_dir().join(format!("puddle-agent-oom-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = Self { dir };
        fake.set_counter(counter);
        std::fs::write(fake.kmsg(), "6,1,1,-;old boot noise\n3,2,2,-;Out of memory: Killed process 1 (before) total-vm:1kB\n").unwrap();
        fake
    }
    fn vmstat(&self) -> PathBuf {
        self.dir.join("vmstat")
    }
    fn kmsg(&self) -> PathBuf {
        self.dir.join("kmsg")
    }
    fn set_counter(&self, n: u64) {
        std::fs::write(self.vmstat(), format!("pgfault 1\noom_kill {n}\n")).unwrap();
    }
    fn log(&self, record: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.kmsg())
            .unwrap();
        f.write_all(record.as_bytes()).unwrap();
    }
    fn sources(&self) -> OomSources {
        OomSources {
            vmstat: self.vmstat(),
            kmsg: self.kmsg(),
            poll: Duration::from_millis(20),
            grace: Duration::from_millis(200),
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn next(rx: &mut mpsc::Receiver<AgentMessage>, within: Duration) -> Option<AgentMessage> {
    tokio::time::timeout(within, rx.recv()).await.ok().flatten()
}

#[tokio::test]
async fn watch_reports_a_logged_kill_once_with_its_name_and_nothing_from_before_it_started() {
    let fake = Fake::new("named", 5);
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(watch(fake.sources(), tx));
    // Nothing yet: the counter's baseline is 5 and the old log line is skipped.
    assert_eq!(next(&mut rx, Duration::from_millis(300)).await, None);

    fake.set_counter(6);
    fake.log("3,3,3,-;Out of memory: Killed process 4242 (hog) total-vm:9kB\n");
    assert_eq!(
        next(&mut rx, Duration::from_secs(2)).await,
        Some(AgentMessage::oom_kill(Some(4242), Some("hog".into())))
    );
    // The counter increase was claimed by the log line: no unnamed report follows.
    assert_eq!(next(&mut rx, Duration::from_millis(500)).await, None);
    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn watch_reports_a_counted_kill_without_a_log_line_unnamed() {
    let fake = Fake::new("unnamed", 0);
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(watch(fake.sources(), tx));
    tokio::time::sleep(Duration::from_millis(60)).await;
    fake.set_counter(2);
    assert_eq!(
        next(&mut rx, Duration::from_secs(2)).await,
        Some(AgentMessage::oom_kill(None, None))
    );
    assert_eq!(
        next(&mut rx, Duration::from_secs(2)).await,
        Some(AgentMessage::oom_kill(None, None))
    );
    assert_eq!(next(&mut rx, Duration::from_millis(400)).await, None);
    task.abort();
}

#[tokio::test]
async fn watch_works_from_the_log_alone_and_gives_up_with_no_source() {
    let fake = Fake::new("logonly", 0);
    let mut sources = fake.sources();
    sources.vmstat = fake.dir.join("missing");
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(watch(sources.clone(), tx));
    tokio::time::sleep(Duration::from_millis(60)).await;
    fake.log("3,3,3,-;Out of memory: Killed process 7 (x) total-vm:9kB\n");
    assert_eq!(
        next(&mut rx, Duration::from_secs(2)).await,
        Some(AgentMessage::oom_kill(Some(7), Some("x".into())))
    );
    task.abort();

    sources.kmsg = fake.dir.join("missing-too");
    let (tx, _rx) = mpsc::channel(8);
    tokio::time::timeout(Duration::from_secs(2), watch(sources, tx))
        .await
        .expect("watch with no source returns");
}

#[test]
fn a_full_queue_drops_and_a_closed_one_stops() {
    let (tx, rx) = mpsc::channel(1);
    assert!(send(&tx, AgentMessage::oom_kill(None, None)));
    assert!(send(&tx, AgentMessage::oom_kill(None, None)));
    drop(rx);
    assert!(!send(&tx, AgentMessage::oom_kill(None, None)));
}
