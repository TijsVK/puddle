// SPDX-License-Identifier: GPL-3.0-or-later
//! Watching the guest kernel's OOM killer (D-47: show the guest's OOM kills to the user).
//!
//! Two sources, because each misses something the other has:
//!
//! - **`oom_kill` in `/proc/vmstat`** counts every kill, global and memory-cgroup (Linux ≥ 4.13),
//!   but says nothing about the victim.
//! - **`Killed process <pid> (<name>)`** in the kernel log (`/dev/kmsg`) names it, but a record
//!   can be lost (ring overrun) or the log unreadable.
//!
//! A log line is reported at once with its pid and name. A counter increase that no log line
//! accounts for within the grace period is reported without them. [`Correlator`] matches the
//! two so one kill is one report, whichever arrives first. Kills from before the agent started
//! are not reported: the counter's first reading is the baseline and the log is read from its end.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use puddle_agent_proto::AgentMessage;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

use crate::config::OomSources;

/// Room for log kills between the reader thread and the watch loop.
const KILL_QUEUE: usize = 64;

/// One `Killed process` record from the kernel log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kill {
    /// The victim's pid.
    pub pid: u32,
    /// The victim's `comm`, as the kernel printed it.
    pub process: String,
}

/// Parses one `/dev/kmsg` record (`<prio>,<seq>,<usec>,<flags>[,...];<message>`, continuation
/// lines after it). Returns the kill it reports, or `None` for any other record.
///
/// Only kernel records count (syslog facility 0): the kernel forces userspace writes to
/// `/dev/kmsg` to another facility, so a process can't fake a kill line.
///
/// ```
/// use puddle_agent::oom::{parse_kmsg_record, Kill};
/// let rec = "3,812,5140900,-;Out of memory: Killed process 2406 (tail) total-vm:7280204kB, anon-rss:7274112kB\n";
/// assert_eq!(parse_kmsg_record(rec), Some(Kill { pid: 2406, process: "tail".into() }));
/// ```
#[must_use]
pub fn parse_kmsg_record(record: &str) -> Option<Kill> {
    let (header, message) = record.split_once(';')?;
    let prio: u32 = header.split(',').next()?.parse().ok()?;
    if prio >> 3 != 0 {
        return None;
    }
    let message = message.lines().next()?;
    let (_, rest) = message.split_once("Killed process ")?;
    let (pid, rest) = rest.split_once(' ')?;
    let pid = pid.parse().ok()?;
    let rest = rest.strip_prefix('(')?;
    // `comm` may itself contain ") ", so cut at the field that follows it when it is there.
    let end = rest.rfind(") total-vm:").or_else(|| rest.rfind(')'))?;
    let process = rest.get(..end)?.to_owned();
    Some(Kill { pid, process })
}

/// The `oom_kill` counter from the text of `/proc/vmstat`, or `None` if it isn't there.
///
/// ```
/// assert_eq!(puddle_agent::oom::parse_vmstat("pgfault 9\noom_kill 3\n"), Some(3));
/// ```
#[must_use]
pub fn parse_vmstat(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("oom_kill "))
        .and_then(|n| n.trim().parse().ok())
}

/// Matches counter increases with log kills, so each kill is reported once.
#[derive(Debug)]
pub struct Correlator {
    grace: Duration,
    /// Log kills the counter hasn't shown yet.
    logged_ahead: u64,
    /// Counter increases no log kill has claimed yet: (when seen, how many).
    unclaimed: VecDeque<(Instant, u64)>,
}

impl Correlator {
    /// A correlator that waits `grace` for a log line before reporting a counted kill unnamed.
    #[must_use]
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            logged_ahead: 0,
            unclaimed: VecDeque::new(),
        }
    }

    /// A log kill arrived (and was reported with its name).
    pub fn on_logged(&mut self) {
        match self.unclaimed.front_mut() {
            Some((_, n)) if *n > 1 => *n -= 1,
            Some(_) => {
                self.unclaimed.pop_front();
            }
            None => self.logged_ahead = self.logged_ahead.saturating_add(1),
        }
    }

    /// The counter went up by `delta` at `now`.
    pub fn on_counted(&mut self, delta: u64, now: Instant) {
        let claimed = delta.min(self.logged_ahead);
        self.logged_ahead -= claimed;
        let rest = delta - claimed;
        if rest > 0 {
            self.unclaimed.push_back((now, rest));
        }
    }

    /// How many counted kills are past the grace period without a log line: report them unnamed.
    pub fn due(&mut self, now: Instant) -> u64 {
        let mut due = 0u64;
        while let Some(&(seen, n)) = self.unclaimed.front() {
            if now.saturating_duration_since(seen) < self.grace {
                break;
            }
            due = due.saturating_add(n);
            self.unclaimed.pop_front();
        }
        due
    }
}

/// Watches both sources and sends one [`AgentMessage::OomKill`] per kill into `out`. Returns
/// when `out` closes, or at once if neither source can be read.
pub async fn watch(sources: OomSources, out: mpsc::Sender<AgentMessage>) {
    let (kill_tx, mut kills) = mpsc::channel(KILL_QUEUE);
    let log_ok = match open_log(&sources.kmsg) {
        Ok(file) => {
            let poll = sources.poll;
            std::thread::Builder::new()
                .name("puddle-agent-kmsg".into())
                .spawn(move || read_log(file, poll, &kill_tx))
                .is_ok()
        }
        Err(err) => {
            tracing::warn!(path = %sources.kmsg.display(), error = %err, "kernel log unreadable: OOM kills are reported without names");
            false
        }
    };
    let mut count = read_counter(&sources.vmstat).await;
    if count.is_none() {
        tracing::warn!(path = %sources.vmstat.display(), "no oom_kill counter: OOM kills are seen only through the kernel log");
        if !log_ok {
            tracing::warn!("no OOM source readable: OOM kills are not reported");
            return;
        }
    }
    let mut correlator = Correlator::new(sources.grace);
    let mut tick = tokio::time::interval(sources.poll);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = out.closed() => return,
            Some(kill) = kills.recv() => {
                correlator.on_logged();
                if !send(&out, AgentMessage::oom_kill(Some(kill.pid), Some(kill.process))) {
                    return;
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if let Some(before) = count
                    && let Some(seen) = read_counter(&sources.vmstat).await
                {
                    if seen > before {
                        correlator.on_counted(seen - before, now);
                    }
                    count = Some(seen);
                }
                for _ in 0..correlator.due(now) {
                    if !send(&out, AgentMessage::oom_kill(None, None)) {
                        return;
                    }
                }
            }
        }
    }
}

/// Queues `msg`; `false` once the receiver is gone. A full queue drops the report with a warning
/// rather than stalling the watch.
fn send(out: &mpsc::Sender<AgentMessage>, msg: AgentMessage) -> bool {
    match out.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("OOM report dropped: the host isn't taking reports fast enough");
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

async fn read_counter(path: &Path) -> Option<u64> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    parse_vmstat(&text)
}

/// Opens the kernel log positioned at its end, so only new records are read.
fn open_log(path: &Path) -> io::Result<File> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    Ok(file)
}

/// Blocking reader (own thread): one record per line, kills go to `out`. On `/dev/kmsg` a read
/// blocks until a record arrives; on a plain file (tests) end of file is polled every `poll`.
/// Ends when `out` closes or the log fails.
fn read_log(file: File, poll: Duration, out: &mpsc::Sender<Kill>) {
    let mut reader = BufReader::with_capacity(16 * 1024, file);
    let mut record = Vec::with_capacity(1024);
    loop {
        record.clear();
        match reader.read_until(b'\n', &mut record) {
            Ok(0) => {
                if out.is_closed() {
                    return;
                }
                std::thread::sleep(poll);
            }
            Ok(_) => {
                if let Some(kill) = parse_kmsg_record(&String::from_utf8_lossy(&record))
                    && out.blocking_send(kill).is_err()
                {
                    return;
                }
            }
            // Records were overwritten before we read them; reading goes on from the oldest kept.
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {}
            Err(err) => {
                tracing::warn!(error = %err, "kernel log read failed: OOM kills are reported without names");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
