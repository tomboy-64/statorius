//! The "L2 Pingers" feature: a list of targets pinged over raw Ethernet
//! frames (via `l2_manager`/`l2_engine`), each with its own VLAN, IP/prefix,
//! and per-ping timeout. Every round checks for a duplicate IP first (see
//! the explanation given alongside this feature - ARP-based, best effort)
//! before actually pinging, then sleeps a second before the next round.
//!
//! Mirrors `state::SharedState`/`net::ping_worker`'s shape on purpose:
//! `L2PingerState` is the shared, lock-protected snapshot the UI reads every
//! frame; `L2PingerCommand` is what the UI sends in. The one real
//! difference: every round goes through `l2_manager`'s `L2JobRequest`
//! channel, which relays into `l2_engine`'s single-threaded job queue - so
//! "never more than one ping in flight" isn't something this file has to
//! enforce itself, it falls out of that shared queue being processed one
//! job at a time, globally, across every L2 target at once.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::l2_ipc::{L2DuplicateOutcomeWire, L2PingOutcomeWire};
use super::l2_manager::L2JobRequest;
use crate::state::{PingResult, HISTORY_LEN};

/// One round's current phase for a target - shown as the small colored dot
/// next to its row: yellow (checking) / red (duplicate) / teal (in flight) /
/// green (response arrived), as requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Phase {
    /// Between rounds - just finished sleeping, or hasn't run yet.
    Idle,
    CheckingDuplicate,
    Duplicate,
    InFlight,
    Success,
    Failed,
}

#[derive(Debug, Clone)]
pub struct L2PingEntry {
    pub target: Ipv4Addr,
    pub prefix_len: u8,
    pub vlan: Option<u16>,
    pub timeout: Duration,
    pub phase: L2Phase,
    pub last_result: Option<PingResult>,
    pub last_updated: Option<Instant>,
    pub attempts: u32,
    pub successes: u32,
    pub history: VecDeque<Option<Duration>>,
    pub running: bool,
    pub duplicate_macs: Vec<String>,
}

impl L2PingEntry {
    fn new(target: Ipv4Addr, prefix_len: u8, vlan: Option<u16>, timeout: Duration) -> Self {
        Self {
            target,
            prefix_len,
            vlan,
            timeout,
            phase: L2Phase::Idle,
            last_result: None,
            last_updated: None,
            attempts: 0,
            successes: 0,
            history: VecDeque::with_capacity(HISTORY_LEN),
            running: true,
            duplicate_macs: Vec::new(),
        }
    }

    /// Same rolling-average semantics as the plain ping list's `PingEntry`.
    pub fn rolling_average(&self) -> Option<Duration> {
        let (sum, count) = self
            .history
            .iter()
            .flatten()
            .fold((Duration::ZERO, 0u32), |(sum, count), d| {
                (sum + *d, count + 1)
            });
        if count == 0 {
            None
        } else {
            Some(sum / count)
        }
    }
}

#[derive(Clone, Default)]
pub struct L2PingerState {
    inner: Arc<Mutex<HashMap<Ipv4Addr, L2PingEntry>>>,
}

impl L2PingerState {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_target(&self, target: Ipv4Addr, prefix_len: u8, vlan: Option<u16>, timeout: Duration) {
        let mut map = self.inner.lock().unwrap();
        map.entry(target)
            .or_insert_with(|| L2PingEntry::new(target, prefix_len, vlan, timeout));
    }

    fn set_phase(&self, target: Ipv4Addr, phase: L2Phase) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&target) {
            e.phase = phase;
        }
    }

    fn set_duplicate_macs(&self, target: Ipv4Addr, macs: Vec<String>) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&target) {
            e.duplicate_macs = macs;
        }
    }

    fn record_result(&self, target: Ipv4Addr, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        let Some(entry) = map.get_mut(&target) else {
            return;
        };
        entry.attempts += 1;
        let sample = if let PingResult::Success(d) = &result {
            Some(*d)
        } else {
            None
        };
        if sample.is_some() {
            entry.successes += 1;
        }
        if entry.history.len() == HISTORY_LEN {
            entry.history.pop_front();
        }
        entry.history.push_back(sample);
        entry.last_result = Some(result);
        entry.last_updated = Some(Instant::now());
    }

    fn set_running(&self, target: Ipv4Addr, running: bool) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&target) {
            e.running = running;
        }
    }

    pub fn remove(&self, target: Ipv4Addr) {
        let mut map = self.inner.lock().unwrap();
        map.remove(&target);
    }

    pub fn snapshot(&self) -> Vec<L2PingEntry> {
        let map = self.inner.lock().unwrap();
        let mut entries: Vec<L2PingEntry> = map.values().cloned().collect();
        entries.sort_by_key(|e| e.target);
        entries
    }
}

#[derive(Debug, Clone)]
pub enum L2PingerCommand {
    Start {
        target: Ipv4Addr,
        prefix_len: u8,
        vlan: Option<u16>,
        timeout: Duration,
    },
    Stop(Ipv4Addr),
    Delete(Ipv4Addr),
}

const ROUND_SLEEP: Duration = Duration::from_secs(1);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

struct TargetHandle {
    stop_flag: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

/// Dispatcher loop - structurally identical to `net::ping_worker`: one
/// continuous-round task per target, Start/Stop/Delete control.
pub async fn l2_pinger_worker(
    mut rx: mpsc::Receiver<L2PingerCommand>,
    state: L2PingerState,
    job_tx: mpsc::Sender<L2JobRequest>,
) {
    let mut handles: HashMap<Ipv4Addr, TargetHandle> = HashMap::new();

    while let Some(command) = rx.recv().await {
        match command {
            L2PingerCommand::Start {
                target,
                prefix_len,
                vlan,
                timeout,
            } => {
                if let Some(old) = handles.remove(&target) {
                    old.stop_flag.store(true, Ordering::Relaxed);
                    old.task.abort();
                    let _ = old.task.await;
                }

                state.ensure_target(target, prefix_len, vlan, timeout);
                state.set_running(target, true);

                let stop_flag = Arc::new(AtomicBool::new(false));
                let task_stop_flag = stop_flag.clone();
                let task_state = state.clone();
                let task_job_tx = job_tx.clone();

                let task = tokio::spawn(async move {
                    run_rounds(target, vlan, timeout, task_state, task_job_tx, task_stop_flag).await;
                });

                handles.insert(target, TargetHandle { stop_flag, task });
            }
            L2PingerCommand::Stop(target) => {
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                }
                state.set_running(target, false);
            }
            L2PingerCommand::Delete(target) => {
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                    handle.task.abort();
                    let _ = handle.task.await;
                }
                state.remove(target);
            }
        }
    }
}

async fn run_rounds(
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
    state: L2PingerState,
    job_tx: mpsc::Sender<L2JobRequest>,
    stop_flag: Arc<AtomicBool>,
) {
    while !stop_flag.load(Ordering::Relaxed) {
        // 1. Check for duplicateness before every ping, as requested.
        state.set_phase(target, L2Phase::CheckingDuplicate);
        let dup_outcome = check_duplicate(&job_tx, target, vlan, timeout).await;

        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        match dup_outcome {
            L2DuplicateOutcomeWire::Duplicate { macs } => {
                state.set_duplicate_macs(target, macs);
                state.set_phase(target, L2Phase::Duplicate);
                state.record_result(target, PingResult::Error("duplicate IP detected".to_owned()));
                interruptible_sleep(ROUND_SLEEP, &stop_flag).await;
                continue;
            }
            L2DuplicateOutcomeWire::Error(_) => {
                // Inconclusive (e.g. L2 briefly unavailable) - proceed with
                // the ping anyway rather than blocking forever on a check
                // that can't complete; the ping itself will surface the same
                // underlying problem if there is one.
            }
            L2DuplicateOutcomeWire::Clear => {
                state.set_duplicate_macs(target, Vec::new());
            }
        }

        // 2. Actually ping.
        state.set_phase(target, L2Phase::InFlight);
        let outcome = do_ping(&job_tx, target, vlan, timeout).await;

        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let result = match outcome {
            L2PingOutcomeWire::Success { rtt_ms } => {
                state.set_phase(target, L2Phase::Success);
                PingResult::Success(Duration::from_millis(rtt_ms))
            }
            L2PingOutcomeWire::Timeout => {
                state.set_phase(target, L2Phase::Failed);
                PingResult::Timeout
            }
            L2PingOutcomeWire::Error(e) => {
                state.set_phase(target, L2Phase::Failed);
                PingResult::Error(e)
            }
        };
        state.record_result(target, result);

        // 3. Sleep, then repeat.
        interruptible_sleep(ROUND_SLEEP, &stop_flag).await;
        state.set_phase(target, L2Phase::Idle);
    }
}

async fn check_duplicate(
    job_tx: &mpsc::Sender<L2JobRequest>,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcomeWire {
    let (tx, rx) = oneshot::channel();
    if job_tx
        .send(L2JobRequest::CheckDuplicate {
            target,
            vlan,
            timeout,
            respond_to: tx,
        })
        .await
        .is_err()
    {
        return L2DuplicateOutcomeWire::Error("L2 manager unavailable".to_owned());
    }
    rx.await
        .unwrap_or_else(|_| L2DuplicateOutcomeWire::Error("L2 manager dropped the request".to_owned()))
}

async fn do_ping(
    job_tx: &mpsc::Sender<L2JobRequest>,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcomeWire {
    let (tx, rx) = oneshot::channel();
    if job_tx
        .send(L2JobRequest::Ping {
            target,
            vlan,
            timeout,
            respond_to: tx,
        })
        .await
        .is_err()
    {
        return L2PingOutcomeWire::Error("L2 manager unavailable".to_owned());
    }
    rx.await
        .unwrap_or_else(|_| L2PingOutcomeWire::Error("L2 manager dropped the request".to_owned()))
}

async fn interruptible_sleep(duration: Duration, stop_flag: &AtomicBool) {
    let mut remaining = duration;
    while remaining > Duration::ZERO {
        if stop_flag.load(Ordering::Relaxed) {
            return;
        }
        let step = remaining.min(STOP_POLL_INTERVAL);
        tokio::time::sleep(step).await;
        remaining = remaining.saturating_sub(step);
    }
}
