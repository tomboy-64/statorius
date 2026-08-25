//! The "L2 Pingers" feature: a list of (source IP, target) pairs pinged
//! over raw Ethernet frames (via `l2_manager`/`l2_engine`), each with its
//! own VLAN, target IP/prefix, source IP, per-ping timeout, and method
//! (full ICMP echo, or a bare ARP/NDP exchange - see `L2PingMethod`). Every
//! round checks the *source* IP for duplicateness first (not the target -
//! see the explanation given alongside this feature) before actually
//! pinging, then sleeps a second before the next round.
//!
//! Mirrors `state::SharedState`/`net::ping_worker`'s shape on purpose:
//! `L2PingerState` is the shared, lock-protected snapshot the UI reads every
//! frame; `L2PingerCommand` is what the UI sends in. Two differences from
//! the plain ping list: every round goes through `l2_manager`'s
//! `L2JobRequest` channel (which relays into `l2_engine`'s single-threaded
//! job queue - "never more than one ping in flight" falls out of that queue
//! being processed one job at a time, globally, across every L2 target at
//! once, rather than something this file enforces itself); and entries are
//! keyed by `(source_ip, target)` rather than just `target`, since the same
//! target might reasonably be tested from more than one candidate source
//! address.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::l2_ipc::{L2DuplicateOutcomeWire, L2PingOutcomeWire};
use super::l2_manager::L2JobRequest;
use crate::state::{PingResult, HISTORY_LEN};

/// A (source IP, target) pair - the unique identity of one row in the L2
/// Pingers list. A pairing can only run one method at a time - starting it
/// again with a different `L2PingMethod` restarts it under the new one
/// rather than running both concurrently, same as changing any other field
/// (VLAN, timeout, ...) on an existing pairing already does.
pub type L2PingerKey = (IpAddr, IpAddr);

/// Which flavor of reachability check a pairing performs each round, once
/// the mandatory duplicate-check on `source_ip` (which always happens,
/// regardless of this) has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2PingMethod {
    /// A full ICMP-over-L2 echo request/reply - today's only behavior,
    /// still the default.
    Icmp,
    /// A bare ARP (V4) / Neighbor Solicitation (V6) exchange instead -
    /// faster and simpler than a full echo, and doesn't require the target
    /// to run an IP stack that answers ICMP at all, just to be present on
    /// the segment. See `l2_engine::do_arp_ping`.
    ArpNdp,
}

/// One round's current phase for a pairing - shown as the small colored dot
/// next to its row: yellow (checking) / red (duplicate) / teal (in flight) /
/// green (response arrived), as requested. "Duplicate" here means the
/// *source* IP, not the target.
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
    pub source_ip: IpAddr,
    pub target: IpAddr,
    pub prefix_len: u8,
    pub vlan: Option<u16>,
    pub timeout: Duration,
    pub method: L2PingMethod,
    pub phase: L2Phase,
    pub last_result: Option<PingResult>,
    pub last_updated: Option<Instant>,
    pub attempts: u32,
    pub successes: u32,
    pub history: VecDeque<Option<Duration>>,
    pub running: bool,
    /// MACs seen answering for `source_ip` (not `target`) when it was found
    /// to be a duplicate.
    pub duplicate_macs: Vec<String>,
}

impl L2PingEntry {
    fn new(
        source_ip: IpAddr,
        target: IpAddr,
        prefix_len: u8,
        vlan: Option<u16>,
        timeout: Duration,
        method: L2PingMethod,
    ) -> Self {
        Self {
            source_ip,
            target,
            prefix_len,
            vlan,
            timeout,
            method,
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
    inner: Arc<Mutex<HashMap<L2PingerKey, L2PingEntry>>>,
}

impl L2PingerState {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_target(
        &self,
        source_ip: IpAddr,
        target: IpAddr,
        prefix_len: u8,
        vlan: Option<u16>,
        timeout: Duration,
        method: L2PingMethod,
    ) {
        let mut map = self.inner.lock().unwrap();
        map.entry((source_ip, target))
            .or_insert_with(|| L2PingEntry::new(source_ip, target, prefix_len, vlan, timeout, method));
    }

    fn set_phase(&self, key: L2PingerKey, phase: L2Phase) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&key) {
            e.phase = phase;
        }
    }

    fn set_duplicate_macs(&self, key: L2PingerKey, macs: Vec<String>) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&key) {
            e.duplicate_macs = macs;
        }
    }

    fn record_result(&self, key: L2PingerKey, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        let Some(entry) = map.get_mut(&key) else {
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

    fn set_running(&self, key: L2PingerKey, running: bool) {
        let mut map = self.inner.lock().unwrap();
        if let Some(e) = map.get_mut(&key) {
            e.running = running;
        }
    }

    pub fn remove(&self, key: L2PingerKey) {
        let mut map = self.inner.lock().unwrap();
        map.remove(&key);
    }

    pub fn snapshot(&self) -> Vec<L2PingEntry> {
        let map = self.inner.lock().unwrap();
        let mut entries: Vec<L2PingEntry> = map.values().cloned().collect();
        entries.sort_by_key(|e| (e.source_ip, e.target));
        entries
    }
}

#[derive(Debug, Clone)]
pub enum L2PingerCommand {
    Start {
        source_ip: IpAddr,
        target: IpAddr,
        prefix_len: u8,
        vlan: Option<u16>,
        timeout: Duration,
        method: L2PingMethod,
    },
    Stop(L2PingerKey),
    Delete(L2PingerKey),
}

const ROUND_SLEEP: Duration = Duration::from_secs(1);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

struct TargetHandle {
    stop_flag: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

/// Dispatcher loop - structurally identical to `net::ping_worker`: one
/// continuous-round task per (source, target) pairing, Start/Stop/Delete
/// control.
pub async fn l2_pinger_worker(
    mut rx: mpsc::Receiver<L2PingerCommand>,
    state: L2PingerState,
    job_tx: mpsc::Sender<L2JobRequest>,
) {
    let mut handles: HashMap<L2PingerKey, TargetHandle> = HashMap::new();

    while let Some(command) = rx.recv().await {
        match command {
            L2PingerCommand::Start {
                source_ip,
                target,
                prefix_len,
                vlan,
                timeout,
                method,
            } => {
                let key = (source_ip, target);
                if let Some(old) = handles.remove(&key) {
                    old.stop_flag.store(true, Ordering::Relaxed);
                    old.task.abort();
                    let _ = old.task.await;
                }

                state.ensure_target(source_ip, target, prefix_len, vlan, timeout, method);
                state.set_running(key, true);

                let stop_flag = Arc::new(AtomicBool::new(false));
                let task_stop_flag = stop_flag.clone();
                let task_state = state.clone();
                let task_job_tx = job_tx.clone();

                let task = tokio::spawn(async move {
                    run_rounds(
                        source_ip,
                        target,
                        vlan,
                        timeout,
                        method,
                        task_state,
                        task_job_tx,
                        task_stop_flag,
                    )
                        .await;
                });

                handles.insert(key, TargetHandle { stop_flag, task });
            }
            L2PingerCommand::Stop(key) => {
                if let Some(handle) = handles.remove(&key) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                }
                state.set_running(key, false);
            }
            L2PingerCommand::Delete(key) => {
                if let Some(handle) = handles.remove(&key) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                    handle.task.abort();
                    let _ = handle.task.await;
                }
                state.remove(key);
            }
        }
    }
}

async fn run_rounds(
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
    method: L2PingMethod,
    state: L2PingerState,
    job_tx: mpsc::Sender<L2JobRequest>,
    stop_flag: Arc<AtomicBool>,
) {
    let key: L2PingerKey = (source_ip, target);

    while !stop_flag.load(Ordering::Relaxed) {
        // 1. Check the *source* IP for duplicateness before every ping, as
        // requested - not the target. `source_ip` is the address we're
        // about to claim as ours for this ping; `target` is just who we're
        // sending to.
        state.set_phase(key, L2Phase::CheckingDuplicate);
        let dup_outcome = check_duplicate(&job_tx, source_ip, vlan, timeout).await;

        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        match dup_outcome {
            L2DuplicateOutcomeWire::Duplicate { macs } => {
                state.set_duplicate_macs(key, macs);
                state.set_phase(key, L2Phase::Duplicate);
                state.record_result(
                    key,
                    PingResult::Error("duplicate source IP detected".to_owned()),
                );
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
                state.set_duplicate_macs(key, Vec::new());
            }
        }

        // 2. Actually ping, from source_ip to target - a full ICMP echo or
        // a bare ARP/NDP exchange, depending on `method`.
        state.set_phase(key, L2Phase::InFlight);
        let outcome = match method {
            L2PingMethod::Icmp => do_ping(&job_tx, source_ip, target, vlan, timeout).await,
            L2PingMethod::ArpNdp => do_arp_ping(&job_tx, source_ip, target, vlan, timeout).await,
        };

        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let result = match outcome {
            L2PingOutcomeWire::Success { rtt_ms } => {
                state.set_phase(key, L2Phase::Success);
                PingResult::Success(Duration::from_millis(rtt_ms))
            }
            L2PingOutcomeWire::Timeout => {
                state.set_phase(key, L2Phase::Failed);
                PingResult::Timeout
            }
            L2PingOutcomeWire::Error(e) => {
                state.set_phase(key, L2Phase::Failed);
                PingResult::Error(e)
            }
        };
        state.record_result(key, result);

        // 3. Sleep, then repeat.
        interruptible_sleep(ROUND_SLEEP, &stop_flag).await;
        state.set_phase(key, L2Phase::Idle);
    }
}

/// Check `source_ip` (a candidate address, not a ping target) for
/// duplicates.
async fn check_duplicate(
    job_tx: &mpsc::Sender<L2JobRequest>,
    source_ip: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcomeWire {
    let (tx, rx) = oneshot::channel();
    if job_tx
        .send(L2JobRequest::CheckDuplicate {
            candidate: source_ip,
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
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcomeWire {
    let (tx, rx) = oneshot::channel();
    if job_tx
        .send(L2JobRequest::Ping {
            source_ip,
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

async fn do_arp_ping(
    job_tx: &mpsc::Sender<L2JobRequest>,
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcomeWire {
    let (tx, rx) = oneshot::channel();
    if job_tx
        .send(L2JobRequest::ArpPing {
            source_ip,
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