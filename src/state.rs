use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many recent samples we keep per target, for both the rolling average
/// and the hover tooltip.
pub const HISTORY_LEN: usize = 15;

#[derive(Debug, Clone)]
pub enum PingMethod {
    Icmp,
    Tcp { port: u16 },
}

#[derive(Debug, Clone)]
pub struct PingRequest {
    pub target: IpAddr,
    pub method: PingMethod,
    pub source_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub enum PingResult {
    Success(Duration),
    Timeout,
    PortClosed,
    Error(String),
}

/// Commands the UI sends to the worker. Continuous pinging means there's no
/// more "fire one ping and forget" - every target has an ongoing loop that
/// is explicitly started, paused, or torn down.
#[derive(Debug, Clone)]
pub enum WorkerCommand {
    /// Start (or restart, if already running) continuous pinging of a target.
    Start(PingRequest),
    /// Pause continuous pinging; the row and its history are kept as-is.
    Stop(IpAddr),
    /// Pause (if running) and forget this target entirely.
    Delete(IpAddr),
}

/// The latest known status for one target. Updated in place by the worker,
/// read out (cloned) by the UI every frame via `SharedState::snapshot`.
#[derive(Debug, Clone)]
pub struct PingEntry {
    pub target: IpAddr,
    pub method: PingMethod,
    pub last_result: Option<PingResult>,
    pub last_updated: Option<Instant>,
    pub attempts: u32,
    pub successes: u32,
    /// Most recent samples, oldest at the front, newest at the back, capped at
    /// `HISTORY_LEN`. `None` marks a failed/timed-out/errored attempt.
    pub history: VecDeque<Option<Duration>>,
    /// Whether the continuous ping loop for this target is currently active.
    pub running: bool,
}

impl PingEntry {
    fn new(target: IpAddr, method: PingMethod) -> Self {
        Self {
            target,
            method,
            last_result: None,
            last_updated: None,
            attempts: 0,
            successes: 0,
            history: VecDeque::with_capacity(HISTORY_LEN),
            running: true,
        }
    }

    /// Average RTT across whichever attempts in the history window succeeded.
    /// `None` if every attempt in the window failed (or there's no history yet) -
    /// that's the UI's cue to render the red "no response" state.
    pub fn rolling_average(&self) -> Option<Duration> {
        let (sum, count) = self
            .history
            .iter()
            .flatten()
            .fold((Duration::ZERO, 0u32), |(sum, count), d| (sum + *d, count + 1));
        if count == 0 {
            None
        } else {
            Some(sum / count)
        }
    }
}

/// Shared, thread-safe ping state. The worker writes into this after every ping
/// completes; the UI thread reads a snapshot of it every frame. There is
/// deliberately no "results" channel: this `SharedState` *is* the state object.
#[derive(Clone, Default)]
pub struct SharedState {
    inner: Arc<Mutex<HashMap<IpAddr, PingEntry>>>,
}

impl SharedState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called when a target is (re)started, so it shows up in the UI - as
    /// "pending" the first time, unchanged if it already existed - even before
    /// the next result comes back.
    pub fn ensure_target(&self, target: IpAddr, method: PingMethod) {
        let mut map = self.inner.lock().unwrap();
        map.entry(target).or_insert_with(|| PingEntry::new(target, method));
    }

    /// Record the outcome of one ping attempt against `target`, pushing it into
    /// the rolling history (dropping the oldest sample once it's full).
    pub fn record_result(&self, target: IpAddr, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        let entry = map
            .entry(target)
            .or_insert_with(|| PingEntry::new(target, PingMethod::Icmp));

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
        if matches!(entry.last_result, Some(PingResult::Success(_))) {
            entry.last_updated = Some(Instant::now());
        }
    }

    /// Mark whether a target's continuous loop is currently active, so the UI
    /// can show a stop-sign vs. a play-sign.
    pub fn set_running(&self, target: IpAddr, running: bool) {
        let mut map = self.inner.lock().unwrap();
        if let Some(entry) = map.get_mut(&target) {
            entry.running = running;
        }
    }

    /// Forget a target entirely (used by the delete/"X" control).
    pub fn remove(&self, target: IpAddr) {
        let mut map = self.inner.lock().unwrap();
        map.remove(&target);
    }

    /// Snapshot every known target for rendering. Cloned out so the UI never holds
    /// the lock while drawing widgets.
    pub fn snapshot(&self) -> Vec<PingEntry> {
        let map = self.inner.lock().unwrap();
        let mut entries: Vec<PingEntry> = map.values().cloned().collect();
        entries.sort_by_key(|e| e.target);
        entries
    }
}