use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many recent samples we keep per target, for both the rolling average
/// and the hover tooltip.
pub const HISTORY_LEN: usize = 15;

/// ICMP payload size used when a target doesn't specify its own - matches
/// classic `ping`'s traditional default (56 bytes of data, 64 with the ICMP
/// header) rather than anything this app picked arbitrarily.
pub const DEFAULT_ICMP_PAYLOAD_SIZE: usize = 56;

#[derive(Debug, Clone, PartialEq)]
pub enum PingMethod {
    /// `payload_size` is exposed (rather than fixed) so a target can be
    /// pinged with an oversized payload to probe for fragmentation/MTU
    /// issues along the path - see `backend::IcmpSocketBackend`.
    Icmp { payload_size: usize },
    Tcp { port: u16 },
    /// A "null" UDP probe: an empty datagram, success/failure read from
    /// whatever comes back (a reply, an ICMP Port Unreachable surfaced as a
    /// socket error, or silence) - see `backend::UdpProbeBackend` for why
    /// silence is reported as `Timeout` rather than a positive result.
    Udp { port: u16 },
}

#[derive(Debug, Clone)]
pub struct PingRequest {
    pub target: IpAddr,
    pub method: PingMethod,
    /// Stop automatically once this many attempts have completed - `None`
    /// runs until manually stopped, the default from the UI.
    pub count: Option<u32>,
    /// The hostname this target's address was resolved from, if any - purely
    /// a display label (shown as `(name)` in the Ping tab's last column).
    /// The target itself, and therefore the sort order and the worker's
    /// bookkeeping, are always keyed by the literal IP.
    pub label: Option<String>,
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
    /// Whether the continuous ping loop for this target is currently active -
    /// `false` both when the user paused it and when it ran out its `count`
    /// on its own; either way, resuming starts a fresh `count`-sized run.
    pub running: bool,
    /// Stop automatically once this many attempts have completed since the
    /// most recent start/resume - `None` runs until stopped by hand. Kept on
    /// the entry (not just the request) so the ▶ resume button restarts with
    /// the same count instead of reverting to "unlimited".
    pub count: Option<u32>,
    /// Hostname this target was resolved from, if any - see
    /// `PingRequest::label`. Carried on the entry so the ▶ resume button can
    /// hand it back with its restart request.
    pub label: Option<String>,
    /// Reference point for the "Since" timer while no response has ever
    /// come back: when pinging this target was (re)started. Once a success
    /// is recorded, `last_updated` takes over and this is no longer shown.
    pub started_at: Instant,
}

impl PingEntry {
    fn new(target: IpAddr, method: PingMethod, count: Option<u32>, label: Option<String>) -> Self {
        Self {
            target,
            method,
            last_result: None,
            last_updated: None,
            attempts: 0,
            successes: 0,
            history: VecDeque::with_capacity(HISTORY_LEN),
            running: true,
            count,
            label,
            started_at: Instant::now(),
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
    ///
    /// For an already-known target the history is kept as-is, but the label
    /// is refreshed (so re-submitting a literal IP clears an old hostname
    /// label, and re-resolving a name updates it), and - while it has never
    /// had a response - the "no response yet" timer restarts from now, so
    /// time spent paused isn't counted as time spent waiting.
    pub fn ensure_target(
        &self,
        target: IpAddr,
        method: PingMethod,
        count: Option<u32>,
        label: Option<String>,
    ) {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(&target) {
            Some(entry) => {
                entry.label = label;
                if entry.successes == 0 {
                    entry.started_at = Instant::now();
                }
            }
            None => {
                map.insert(target, PingEntry::new(target, method, count, label));
            }
        }
    }

    /// Record the outcome of one ping attempt against `target`, pushing it into
    /// the rolling history (dropping the oldest sample once it's full).
    pub fn record_result(&self, target: IpAddr, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(target).or_insert_with(|| {
            PingEntry::new(
                target,
                PingMethod::Icmp { payload_size: DEFAULT_ICMP_PAYLOAD_SIZE },
                None,
                None,
            )
        });

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