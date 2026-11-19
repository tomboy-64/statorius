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

/// Which protocol a plain ping uses - the part of `PingMethod` that decides
/// whether two pingers for the same address are "the same pinger".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PingProto {
    Icmp,
    Tcp,
    Udp,
}

/// Identity of one pinger: target address + protocol (+ port for TCP/UDP,
/// `0` for ICMP). The same address can therefore have an ICMP, a TCP and a
/// UDP pinger side by side, and e.g. TCP/22 next to TCP/443; (re)starting
/// with an identical key restarts that pinger instead of adding another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PingKey {
    pub target: IpAddr,
    pub proto: PingProto,
    pub port: u16,
}

impl PingMethod {
    pub fn proto(&self) -> PingProto {
        match self {
            PingMethod::Icmp { .. } => PingProto::Icmp,
            PingMethod::Tcp { .. } => PingProto::Tcp,
            PingMethod::Udp { .. } => PingProto::Udp,
        }
    }

    pub fn key(&self, target: IpAddr) -> PingKey {
        let port = match self {
            PingMethod::Icmp { .. } => 0,
            PingMethod::Tcp { port } | PingMethod::Udp { port } => *port,
        };
        PingKey { target, proto: self.proto(), port }
    }

    /// Short label for the list: `ICMP`, `TCP/443`, `UDP/53`.
    pub fn label(&self) -> String {
        match self {
            PingMethod::Icmp { .. } => "ICMP".to_owned(),
            PingMethod::Tcp { port } => format!("TCP/{port}"),
            PingMethod::Udp { port } => format!("UDP/{port}"),
        }
    }

    /// What one attempt actually puts on the wire - shown as a tooltip.
    pub fn wire_description(&self) -> &'static str {
        match self {
            PingMethod::Icmp { .. } => "ICMP echo request \u{2192} echo reply",
            PingMethod::Tcp { .. } => "TCP SYN \u{2192} SYN/ACK (open) or RST (closed)",
            PingMethod::Udp { .. } => {
                "Empty UDP datagram \u{2192} reply (open) or ICMP port unreachable (closed); \
                 silence = open or filtered"
            }
        }
    }
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
    /// Nothing came back within the timeout (ICMP/TCP: probe or answer
    /// lost, or silently filtered).
    Timeout,
    /// UDP only: no reply at all. Not a failure - an open UDP port that
    /// has nothing to say to an empty datagram looks exactly like this -
    /// so it is shown neutrally, not red.
    Silent,
    /// The target or something on the path explicitly said no: TCP RST,
    /// ICMP port/host/network unreachable, admin-prohibited, TTL exceeded...
    /// `short` fits in the list cell, `detail` goes in the tooltip.
    Rejected { short: String, detail: String },
    /// Local problem (socket creation, send failure, ...).
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
    Stop(PingKey),
    /// Pause (if running) and forget this pinger entirely.
    Delete(PingKey),
}

/// The latest known status for one target. Updated in place by the worker,
/// read out (cloned) by the UI every frame via `SharedState::snapshot`.
#[derive(Debug, Clone)]
pub struct PingEntry {
    pub key: PingKey,
    pub target: IpAddr,
    pub method: PingMethod,
    pub last_result: Option<PingResult>,
    pub last_updated: Option<Instant>,
    pub attempts: u32,
    pub successes: u32,
    /// Most recent outcomes, oldest at the front, newest at the back, capped
    /// at `HISTORY_LEN`.
    pub samples: VecDeque<PingResult>,
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
            key: method.key(target),
            target,
            method,
            last_result: None,
            last_updated: None,
            attempts: 0,
            successes: 0,
            samples: VecDeque::with_capacity(HISTORY_LEN),
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
    inner: Arc<Mutex<HashMap<PingKey, PingEntry>>>,
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
        let key = method.key(target);
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(&key) {
            Some(entry) => {
                // Same key = same pinger restarted; take over whatever
                // isn't part of the key (ICMP payload size, count, label).
                entry.method = method;
                entry.count = count;
                entry.label = label;
                if entry.successes == 0 {
                    entry.started_at = Instant::now();
                }
            }
            None => {
                map.insert(key, PingEntry::new(target, method, count, label));
            }
        }
    }

    /// Record the outcome of one ping attempt against `target`, pushing it into
    /// the rolling history (dropping the oldest sample once it's full).
    pub fn record_result(&self, key: PingKey, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        // Only ever reached for a key `ensure_target` has registered (or
        // that was deleted meanwhile - then the result is simply dropped,
        // rather than resurrecting a row the user just removed).
        let Some(entry) = map.get_mut(&key) else {
            return;
        };

        entry.attempts += 1;
        if let PingResult::Success(_) = &result {
            entry.successes += 1;
            entry.last_updated = Some(Instant::now());
        }

        if entry.samples.len() == HISTORY_LEN {
            entry.samples.pop_front();
        }
        entry.samples.push_back(result.clone());
        entry.last_result = Some(result);
    }

    /// Mark whether a target's continuous loop is currently active, so the UI
    /// can show a stop-sign vs. a play-sign.
    pub fn set_running(&self, key: PingKey, running: bool) {
        let mut map = self.inner.lock().unwrap();
        if let Some(entry) = map.get_mut(&key) {
            entry.running = running;
        }
    }

    /// Forget a target entirely (used by the delete/"X" control).
    pub fn remove(&self, key: PingKey) {
        let mut map = self.inner.lock().unwrap();
        map.remove(&key);
    }

    /// Snapshot every known target for rendering. Cloned out so the UI never holds
    /// the lock while drawing widgets.
    pub fn snapshot(&self) -> Vec<PingEntry> {
        let map = self.inner.lock().unwrap();
        let mut entries: Vec<PingEntry> = map.values().cloned().collect();
        entries.sort_by_key(|e| e.key);
        entries
    }
}