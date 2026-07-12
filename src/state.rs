use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

    /// Called when a new target is requested, so it shows up in the UI (as "pending")
    /// even before the first result comes back.
    pub fn ensure_target(&self, target: IpAddr, method: PingMethod) {
        let mut map = self.inner.lock().unwrap();
        map.entry(target).or_insert_with(|| PingEntry::new(target, method));
    }

    /// Record the outcome of one ping attempt against `target`.
    pub fn record_result(&self, target: IpAddr, result: PingResult) {
        let mut map = self.inner.lock().unwrap();
        let entry = map
            .entry(target)
            .or_insert_with(|| PingEntry::new(target, PingMethod::Icmp));
        entry.attempts += 1;
        if matches!(result, PingResult::Success(_)) {
            entry.successes += 1;
        }
        entry.last_result = Some(result);
        entry.last_updated = Some(Instant::now());
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