//! Shared, GUI-side state for captured DHCP exchanges - populated by
//! `l2_manager` as `L2Message::DhcpEvent`s arrive (unsolicited) from the
//! helper's passive sniffer, read out (snapshotted) by the "DHCP" tab every
//! frame. Mirrors `l2_pinger::L2PingerState`'s shape: a lock-protected map
//! the background side writes into and the UI only ever reads a clone of.
//!
//! Messages are grouped by DHCP transaction id (`xid`), since that's the
//! natural unit for "one exchange" - a DISCOVER/OFFER/REQUEST/ACK all share
//! the same `xid`. Two genuinely unrelated exchanges *could* collide on
//! `xid` (it's only a 32-bit value a client picks itself, not guaranteed
//! globally unique) - rare enough in practice, and no worse than what any
//! passive DHCP-watching tool does, so it isn't specially handled here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::dhcp::DhcpMessageWire;

/// Every captured message sharing one DHCP transaction id, in the order
/// they were captured.
#[derive(Debug, Clone)]
pub struct DhcpTransaction {
    pub xid: u32,
    /// Capture time of the first message seen for this `xid` - what the
    /// tab sorts transactions by (oldest exchange first) and shows in the
    /// collapsing header, regardless of what order later messages arrive
    /// in.
    pub first_seen_unix_ms: u64,
    pub messages: Vec<DhcpMessageWire>,
}

#[derive(Clone, Default)]
pub struct DhcpState {
    inner: Arc<Mutex<BTreeMap<u32, DhcpTransaction>>>,
}

impl DhcpState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one newly-captured message, filing it under its `xid` -
    /// creating that transaction if this is the first message seen for it.
    pub fn record(&self, msg: DhcpMessageWire) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(msg.xid).or_insert_with(|| DhcpTransaction {
            xid: msg.xid,
            first_seen_unix_ms: msg.captured_at_unix_ms,
            messages: Vec::new(),
        });
        entry.messages.push(msg);
    }

    /// Every known transaction, oldest exchange first (by its first
    /// message's capture time) - exactly the order the DHCP tab renders
    /// its collapsing headers in.
    pub fn snapshot(&self) -> Vec<DhcpTransaction> {
        let map = self.inner.lock().unwrap();
        let mut transactions: Vec<DhcpTransaction> = map.values().cloned().collect();
        transactions.sort_by_key(|t| t.first_seen_unix_ms);
        transactions
    }
}