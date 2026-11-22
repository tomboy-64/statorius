//! Shared, GUI-side state for captured DHCP exchanges - populated by
//! `l2_manager` as `L2Message::DhcpEvent`s arrive (unsolicited) from the
//! helper's passive sniffer, read out (snapshotted) by the "DHCP" tab every
//! frame. Mirrors `l2_pinger::L2PingerState`'s shape: a lock-protected map
//! the background side writes into and the UI only ever reads a clone of.
//!
//! Messages are grouped by protocol version and DHCP transaction id
//! (`xid`), since that's the natural unit for "one exchange" - a
//! DISCOVER/OFFER/REQUEST/ACK (or SOLICIT/ADVERTISE/REQUEST/REPLY) all share
//! the same `xid`. Two genuinely unrelated exchanges *could* collide on
//! `xid` (it's only a 32-bit value - 24 bits in DHCPv6 - a client picks
//! itself, not guaranteed globally unique) - rare enough in practice, and
//! no worse than what any passive DHCP-watching tool does, so it isn't
//! specially handled here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::dhcp::{DhcpMessageWire, DhcpVersion};

/// Every captured message sharing one DHCP transaction id, in the order
/// they were captured.
#[derive(Debug, Clone)]
pub struct DhcpTransaction {
    pub version: DhcpVersion,
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
    inner: Arc<Mutex<BTreeMap<(DhcpVersion, u32), DhcpTransaction>>>,
    /// `L2Message::DhcpSnifferStatus`'s `error`, once it arrives - `None`
    /// until then (or once it's arrived and reported success). Separate
    /// from the transaction map since it's a one-shot startup outcome, not
    /// something that accumulates.
    sniffer_error: Arc<Mutex<Option<String>>>,
}

impl DhcpState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one newly-captured message, filing it under its version and
    /// `xid` - creating that transaction if this is the first message seen
    /// for it.
    pub fn record(&self, msg: DhcpMessageWire) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry((msg.version, msg.xid)).or_insert_with(|| DhcpTransaction {
            version: msg.version,
            xid: msg.xid,
            first_seen_unix_ms: msg.captured_at_unix_ms,
            messages: Vec::new(),
        });
        entry.messages.push(msg);
    }

    /// Record the sniffer's startup outcome - `None` means it's genuinely
    /// listening, `Some(reason)` means it never got going.
    pub fn set_sniffer_error(&self, error: Option<String>) {
        *self.sniffer_error.lock().unwrap() = error;
    }

    /// The sniffer's startup outcome, if it's arrived yet - what the DHCP
    /// tab checks to show an error banner instead of (or alongside) the
    /// usual empty-capture message.
    pub fn sniffer_error(&self) -> Option<String> {
        self.sniffer_error.lock().unwrap().clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(version: DhcpVersion, xid: u32, at: u64) -> DhcpMessageWire {
        DhcpMessageWire {
            captured_at_unix_ms: at,
            version,
            xid,
            message_type: String::new(),
            client_mac: None,
            ciaddr: None,
            yiaddr: None,
            siaddr: None,
            giaddr: None,
            vlan: None,
            options: Vec::new(),
            client_duid: None,
            server_duid: None,
            src_ip: None,
            dst_ip: None,
            addresses: Vec::new(),
        }
    }

    #[test]
    fn messages_group_by_version_and_xid() {
        let state = DhcpState::new();
        state.record(msg(DhcpVersion::V4, 7, 100));
        state.record(msg(DhcpVersion::V4, 7, 200));
        // The same number in DHCPv6 is a different exchange.
        state.record(msg(DhcpVersion::V6, 7, 150));
        let snapshot = state.snapshot();
        assert_eq!(snapshot.len(), 2);
        let v4 = snapshot.iter().find(|t| t.version == DhcpVersion::V4).unwrap();
        assert_eq!(v4.messages.len(), 2);
        assert_eq!(v4.first_seen_unix_ms, 100);
        // Oldest exchange first.
        assert_eq!(snapshot[0].version, DhcpVersion::V4);
        assert_eq!(snapshot[1].version, DhcpVersion::V6);
    }
}
