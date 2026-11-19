//! Pluggable ping backends.
//!
//! `run_continuous_ping` (in `net::mod`) only ever talks to a
//! `Box<dyn PingBackend>` - it doesn't know or care whether a ping happens
//! over a plain ICMP/TCP/UDP socket (today) or a hand-built Ethernet/IP
//! frame injected via Npcap/libpcap (the L2 side). Every new ping method
//! just needs a new `PingBackend` impl; the continuous-ping loop, history
//! tracking, and start/stop/delete plumbing in `net::mod` and `state` never
//! have to change.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use surge_ping::{Client, IcmpPacket, PingIdentifier, PingSequence, Pinger, SurgeError};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;

use crate::state::PingResult;

const ICMP_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_TIMEOUT: Duration = Duration::from_secs(2);

/// One pluggable way of performing a single ping attempt against a target.
#[async_trait]
pub trait PingBackend: Send {
    /// Perform exactly one ping attempt and return its outcome. `seq` is a
    /// monotonically increasing per-target counter, handed through so
    /// backends that need a wire-level sequence number (ICMP echo) don't
    /// have to track their own.
    async fn ping_once(&mut self, target: IpAddr, seq: u16) -> PingResult;
}

/// Today's ICMP backend: a single long-lived `surge_ping::Pinger` per target -
/// one identifier for the whole continuous-ping session, incrementing
/// sequence numbers per round, exactly what a real `ping` conversation looks
/// like on the wire.
pub struct IcmpSocketBackend {
    pinger: Pinger,
    /// Bytes of payload sent with every echo request - configurable (rather
    /// than fixed) so a target can be pinged with an oversized payload to
    /// probe for fragmentation/MTU issues along the path. The payload's
    /// content never matters for ICMP echo, only its size.
    payload_size: usize,
}

impl IcmpSocketBackend {
    pub async fn new(
        target: IpAddr,
        ident: PingIdentifier,
        payload_size: usize,
        client_v4: &Client,
        client_v6: Option<&Client>,
    ) -> Result<Self, String> {
        let client = if target.is_ipv6() {
            client_v6.ok_or_else(|| "IPv6 ICMP socket unavailable".to_owned())?
        } else {
            client_v4
        };
        let mut pinger = client.pinger(target, ident).await;
        pinger.timeout(ICMP_TIMEOUT);
        Ok(Self { pinger, payload_size })
    }
}

#[async_trait]
impl PingBackend for IcmpSocketBackend {
    async fn ping_once(&mut self, _target: IpAddr, seq: u16) -> PingResult {
        let payload = vec![0u8; self.payload_size];
        match self.pinger.ping(PingSequence(seq), &payload).await {
            // `surge_ping` hands back *any* ICMP message that quotes our
            // request - not just echo replies, but also destination
            // unreachable / time exceeded from a router on the path - so
            // the type has to be checked before calling it a success.
            Ok((packet, rtt)) => match classify_icmp_reply(&packet) {
                None => PingResult::Success(rtt),
                Some((short, detail)) => PingResult::Rejected { short, detail },
            },
            Err(SurgeError::Timeout { .. }) => PingResult::Timeout,
            Err(e) => PingResult::Error(e.to_string()),
        }
    }
}

/// `None` for a genuine echo reply; otherwise `(short, detail)` describing
/// the ICMP error that came back instead (and who sent it - usually a
/// router on the path, or the target itself).
fn classify_icmp_reply(packet: &IcmpPacket) -> Option<(String, String)> {
    let (family, ty, code, from) = match packet {
        IcmpPacket::V4(p) => ("ICMP", p.get_icmp_type().0, p.get_icmp_code().0, p.get_source().to_string()),
        IcmpPacket::V6(p) => ("ICMPv6", p.get_icmpv6_type().0, p.get_icmpv6_code().0, p.get_source().to_string()),
    };
    let v6 = matches!(packet, IcmpPacket::V6(_));

    // Echo reply: type 0 (ICMPv4) / 129 (ICMPv6).
    if (!v6 && ty == 0) || (v6 && ty == 129) {
        return None;
    }

    let short: &str = if !v6 {
        match (ty, code) {
            (3, 0) => "network unreachable",
            (3, 1) => "host unreachable",
            (3, 2) => "protocol unreachable",
            (3, 3) => "port unreachable",
            (3, 4) => "frag needed (DF set)",
            (3, 5) => "source route failed",
            (3, 6) | (3, 7) => "network/host unknown",
            (3, 9) | (3, 10) | (3, 13) => "administratively prohibited",
            (3, _) => "destination unreachable",
            (4, _) => "source quench",
            (5, _) => "redirect",
            (11, 0) => "TTL exceeded",
            (11, 1) => "reassembly time exceeded",
            (12, _) => "parameter problem",
            _ => "ICMP error",
        }
    } else {
        match (ty, code) {
            (1, 0) => "no route to host",
            (1, 1) => "administratively prohibited",
            (1, 2) => "beyond scope of source",
            (1, 3) => "address unreachable",
            (1, 4) => "port unreachable",
            (1, 5) => "source policy failed",
            (1, 6) => "reject route",
            (1, _) => "destination unreachable",
            (2, _) => "packet too big",
            (3, _) => "hop limit exceeded",
            (4, _) => "parameter problem",
            _ => "ICMPv6 error",
        }
    };
    Some((short.to_owned(), format!("{family} type {ty} code {code}: {short} (from {from})")))
}

/// Maps an I/O error that is really "the network told us no" (an ICMP
/// unreachable surfaced by the OS as `EHOSTUNREACH`/`ENETUNREACH`/...) to
/// `(short, detail)`. `None` for anything else - the caller decides whether
/// that is a plain local error.
fn classify_unreachable(e: &std::io::Error) -> Option<(String, String)> {
    use std::io::ErrorKind;
    // Raw errno / WSA codes as a fallback for platforms where std doesn't
    // map them to the dedicated kinds: Linux EHOSTUNREACH 113 / ENETUNREACH
    // 101, Windows WSAEHOSTUNREACH 10065 / WSAENETUNREACH 10051.
    let raw = e.raw_os_error();
    let short = match e.kind() {
        ErrorKind::HostUnreachable => "host