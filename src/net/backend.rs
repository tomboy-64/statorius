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
use surge_ping::{Client, PingIdentifier, PingSequence, Pinger, SurgeError};
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
            Ok((_packet, rtt)) => PingResult::Success(rtt),
            Err(SurgeError::Timeout { .. }) => PingResult::Timeout,
            Err(e) => PingResult::Error(e.to_string()),
        }
    }
}

/// Today's TCP-connect backend: treats a successful handshake as
/// reachability. Holds no per-target state beyond the port, so a fresh
/// `TcpSocket` is created for every attempt (sockets can't be reused across
/// `connect()` calls anyway).
pub struct TcpConnectBackend {
    port: u16,
}

impl TcpConnectBackend {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

#[async_trait]
impl PingBackend for TcpConnectBackend {
    async fn ping_once(&mut self, target: IpAddr, _seq: u16) -> PingResult {
        let addr = std::net::SocketAddr::new(target, self.port);
        let socket = match if target.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        } {
            Ok(s) => s,
            Err(e) => return PingResult::Error(format!("socket create failed: {e}")),
        };

        let start = Instant::now();
        match timeout(TCP_TIMEOUT, socket.connect(addr)).await {
            Ok(Ok(_stream)) => PingResult::Success(start.elapsed()),
            Ok(Err(e)) => {
                // A prompt "connection refused" still tells us the host is up.
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    PingResult::PortClosed
                } else {
                    PingResult::Error(e.to_string())
                }
            }
            Err(_) => PingResult::Timeout,
        }
    }
}

/// A "null" UDP probe: send an empty datagram to `port`, see what comes
/// back. UDP has no handshake, so there are only three possible outcomes,
/// not the two TCP has:
/// - a reply datagram arrives - definitely up, definitely listening;
/// - the OS surfaces an ICMP Port Unreachable it received for this flow as
///   a socket error on the next read - definitely up, this port is closed;
/// - silence - could mean an open port that had nothing to say back to an
///   empty datagram, or a filtered path; UDP can't tell those apart, so
///   this is reported as `Timeout` like any other non-response rather than
///   guessing "open".
pub struct UdpProbeBackend {
    port: u16,
}

impl UdpProbeBackend {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

#[async_trait]
impl PingBackend for UdpProbeBackend {
    async fn ping_once(&mut self, target: IpAddr, _seq: u16) -> PingResult {
        let addr = std::net::SocketAddr::new(target, self.port);
        let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => return PingResult::Error(format!("socket bind failed: {e}")),
        };
        if let Err(e) = socket.connect(addr).await {
            return PingResult::Error(format!("connect failed: {e}"));
        }

        let start = Instant::now();
        if let Err(e) = socket.send(&[]).await {
            return PingResult::Error(e.to_string());
        }

        let mut buf = [0u8; 512];
        match timeout(UDP_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(_n)) => PingResult::Success(start.elapsed()),
            // Which OS-level error kind an ICMP Port Unreachable surfaces
            // as on a connected UDP socket isn't fully nailed down across
            // platforms here - ConnectionRefused is the common Linux/macOS
            // shape, Windows has been seen to surface ConnectionReset for
            // the same condition - so both are treated as "port closed"
            // rather than only trusting one. Worth double-checking against
            // real Windows behavior once this is in front of it.
            Ok(Err(e))
            if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                ) =>
                {
                    PingResult::PortClosed
                }
            Ok(Err(e)) => PingResult::Error(e.to_string()),
            Err(_) => PingResult::Timeout,
        }
    }
}