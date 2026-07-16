//! Pluggable ping backends.
//!
//! `run_continuous_ping` (in `net::mod`) only ever talks to a
//! `Box<dyn PingBackend>` - it doesn't know or care whether a ping happens
//! over a plain ICMP/TCP socket (today) or a hand-built Ethernet/IP frame
//! injected via Npcap/libpcap (future L2 features). Every new ping method
//! just needs a new `PingBackend` impl; the continuous-ping loop, history
//! tracking, and start/stop/delete plumbing in `net::mod` and `state` never
//! have to change.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use surge_ping::{Client, PingIdentifier, PingSequence, Pinger, SurgeError};
use tokio::net::TcpSocket;
use tokio::time::timeout;

use crate::state::PingResult;

const ICMP_PAYLOAD_SIZE: usize = 56;
const ICMP_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

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
}

impl IcmpSocketBackend {
    pub async fn new(
        target: IpAddr,
        ident: PingIdentifier,
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
        Ok(Self { pinger })
    }
}

#[async_trait]
impl PingBackend for IcmpSocketBackend {
    async fn ping_once(&mut self, _target: IpAddr, seq: u16) -> PingResult {
        let payload = [0u8; ICMP_PAYLOAD_SIZE];
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