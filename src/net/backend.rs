//! Pluggable ping backends.
//!
//! `run_continuous_ping` (in `net::mod`) only ever talks to a
//! `Box<dyn PingBackend>` - it doesn't know or care whether a ping happens
//! over a plain ICMP/TCP/UDP socket or a hand-built Ethernet/IP frame
//! injected via Npcap/libpcap (the L2 side). Every ping method is one
//! `PingBackend` impl; the continuous-ping loop, history
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

/// ICMP backend: a single long-lived `surge_ping::Pinger` per target -
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
        scope: u32,
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
        // The interface of a link-local IPv6 target; ignored for IPv4.
        pinger.scope_id(scope);
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

/// The socket address for a probe target; `scope` is the interface index of
/// a link-local IPv6 target (`0` = none, and always ignored for IPv4).
fn socket_addr(target: IpAddr, port: u16, scope: u32) -> std::net::SocketAddr {
    match target {
        IpAddr::V4(v4) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(v4, port)),
        IpAddr::V6(v6) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope)),
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
        ErrorKind::HostUnreachable => "host unreachable",
        ErrorKind::NetworkUnreachable => "network unreachable",
        _ => match raw {
            Some(113) | Some(10065) => "host unreachable",
            Some(101) | Some(10051) => "network unreachable",
            _ => return None,
        },
    };
    Some((short.to_owned(), format!("{short} (ICMP from the path, as reported by the OS: {e})")))
}

/// TCP "SYN ping": one connection attempt per round, read purely from how
/// the handshake's first leg is answered -
/// - SYN/ACK: port open, RTT = time until it arrived;
/// - RST: host is up, port closed (explicit reject);
/// - ICMP unreachable/admin-prohibited, surfaced by the OS: explicit reject
///   from the path;
/// - nothing: timeout (SYN or answer dropped / filtered).
///
/// Implemented with the kernel's `connect()` (no raw sockets, so it works
/// unprivileged and identically on Linux and Windows) - the stack therefore
/// also sends the final ACK of an open port. To keep the footprint as close
/// to a bare SYN probe as that allows, the socket is closed with a zero
/// linger: the teardown is a single RST right away instead of a FIN
/// exchange and TIME_WAIT state on either side. A truly half-open probe
/// (never ACKing the SYN/ACK) would need raw packet injection.
///
/// Holds no per-target state beyond the port, so a fresh `TcpSocket` is
/// created for every attempt (sockets can't be reused across `connect()`
/// calls anyway).
pub struct TcpConnectBackend {
    port: u16,
    scope: u32,
}

impl TcpConnectBackend {
    pub fn new(port: u16, scope: u32) -> Self {
        Self { port, scope }
    }
}

#[async_trait]
impl PingBackend for TcpConnectBackend {
    async fn ping_once(&mut self, target: IpAddr, _seq: u16) -> PingResult {
        let addr = socket_addr(target, self.port, self.scope);
        let socket = match if target.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        } {
            Ok(s) => s,
            Err(e) => return PingResult::Error(format!("socket create failed: {e}")),
        };
        // Best effort: if it fails, the close just falls back to a normal FIN.
        let _ = socket.set_zero_linger();

        let start = Instant::now();
        match timeout(TCP_TIMEOUT, socket.connect(addr)).await {
            // The stream is dropped right here -> RST (zero linger).
            Ok(Ok(_stream)) => PingResult::Success(start.elapsed()),
            Ok(Err(e)) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                    PingResult::Rejected {
                        short: "refused (RST)".to_owned(),
                        detail: format!(
                            "TCP RST in reply to the SYN: host is up, port {} is closed ({e})",
                            self.port
                        ),
                    }
                }
                _ => match classify_unreachable(&e) {
                    Some((short, detail)) => PingResult::Rejected { short, detail },
                    None => PingResult::Error(e.to_string()),
                },
            },
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
///   this is reported as `Silent` (shown neutrally, not as a failure)
///   rather than guessing "open" or "down".
pub struct UdpProbeBackend {
    port: u16,
    scope: u32,
}

impl UdpProbeBackend {
    pub fn new(port: u16, scope: u32) -> Self {
        Self { port, scope }
    }
}

impl UdpProbeBackend {
    /// Maps an I/O error from `send`/`recv` on the connected UDP socket:
    /// which error kind an ICMP Port Unreachable surfaces as differs by OS
    /// (`ConnectionRefused` on Linux/macOS, `ConnectionReset` on Windows),
    /// so both count as the explicit "port unreachable"; other unreachable
    /// codes map via `classify_unreachable`; anything else is a local error.
    fn io_failure(&self, e: std::io::Error) -> PingResult {
        if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
        ) {
            return PingResult::Rejected {
                short: "port unreachable".to_owned(),
                detail: format!(
                    "ICMP port unreachable for UDP/{}: host is up, nothing listens there ({e})",
                    self.port
                ),
            };
        }
        match classify_unreachable(&e) {
            Some((short, detail)) => PingResult::Rejected { short, detail },
            None => PingResult::Error(e.to_string()),
        }
    }
}

#[async_trait]
impl PingBackend for UdpProbeBackend {
    async fn ping_once(&mut self, target: IpAddr, _seq: u16) -> PingResult {
        let addr = socket_addr(target, self.port, self.scope);
        let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => return PingResult::Error(format!("socket bind failed: {e}")),
        };
        if let Err(e) = socket.connect(addr).await {
            return self.io_failure(e);
        }

        let start = Instant::now();
        if let Err(e) = socket.send(&[]).await {
            return self.io_failure(e);
        }

        let mut buf = [0u8; 512];
        match timeout(UDP_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(_n)) => PingResult::Success(start.elapsed()),
            Ok(Err(e)) => self.io_failure(e),
            Err(_) => PingResult::Silent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn socket_addr_carries_the_scope_only_for_ipv6() {
        let v6: IpAddr = "fe80::1".parse().unwrap();
        match socket_addr(v6, 443, 7) {
            std::net::SocketAddr::V6(a) => {
                assert_eq!((a.port(), a.scope_id()), (443, 7));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(socket_addr(LO, 80, 7).to_string(), "127.0.0.1:80");
    }

    #[tokio::test]
    async fn tcp_open_port_succeeds() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let r = TcpConnectBackend::new(port, 0).ping_once(LO, 0).await;
        assert!(matches!(r, PingResult::Success(_)), "{r:?}");
    }

    #[tokio::test]
    async fn tcp_closed_port_is_rejected_with_rst() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let r = TcpConnectBackend::new(port, 0).ping_once(LO, 0).await;
        match r {
            PingResult::Rejected { short, .. } => assert_eq!(short, "refused (RST)"),
            // Windows retransmits the SYN after a RST for about as long as
            // the probe's timeout, so the attempt can end as a timeout there.
            PingResult::Timeout if cfg!(windows) => {}
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_reply_succeeds() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = srv.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 16];
            if let Ok((_, from)) = srv.recv_from(&mut b).await {
                let _ = srv.send_to(b"x", from).await;
            }
        });
        let r = UdpProbeBackend::new(port, 0).ping_once(LO, 0).await;
        assert!(matches!(r, PingResult::Success(_)), "{r:?}");
    }

    #[tokio::test]
    async fn udp_closed_port_is_rejected() {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        let r = UdpProbeBackend::new(port, 0).ping_once(LO, 0).await;
        match r {
            PingResult::Rejected { short, .. } => assert_eq!(short, "port unreachable"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_silence_is_silent_not_failure() {
        // Bound but never answers: no ICMP unreachable, no reply.
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        let r = UdpProbeBackend::new(port, 0).ping_once(LO, 0).await;
        assert!(matches!(r, PingResult::Silent), "{r:?}");
        drop(s);
    }

    #[tokio::test]
    async fn tcp_unroutable_times_out_or_is_rejected() {
        // TEST-NET-1: sandbox may drop (Timeout) or answer unreachable.
        let r = TcpConnectBackend::new(80, 0)
            .ping_once(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0)
            .await;
        assert!(
            matches!(r, PingResult::Timeout | PingResult::Rejected { .. } | PingResult::Error(_)),
            "{r:?}"
        );
    }
}
