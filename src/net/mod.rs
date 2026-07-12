use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError, ICMP};
use tokio::sync::mpsc;

use crate::state::{PingMethod, PingRequest, PingResult, SharedState};

/// Payload size in bytes for outgoing ICMP echo requests. 56 bytes is the classic
/// default used by most `ping` implementations (64 bytes on the wire once the
/// 8-byte ICMP header is included).
const ICMP_PAYLOAD_SIZE: usize = 56;
const ICMP_TIMEOUT: Duration = Duration::from_secs(2);

/// The dispatcher loop. Receives ping requests from the UI, fires each one off
/// concurrently, and writes results straight into `state` - there is no results
/// channel back to the UI; `SharedState` is the single source of truth.
pub async fn ping_worker(mut rx: mpsc::Receiver<PingRequest>, state: SharedState) {
    // One long-lived client per address family. Creating a `Client` opens a socket,
    // so this happens once up front rather than per-request.
    let client_v4 = match Client::new(&Config::builder().kind(ICMP::V4).build()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!(
                "Failed to open ICMPv4 socket (try running with elevated privileges): {e}"
            );
            return;
        }
    };
    let client_v6 = match Client::new(&Config::builder().kind(ICMP::V6).build()) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            eprintln!("Failed to open ICMPv6 socket - IPv6 targets will report errors: {e}");
            None
        }
    };

    // Each in-flight ping needs a locally-unique identifier; a simple wrapping
    // counter is enough here since requests are handled concurrently but briefly.
    let mut next_ident: u16 = 1;

    while let Some(request) = rx.recv().await {
        state.ensure_target(request.target, request.method.clone());

        let ident = PingIdentifier(next_ident);
        next_ident = next_ident.wrapping_add(1);

        let state = state.clone();
        let client_v4 = client_v4.clone();
        let client_v6 = client_v6.clone();

        // Spawn a concurrent task per request so a slow/unreachable target never
        // blocks pings to other targets.
        tokio::spawn(async move {
            let result = match request.method {
                PingMethod::Icmp => {
                    run_icmp_ping(request.target, ident, &client_v4, client_v6.as_deref()).await
                }
                PingMethod::Tcp { port } => execute_tcp_ping(request.target, port).await,
            };
            state.record_result(request.target, result);
        });
    }
}

/// Send a single ICMP echo request and translate the outcome into a `PingResult`.
async fn run_icmp_ping(
    target: IpAddr,
    ident: PingIdentifier,
    client_v4: &Client,
    client_v6: Option<&Client>,
) -> PingResult {
    let client = if target.is_ipv6() {
        match client_v6 {
            Some(c) => c,
            None => return PingResult::Error("IPv6 ICMP socket unavailable".to_owned()),
        }
    } else {
        client_v4
    };

    let mut pinger = client.pinger(target, ident).await;
    pinger.timeout(ICMP_TIMEOUT);

    let payload = [0u8; ICMP_PAYLOAD_SIZE];
    match pinger.ping(PingSequence(0), &payload).await {
        Ok((_packet, rtt)) => PingResult::Success(rtt),
        Err(SurgeError::Timeout { .. }) => PingResult::Timeout,
        Err(e) => PingResult::Error(e.to_string()),
    }
}

/// TCP-connect "ping": treats a successful handshake as reachability.
async fn execute_tcp_ping(target: IpAddr, port: u16) -> PingResult {
    use std::time::Instant;
    use tokio::net::TcpSocket;
    use tokio::time::timeout;

    let addr = std::net::SocketAddr::new(target, port);
    let socket = match if target.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    } {
        Ok(s) => s,
        Err(e) => return PingResult::Error(format!("socket create failed: {e}")),
    };

    let start = Instant::now();
    match timeout(Duration::from_secs(2), socket.connect(addr)).await {
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