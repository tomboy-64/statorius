use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError, ICMP};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::state::{PingMethod, PingRequest, PingResult, SharedState, WorkerCommand};

/// Payload size in bytes for outgoing ICMP echo requests. 56 bytes is the classic
/// default used by most `ping` implementations (64 bytes on the wire once the
/// 8-byte ICMP header is included).
const ICMP_PAYLOAD_SIZE: usize = 56;
const ICMP_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between successive pings to the same target once its continuous loop
/// is running - mirrors the classic `ping` utility's 1-second cadence.
const PING_INTERVAL: Duration = Duration::from_secs(1);

/// Granularity at which a target's loop re-checks its stop flag while waiting
/// out `PING_INTERVAL`, so pressing "Stop" feels close to instant.
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Everything needed to control one target's in-flight continuous-ping task.
struct TargetHandle {
    stop_flag: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

/// The dispatcher loop. Receives Start/Stop/Delete commands from the UI and
/// maintains one continuous-ping task per target, writing every result
/// straight into `state` - there is no results channel back to the UI;
/// `SharedState` is the single source of truth.
pub async fn ping_worker(mut rx: mpsc::Receiver<WorkerCommand>, state: SharedState) {
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

    // One entry per target that currently has a running (or just-stopped-but-
    // not-yet-cleaned-up) continuous-ping task.
    let mut handles: HashMap<IpAddr, TargetHandle> = HashMap::new();

    // Each continuous-ping loop needs a locally-unique ICMP identifier for its
    // whole lifetime (one identifier, incrementing sequence numbers per round -
    // exactly what a real `ping` conversation looks like on the wire).
    let mut next_ident: u16 = 1;

    while let Some(command) = rx.recv().await {
        match command {
            WorkerCommand::Start(request) => {
                let target = request.target;

                // Re-starting an already-running target replaces its loop outright
                // (fresh identifier, fresh interval) rather than stacking a second
                // one on top - abort immediately so the new loop takes over
                // without waiting on the old loop's current in-flight ping.
                if let Some(old) = handles.remove(&target) {
                    old.stop_flag.store(true, Ordering::Relaxed);
                    old.task.abort();
                }

                state.ensure_target(target, request.method.clone());
                state.set_running(target, true);

                let ident = next_ident;
                next_ident = next_ident.wrapping_add(1);

                let stop_flag = Arc::new(AtomicBool::new(false));
                let task_stop_flag = stop_flag.clone();
                let task_state = state.clone();
                let task_client_v4 = client_v4.clone();
                let task_client_v6 = client_v6.clone();

                let task = tokio::spawn(async move {
                    run_continuous_ping(
                        request,
                        ident,
                        task_state,
                        task_stop_flag,
                        task_client_v4,
                        task_client_v6,
                    )
                        .await;
                });

                handles.insert(target, TargetHandle { stop_flag, task });
            }

            WorkerCommand::Stop(target) => {
                // Graceful: just raise the flag and let the loop wind down on its
                // own after finishing whatever ping is currently in flight, then
                // drop (detach) the handle. No `.abort()` here on purpose.
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                }
                state.set_running(target, false);
            }

            WorkerCommand::Delete(target) => {
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                    handle.task.abort();
                }
                state.remove(target);
            }
        }
    }
}

/// Runs one target's continuous ping loop until `stop_flag` is raised: ping,
/// record the result, wait out `PING_INTERVAL` (checking `stop_flag`
/// periodically so a stop request is picked up promptly), repeat.
async fn run_continuous_ping(
    request: PingRequest,
    ident: u16,
    state: SharedState,
    stop_flag: Arc<AtomicBool>,
    client_v4: Arc<Client>,
    client_v6: Option<Arc<Client>>,
) {
    // For ICMP we keep a single `Pinger` alive for the whole loop (one
    // identifier, incrementing sequence numbers per round) instead of opening a
    // fresh conversation every second.
    let mut icmp_pinger = if matches!(request.method, PingMethod::Icmp) {
        let client: &Client = if request.target.is_ipv6() {
            match client_v6.as_deref() {
                Some(c) => c,
                None => {
                    state.record_result(
                        request.target,
                        PingResult::Error("IPv6 ICMP socket unavailable".to_owned()),
                    );
                    state.set_running(request.target, false);
                    return;
                }
            }
        } else {
            &client_v4
        };
        let mut pinger = client.pinger(request.target, PingIdentifier(ident)).await;
        pinger.timeout(ICMP_TIMEOUT);
        Some(pinger)
    } else {
        None
    };

    let mut seq: u16 = 0;

    while !stop_flag.load(Ordering::Relaxed) {
        let result = match (&request.method, &mut icmp_pinger) {
            (PingMethod::Icmp, Some(pinger)) => {
                let payload = [0u8; ICMP_PAYLOAD_SIZE];
                match pinger.ping(PingSequence(seq), &payload).await {
                    Ok((_packet, rtt)) => PingResult::Success(rtt),
                    Err(SurgeError::Timeout { .. }) => PingResult::Timeout,
                    Err(e) => PingResult::Error(e.to_string()),
                }
            }
            (PingMethod::Tcp { port }, _) => execute_tcp_ping(request.target, *port).await,
            // Only reachable if the IPv6 socket was unavailable and we somehow
            // got here anyway; the early-return above handles the normal case.
            _ => PingResult::Error("ICMP socket unavailable".to_owned()),
        };
        seq = seq.wrapping_add(1);

        // Don't record a straggling result for a loop that's already been told
        // to stop - avoids a "just resumed" restart briefly showing a sample
        // from before it was paused.
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        state.record_result(request.target, result);

        interruptible_sleep(PING_INTERVAL, &stop_flag).await;
    }
}

/// Sleep for `duration`, but wake up early (in `STOP_POLL_INTERVAL` steps) if
/// `stop_flag` gets set - keeps "Stop" feeling responsive without needing a
/// dedicated cancellation channel per target.
async fn interruptible_sleep(duration: Duration, stop_flag: &AtomicBool) {
    let mut remaining = duration;
    while remaining > Duration::ZERO {
        if stop_flag.load(Ordering::Relaxed) {
            return;
        }
        let step = remaining.min(STOP_POLL_INTERVAL);
        tokio::time::sleep(step).await;
        remaining = remaining.saturating_sub(step);
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