mod backend;
pub(crate) mod dhcp;
mod dhcp_sniffer;
pub(crate) mod dhcp_state;
pub(crate) mod dns;
mod l2_engine;
mod l2_frame;
pub(crate) mod l2_helper;
pub(crate) mod l2_ipc;
pub(crate) mod l2_manager;
pub(crate) mod l2_pinger;
pub(crate) mod l2;
mod windows_elevate;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, ICMP};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use backend::{IcmpSocketBackend, PingBackend, TcpConnectBackend};
use crate::state::{PingMethod, PingResult, SharedState, WorkerCommand};

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
    // One long-lived client per address family, used to build `IcmpSocketBackend`s.
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

    let mut handles: HashMap<IpAddr, TargetHandle> = HashMap::new();

    // Each continuous-ping loop needs a locally-unique ICMP identifier for its
    // whole lifetime.
    let mut next_ident: u16 = 1;

    while let Some(command) = rx.recv().await {
        match command {
            WorkerCommand::Start(request) => {
                let target = request.target;

                // Re-starting an already-running target replaces its loop
                // outright. We abort the old task AND await its actual
                // termination before spawning the replacement - otherwise a
                // straggling in-flight ping from the old generation can race
                // the new one to call `record_result`, landing a stale
                // sample out of order.
                if let Some(old) = handles.remove(&target) {
                    old.stop_flag.store(true, Ordering::Relaxed);
                    old.task.abort();
                    let _ = old.task.await;
                }

                state.ensure_target(target, request.method.clone());
                state.set_running(target, true);

                let ident = next_ident;
                next_ident = next_ident.wrapping_add(1);

                // Build the backend up front (this is the one and only place
                // that maps a `PingMethod` to a concrete `PingBackend` impl -
                // a future raw-L2 method would add one match arm here and
                // nothing else in this file would need to change).
                let backend: Box<dyn PingBackend> = match &request.method {
                    PingMethod::Icmp => {
                        match IcmpSocketBackend::new(
                            target,
                            PingIdentifier(ident),
                            &client_v4,
                            client_v6.as_deref(),
                        )
                            .await
                        {
                            Ok(b) => Box::new(b),
                            Err(msg) => {
                                state.record_result(target, PingResult::Error(msg));
                                state.set_running(target, false);
                                continue;
                            }
                        }
                    }
                    PingMethod::Tcp { port } => Box::new(TcpConnectBackend::new(*port)),
                };

                let stop_flag = Arc::new(AtomicBool::new(false));
                let task_stop_flag = stop_flag.clone();
                let task_state = state.clone();

                let task = tokio::spawn(async move {
                    run_continuous_ping(target, backend, task_state, task_stop_flag).await;
                });

                handles.insert(target, TargetHandle { stop_flag, task });
            }

            WorkerCommand::Stop(target) => {
                // Graceful: just raise the flag and let the loop wind down on
                // its own after finishing whatever ping is currently in
                // flight, then drop (detach) the handle. No `.abort()` here
                // on purpose.
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                }
                state.set_running(target, false);
            }

            WorkerCommand::Delete(target) => {
                if let Some(handle) = handles.remove(&target) {
                    handle.stop_flag.store(true, Ordering::Relaxed);
                    handle.task.abort();
                    let _ = handle.task.await;
                }
                state.remove(target);
            }
        }
    }
}

/// Runs one target's continuous ping loop until `stop_flag` is raised: ping,
/// record the result, wait out `PING_INTERVAL` (checking `stop_flag`
/// periodically), repeat. Entirely backend-agnostic - it doesn't know or care
/// whether `backend` is today's ICMP/TCP socket or a future raw-L2 impl.
async fn run_continuous_ping(
    target: IpAddr,
    mut backend: Box<dyn PingBackend>,
    state: SharedState,
    stop_flag: Arc<AtomicBool>,
) {
    let mut seq: u16 = 0;

    while !stop_flag.load(Ordering::Relaxed) {
        let result = backend.ping_once(target, seq).await;
        seq = seq.wrapping_add(1);

        // Don't record a straggling result for a loop that's already been
        // told to stop.
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        state.record_result(target, result);

        interruptible_sleep(PING_INTERVAL, &stop_flag).await;
    }
}

/// Sleep for `duration`, but wake up early (in `STOP_POLL_INTERVAL` steps) if
/// `stop_flag` gets set.
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