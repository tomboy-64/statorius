//! GUI-side orchestration for the L2 helper process: spawns it (elevated if
//! needed), completes the IPC handshake, keeps `SharedL2Status` in sync, and
//! relays Ping/DuplicateCheck job requests to it while active.
//!
//! Mirrors `state::SharedState`/`net::ping_worker`'s pattern for status
//! (commands in over a channel, status read out via a shared snapshot), and
//! adds a second channel (`L2JobRequest`) for anything that actually wants
//! to *use* L2 once it's active - today that's `net::l2_pinger`, but the
//! same channel is exactly what a future TCP/UDP L2 scan would use too.

use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{BufReader, WriteHalf};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

use super::l2::L2Readiness;
use super::l2_ipc::{
    self, L2DuplicateOutcomeWire, L2Message, L2PingOutcomeWire, ServerStream,
};

#[derive(Debug, Clone)]
pub enum L2Status {
    Inactive,
    Starting,
    Active { detail: String },
    Failed { reason: String },
}

impl Default for L2Status {
    fn default() -> Self {
        L2Status::Inactive
    }
}

#[derive(Clone, Default)]
pub struct SharedL2Status(Arc<Mutex<L2Status>>);

impl SharedL2Status {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> L2Status {
        self.0.lock().unwrap().clone()
    }

    fn set(&self, status: L2Status) {
        *self.0.lock().unwrap() = status;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum L2Command {
    Activate,
    Deactivate,
}

/// A request to actually *use* L2 once it's active - sent by anything that
/// wants to perform a raw ping or duplicate check (today: `l2_pinger`).
/// Fails immediately (not queued) if L2 isn't `Active` right now.
pub enum L2JobRequest {
    Ping {
        target: Ipv4Addr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2PingOutcomeWire>,
    },
    CheckDuplicate {
        target: Ipv4Addr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2DuplicateOutcomeWire>,
    },
}

impl L2JobRequest {
    fn fail_not_active(self) {
        let message = "L2 mode is not active".to_owned();
        match self {
            L2JobRequest::Ping { respond_to, .. } => {
                let _ = respond_to.send(L2PingOutcomeWire::Error(message));
            }
            L2JobRequest::CheckDuplicate { respond_to, .. } => {
                let _ = respond_to.send(L2DuplicateOutcomeWire::Error(message));
            }
        }
    }

    fn into_message_and_reply(self, id: u64) -> (L2Message, PendingReply) {
        match self {
            L2JobRequest::Ping {
                target,
                vlan,
                timeout,
                respond_to,
            } => (
                L2Message::PingRequest {
                    id,
                    target,
                    vlan,
                    timeout_ms: timeout.as_millis() as u32,
                },
                PendingReply::Ping(respond_to),
            ),
            L2JobRequest::CheckDuplicate {
                target,
                vlan,
                timeout,
                respond_to,
            } => (
                L2Message::DuplicateCheckRequest {
                    id,
                    target,
                    vlan,
                    timeout_ms: timeout.as_millis() as u32,
                },
                PendingReply::Duplicate(respond_to),
            ),
        }
    }
}

enum PendingReply {
    Ping(oneshot::Sender<L2PingOutcomeWire>),
    Duplicate(oneshot::Sender<L2DuplicateOutcomeWire>),
}

impl PendingReply {
    fn fail(self, message: String) {
        match self {
            PendingReply::Ping(tx) => {
                let _ = tx.send(L2PingOutcomeWire::Error(message));
            }
            PendingReply::Duplicate(tx) => {
                let _ = tx.send(L2DuplicateOutcomeWire::Error(message));
            }
        }
    }
}

/// How long we're willing to wait for the helper to launch, connect, and
/// report its status - covers a slow UAC/pkexec prompt, not just plain
/// process startup, so it's generous on purpose.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

struct L2Session {
    write_half: WriteHalf<ServerStream>,
    /// Owns the read half; forwards every message it reads into the
    /// `event_rx` the manager loop selects on. Aborting this on shutdown
    /// stops it promptly rather than waiting for a read to fail.
    reader_task: tokio::task::JoinHandle<()>,
    /// `Some` when we hold a real child handle (unprivileged spawn, or
    /// pkexec on Linux - pkexec itself is our direct child); `None` on
    /// Windows via `ShellExecuteW`, which never hands one back. Either way,
    /// shutdown goes through the IPC message first; this is only a
    /// best-effort backstop if that doesn't work.
    child: Option<Child>,
}

impl L2Session {
    async fn shutdown(mut self) {
        let _ = l2_ipc::send_message(&mut self.write_half, &L2Message::Shutdown).await;
        self.reader_task.abort();
        if let Some(mut child) = self.child {
            let waited = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
            if waited.is_err() {
                let _ = child.kill().await;
            }
        }
    }
}

/// The background task owning the L2 helper's whole lifecycle, plus relaying
/// job requests to it while it's active. Spawned once at startup.
pub async fn l2_manager_task(
    mut rx: mpsc::Receiver<L2Command>,
    mut job_rx: mpsc::Receiver<L2JobRequest>,
    status: SharedL2Status,
    readiness: L2Readiness,
) {
    let mut session: Option<L2Session> = None;
    let mut helper_rx: Option<mpsc::Receiver<L2Message>> = None;
    let mut pending: HashMap<u64, PendingReply> = HashMap::new();
    let mut next_id: u64 = 1;

    loop {
        tokio::select! {
            command = rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    L2Command::Activate => {
                        if session.is_some() {
                            continue; // already active or starting
                        }
                        if matches!(readiness, L2Readiness::Unavailable { .. }) {
                            // The UI shouldn't let this happen (checkbox
                            // disabled), but guard against it regardless.
                            continue;
                        }
                        status.set(L2Status::Starting);
                        match start_session(&readiness).await {
                            Ok((sess, events, detail)) => {
                                status.set(L2Status::Active { detail });
                                session = Some(sess);
                                helper_rx = Some(events);
                            }
                            Err(reason) => {
                                status.set(L2Status::Failed { reason });
                            }
                        }
                    }
                    L2Command::Deactivate => {
                        if let Some(sess) = session.take() {
                            sess.shutdown().await;
                        }
                        helper_rx = None;
                        status.set(L2Status::Inactive);
                        for (_, reply) in pending.drain() {
                            reply.fail("L2 mode was deactivated".to_owned());
                        }
                    }
                }
            }

            maybe_job = job_rx.recv() => {
                let Some(job) = maybe_job else { break };
                match &mut session {
                    Some(sess) => {
                        let id = next_id;
                        next_id += 1;
                        let (message, reply) = job.into_message_and_reply(id);
                        match l2_ipc::send_message(&mut sess.write_half, &message).await {
                            Ok(()) => {
                                pending.insert(id, reply);
                            }
                            Err(e) => {
                                reply.fail(format!("Failed to send request to L2 helper: {e}"));
                            }
                        }
                    }
                    None => job.fail_not_active(),
                }
            }

            // Only pollable while a session exists - the `if` guard means
            // this branch is simply skipped (not polled at all) otherwise,
            // which is what lets `helper_rx` be an `Option` here without a
            // borrow conflict with the other branches above.
            incoming = async { helper_rx.as_mut().unwrap().recv().await }, if helper_rx.is_some() => {
                match incoming {
                    Some(L2Message::PingResponse { id, outcome }) => {
                        if let Some(PendingReply::Ping(tx)) = pending.remove(&id) {
                            let _ = tx.send(outcome);
                        }
                    }
                    Some(L2Message::DuplicateCheckResponse { id, outcome }) => {
                        if let Some(PendingReply::Duplicate(tx)) = pending.remove(&id) {
                            let _ = tx.send(outcome);
                        }
                    }
                    Some(_) => {} // Ready/Failed/Shutdown aren't sent to us here
                    None => {
                        // The reader task ended - the helper disconnected
                        // unexpectedly (crash, killed, etc.), not via our
                        // own Deactivate path.
                        session = None;
                        helper_rx = None;
                        status.set(L2Status::Failed {
                            reason: "The L2 helper disconnected unexpectedly".to_owned(),
                        });
                        for (_, reply) in pending.drain() {
                            reply.fail("L2 helper disconnected".to_owned());
                        }
                    }
                }
            }
        }
    }
}

async fn start_session(
    readiness: &L2Readiness,
) -> Result<(L2Session, mpsc::Receiver<L2Message>, String), String> {
    let endpoint = l2_ipc::endpoint_name();
    let exe =
        env::current_exe().map_err(|e| format!("Couldn't locate our own executable: {e}"))?;

    // Create the IPC endpoint *before* spawning the helper, so the helper
    // can never race ahead of us and find nothing to connect to.
    let accept_fut = l2_ipc::listen_and_accept(&endpoint);
    tokio::pin!(accept_fut);

    let maybe_child = match readiness {
        L2Readiness::Ready { .. } => Some(
            spawn_unprivileged(&exe, &endpoint)
                .map_err(|e| format!("Failed to start the L2 helper: {e}"))?,
        ),
        L2Readiness::NeedsElevation { .. } => spawn_elevated(&exe, &endpoint)?,
        L2Readiness::Unavailable { .. } => {
            return Err("L2 is unavailable on this system.".to_owned());
        }
    };

    // Race the handshake against the child exiting early (e.g. a declined
    // pkexec/UAC prompt), so "Starting..." never hangs forever.
    let (stream, child) = match maybe_child {
        Some(mut child) => tokio::select! {
            accept_result = &mut accept_fut => {
                let stream = accept_result.map_err(|e| format!("IPC connection failed: {e}"))?;
                (stream, Some(child))
            }
            exit = child.wait() => {
                let code = exit.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                return Err(format!(
                    "The L2 helper exited before connecting (code {code}) - \
                     the elevation prompt may have been declined."
                ));
            }
        },
        None => {
            // Windows via ShellExecuteW: no child handle at all, just wait
            // for the connection (or time out).
            let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, &mut accept_fut)
                .await
                .map_err(|_| {
                    "Timed out waiting for the elevated helper to connect - \
                     the UAC prompt may have been declined."
                        .to_owned()
                })?
                .map_err(|e| format!("IPC connection failed: {e}"))?;
            (stream, None)
        }
    };

    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, l2_ipc::recv_message(&mut reader))
        .await
        .map_err(|_| "Timed out waiting for the L2 helper's status.".to_owned())?
        .map_err(|e| format!("IPC error waiting for status: {e}"))?;

    let detail = match handshake {
        Some(L2Message::Ready { detail }) => detail,
        Some(L2Message::Failed { reason }) => return Err(reason),
        Some(_) | None => {
            return Err("The L2 helper disconnected before reporting status.".to_owned())
        }
    };

    // From here on, a dedicated task owns the read half and just forwards
    // every subsequent message into a plain channel. This is what lets the
    // manager loop treat "is there a live connection" as an `Option` without
    // needing to hold a direct borrow of it across `select!`.
    let (event_tx, event_rx) = mpsc::channel::<L2Message>(64);
    let reader_task = tokio::spawn(async move {
        loop {
            match l2_ipc::recv_message(&mut reader).await {
                Ok(Some(msg)) => {
                    if event_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        // `event_tx` drops here; the manager loop sees that as `None`.
    });

    Ok((
        L2Session {
            write_half,
            reader_task,
            child,
        },
        event_rx,
        detail,
    ))
}

fn spawn_unprivileged(exe: &Path, endpoint: &str) -> std::io::Result<Child> {
    Command::new(exe)
        .arg("--l2-helper")
        .arg(endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

#[cfg(target_os = "linux")]
fn spawn_elevated(exe: &Path, endpoint: &str) -> Result<Option<Child>, String> {
    let child = Command::new("pkexec")
        .arg(exe)
        .arg("--l2-helper")
        .arg(endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to launch pkexec (is polkit installed?): {e}"))?;
    Ok(Some(child))
}

#[cfg(target_os = "windows")]
fn spawn_elevated(exe: &Path, endpoint: &str) -> Result<Option<Child>, String> {
    super::windows_elevate::shell_execute_runas(exe, &format!("--l2-helper {endpoint}"))?;
    Ok(None) // ShellExecuteW doesn't hand back a process handle
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn spawn_elevated(_exe: &Path, _endpoint: &str) -> Result<Option<Child>, String> {
    Err("Elevation isn't supported on this platform yet.".to_owned())
}
