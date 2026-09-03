//! The elevated L2 helper process. When the binary is invoked with
//! `--l2-helper <endpoint>`, `main()` runs this instead of the GUI: connect
//! back to the GUI over the local IPC endpoint, resolve the default
//! interface, bring up the job engine and the passive DHCP sniffer on it
//! (strictly in that order - see below), and then relay Ping/ArpPing/
//! DuplicateCheck requests (and stream captured DHCP messages) until told
//! to shut down.
//!
//! This is deliberately the *only* code path in the whole binary that ever
//! runs elevated - the GUI process, `state`, and everything the UI touches
//! stay unprivileged no matter what.

use std::sync::Arc;

use tokio::io::{AsyncWrite, BufReader};
use tokio::sync::{oneshot, Mutex};

use super::dhcp_sniffer;
use super::l2_engine::{self, L2DuplicateOutcome, L2Job, L2PingOutcome};
use super::l2_frame;
use super::l2_ipc::{self, L2DuplicateOutcomeWire, L2Message, L2PingOutcomeWire};

pub async fn run_l2_helper(endpoint: String) {
    let stream = match l2_ipc::connect(&endpoint).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("l2-helper: failed to connect back to the GUI: {e}");
            return;
        }
    };

    // Split so we can read incoming requests and write outgoing responses
    // concurrently - jobs can queue up and complete out-of-order relative to
    // each other (the engine still only ever runs one at a time; this split
    // just means the IPC connection itself isn't blocked while it does).
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let writer = Arc::new(Mutex::new(write_half));

    let ctx = match l2_frame::resolve_default_interface() {
        Ok(ctx) => ctx,
        Err(e) => {
            let _ = send(
                &writer,
                &L2Message::Failed {
                    reason: format!("No usable network interface: {e}"),
                },
            )
                .await;
            return;
        }
    };

    // The job engine's capture handle is the definitive test of whether
    // elevation actually got us raw access to this interface - opened and
    // awaited to completion *before* anything else touches the interface,
    // so there's never a moment where two capture handles are racing to
    // open the same device (some platforms' capture drivers don't tolerate
    // that cleanly).
    let (job_tx, engine_ready) = l2_engine::spawn_engine(ctx.clone());
    let engine_result = match engine_ready.await {
        Ok(result) => result,
        Err(_) => Err("engine thread ended before starting up".to_owned()),
    };
    if let Err(reason) = engine_result {
        let _ = send(&writer, &L2Message::Failed { reason }).await;
        return;
    }

    // Only now - with the engine's handle already open - does the DHCP
    // sniffer open its own, independent handle on the same interface.
    let (mut dhcp_rx, dhcp_ready) = dhcp_sniffer::spawn_dhcp_sniffer(ctx.clone());
    let dhcp_outcome = match dhcp_ready.await {
        Ok(result) => result,
        Err(_) => Err("sniffer thread ended before starting up".to_owned()),
    };
    if send(&writer, &L2Message::DhcpSnifferStatus { error: dhcp_outcome.err() }).await.is_err() {
        eprintln!("l2-helper: failed to report DHCP sniffer status to the GUI");
        return;
    }

    let detail = format!("Opened '{}' in promiscuous mode.", ctx.name);
    if send(&writer, &L2Message::Ready { detail }).await.is_err() {
        eprintln!("l2-helper: failed to report status to the GUI");
        return;
    }

    loop {
        tokio::select! {
            // Purely passive - decoded messages get relayed to the GUI as
            // soon as they arrive, with no id and no matching request; see
            // `L2Message::DhcpEvent`. `None` here means the sniffer thread
            // itself has exited (e.g. the interface disappeared) - nothing
            // to shut down over that; the rest of the helper keeps working.
            dhcp_msg = dhcp_rx.recv() => {
                let Some(dhcp_msg) = dhcp_msg else { continue };
                let _ = send(&writer, &L2Message::DhcpEvent(dhcp_msg)).await;
            }

            incoming = l2_ipc::recv_message(&mut reader) => {
        match incoming {
            Ok(Some(L2Message::Shutdown)) | Ok(None) => break,
            Ok(Some(L2Message::PingRequest {
                        id,
                        source_ip,
                        target,
                        vlan,
                        timeout_ms,
                    })) => {
                let (tx, rx) = oneshot::channel();
                let job = L2Job::Ping {
                    source_ip,
                    target,
                    vlan,
                    timeout: std::time::Duration::from_millis(timeout_ms as u64),
                    respond_to: tx,
                };
                if job_tx.send(job).await.is_err() {
                    let _ = send(
                        &writer,
                        &L2Message::PingResponse {
                            id,
                            outcome: L2PingOutcomeWire::Error("L2 engine unavailable".to_owned()),
                        },
                    )
                        .await;
                    continue;
                }
                // Each request's own wait happens on its own spawned task, so
                // a slow ping never blocks reading the *next* incoming
                // request off the connection - only the engine's single
                // dedicated thread enforces "one ping in flight at a time".
                let writer = writer.clone();
                tokio::spawn(async move {
                    let outcome = match rx.await {
                        Ok(L2PingOutcome::Success { rtt }) => L2PingOutcomeWire::Success {
                            rtt_ms: rtt.as_millis() as u64,
                        },
                        Ok(L2PingOutcome::Timeout) => L2PingOutcomeWire::Timeout,
                        Ok(L2PingOutcome::Error(e)) => L2PingOutcomeWire::Error(e),
                        Err(_) => L2PingOutcomeWire::Error("engine dropped the request".to_owned()),
                    };
                    let _ = send(&writer, &L2Message::PingResponse { id, outcome }).await;
                });
            }
            Ok(Some(L2Message::ArpPingRequest {
                        id,
                        source_ip,
                        target,
                        vlan,
                        timeout_ms,
                    })) => {
                let (tx, rx) = oneshot::channel();
                let job = L2Job::ArpPing {
                    source_ip,
                    target,
                    vlan,
                    timeout: std::time::Duration::from_millis(timeout_ms as u64),
                    respond_to: tx,
                };
                if job_tx.send(job).await.is_err() {
                    let _ = send(
                        &writer,
                        &L2Message::ArpPingResponse {
                            id,
                            outcome: L2PingOutcomeWire::Error("L2 engine unavailable".to_owned()),
                        },
                    )
                        .await;
                    continue;
                }
                let writer = writer.clone();
                tokio::spawn(async move {
                    let outcome = match rx.await {
                        Ok(L2PingOutcome::Success { rtt }) => L2PingOutcomeWire::Success {
                            rtt_ms: rtt.as_millis() as u64,
                        },
                        Ok(L2PingOutcome::Timeout) => L2PingOutcomeWire::Timeout,
                        Ok(L2PingOutcome::Error(e)) => L2PingOutcomeWire::Error(e),
                        Err(_) => L2PingOutcomeWire::Error("engine dropped the request".to_owned()),
                    };
                    let _ = send(&writer, &L2Message::ArpPingResponse { id, outcome }).await;
                });
            }
            Ok(Some(L2Message::TimestampPingRequest {
                        id,
                        source_ip,
                        target,
                        vlan,
                        timeout_ms,
                    })) => {
                let (tx, rx) = oneshot::channel();
                let job = L2Job::TimestampPing {
                    source_ip,
                    target,
                    vlan,
                    timeout: std::time::Duration::from_millis(timeout_ms as u64),
                    respond_to: tx,
                };
                if job_tx.send(job).await.is_err() {
                    let _ = send(
                        &writer,
                        &L2Message::TimestampPingResponse {
                            id,
                            outcome: L2PingOutcomeWire::Error("L2 engine unavailable".to_owned()),
                        },
                    )
                        .await;
                    continue;
                }
                let writer = writer.clone();
                tokio::spawn(async move {
                    let outcome = match rx.await {
                        Ok(L2PingOutcome::Success { rtt }) => L2PingOutcomeWire::Success {
                            rtt_ms: rtt.as_millis() as u64,
                        },
                        Ok(L2PingOutcome::Timeout) => L2PingOutcomeWire::Timeout,
                        Ok(L2PingOutcome::Error(e)) => L2PingOutcomeWire::Error(e),
                        Err(_) => L2PingOutcomeWire::Error("engine dropped the request".to_owned()),
                    };
                    let _ = send(&writer, &L2Message::TimestampPingResponse { id, outcome }).await;
                });
            }
            Ok(Some(L2Message::DuplicateCheckRequest {
                        id,
                        candidate,
                        vlan,
                        timeout_ms,
                    })) => {
                let (tx, rx) = oneshot::channel();
                let job = L2Job::CheckDuplicate {
                    candidate,
                    vlan,
                    timeout: std::time::Duration::from_millis(timeout_ms as u64),
                    respond_to: tx,
                };
                if job_tx.send(job).await.is_err() {
                    let _ = send(
                        &writer,
                        &L2Message::DuplicateCheckResponse {
                            id,
                            outcome: L2DuplicateOutcomeWire::Error(
                                "L2 engine unavailable".to_owned(),
                            ),
                        },
                    )
                        .await;
                    continue;
                }
                let writer = writer.clone();
                tokio::spawn(async move {
                    let outcome = match rx.await {
                        Ok(L2DuplicateOutcome::Clear) => L2DuplicateOutcomeWire::Clear,
                        Ok(L2DuplicateOutcome::Duplicate { macs }) => {
                            L2DuplicateOutcomeWire::Duplicate { macs }
                        }
                        Ok(L2DuplicateOutcome::Error(e)) => L2DuplicateOutcomeWire::Error(e),
                        Err(_) => {
                            L2DuplicateOutcomeWire::Error("engine dropped the request".to_owned())
                        }
                    };
                    let _ = send(&writer, &L2Message::DuplicateCheckResponse { id, outcome }).await;
                });
            }
            Ok(Some(_)) => continue, // Ready/Failed/etc. from us, not for us to receive
            Err(e) => {
                eprintln!("l2-helper: IPC error, exiting: {e}");
                break;
            }
        }
            }
        }
    }
}

async fn send<W>(writer: &Arc<Mutex<W>>, msg: &L2Message) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut guard = writer.lock().await;
    l2_ipc::send_message(&mut *guard, msg).await
}