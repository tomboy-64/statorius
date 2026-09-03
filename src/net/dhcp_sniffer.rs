//! A continuous, entirely passive capture loop for DHCP traffic (UDP ports
//! 67/68), run only inside the elevated L2 helper process (see
//! `l2_helper`). Every decoded message is pushed into an unbounded channel
//! the helper relays to the GUI as `L2Message::DhcpEvent` - there's no
//! request/response here, just a stream of "here's what was seen".
//!
//! Deliberately **its own** capture handle, opened with `l2_engine`'s exact
//! `open_capture` (promiscuous, immediate mode, same snaplen/timeout) but
//! never the *same* handle the job engine uses for Ping/CheckDuplicate:
//! that one is read from inside `l2_engine`'s single-threaded, one-job-at-a-
//! time loop, and a continuous sniffer has no natural place to yield there.

use tokio::sync::{mpsc, oneshot};

use super::dhcp::{self, DhcpMessageWire};
use super::l2_engine::open_capture;
use super::l2_frame::{self, InterfaceContext};

/// Start the sniffer on its own blocking OS thread against `ctx` - the same
/// interface the job engine's own handle already opened. Returns the
/// channel it pushes decoded messages into, plus a one-shot that fires once
/// this capture handle has either opened or definitively failed to.
/// `Ok(())` means it's genuinely listening; `Err(reason)` means it never
/// got going - `l2_helper` relays this to the GUI as
/// `L2Message::DhcpSnifferStatus` specifically so that failure is visible
/// somewhere, rather than only in a console a built .exe typically doesn't
/// show.
///
/// Call only after the job engine's own handle has already opened
/// successfully (see `l2_engine::spawn_engine`) - never concurrently with
/// it. Two capture handles opening on the same interface at the same
/// moment isn't something every platform's capture driver handles cleanly.
pub fn spawn_dhcp_sniffer(
    ctx: InterfaceContext,
) -> (
    mpsc::UnboundedReceiver<DhcpMessageWire>,
    oneshot::Receiver<Result<(), String>>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::task::spawn_blocking(move || sniffer_loop(ctx, tx, ready_tx));
    (rx, ready_rx)
}

fn sniffer_loop(
    ctx: InterfaceContext,
    tx: mpsc::UnboundedSender<DhcpMessageWire>,
    ready_tx: oneshot::Sender<Result<(), String>>,
) {
    let mut cap = match open_capture(&ctx) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("failed to open '{}': {e}", ctx.name)));
            return;
        }
    };

    // Best-effort: a BPF filter here is purely a performance optimization
    // (avoids handing every non-DHCP packet on the wire to userspace just
    // to be immediately dropped by `decode_frame` below) - if it can't be
    // set for some reason, fall back to filtering in software instead of
    // giving up on DHCP capture entirely. Not treated as a startup failure.
    if let Err(e) = cap.filter("udp and (port 67 or port 68)", true) {
        eprintln!(
            "dhcp-sniffer: couldn't install a capture filter ({e}), \
             continuing without one (slower, not incorrect)"
        );
    }

    // The handle is open - genuinely ready to capture from here on. The
    // receiving end being gone (the helper already shut down) just means
    // there's no one left to signal; not this thread's problem to handle.
    let _ = ready_tx.send(Ok(()));

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(msg) = decode_frame(packet.data) {
                    // The GUI side dropped its receiver (L2 mode was
                    // deactivated, or the whole session is tearing down) -
                    // nothing left to do here.
                    if tx.send(msg).is_err() {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue, // a single bad read shouldn't kill the sniffer
        }
    }
}

/// Ethernet/VLAN -> IPv4 -> UDP -> DHCP, reusing exactly the same parsing
/// building blocks `l2_engine` uses for everything else - this is the one
/// function in this file that knows what a "DHCP packet" looks like on the
/// wire.
fn decode_frame(frame: &[u8]) -> Option<DhcpMessageWire> {
    let link = l2_frame::parse_link(frame)?;
    if !l2_frame::is_ipv4_ethertype(link.ethertype) {
        return None; // DHCP is IPv4-only (IPv6 has its own DHCPv6, not handled here)
    }
    let ip = l2_frame::parse_ipv4(&frame[link.payload_offset..])?;
    if ip.protocol != l2_frame::udp_protocol() {
        return None;
    }
    let l4 = &frame[link.payload_offset + ip.l4_offset..];
    let udp = l2_frame::parse_udp(l4)?;
    let is_dhcp_port = |p: u16| p == 67 || p == 68;
    if !is_dhcp_port(udp.source_port) || !is_dhcp_port(udp.destination_port) {
        return None; // the software fallback for when the BPF filter above didn't apply
    }
    dhcp::parse_dhcp_message(udp.payload, link.vlan)
}