//! A continuous, entirely passive capture loop for DHCP traffic (DHCPv4 on
//! UDP ports 67/68, DHCPv6 on 546/547), run only inside the elevated L2 helper process (see
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
use super::dhcpv6;
use super::l2_engine::open_capture;

/// BPF filter for the capture: UDP on the DHCPv4 (67/68) and DHCPv6
/// (546/547) ports, both address families.
const CAPTURE_FILTER: &str = "udp and (port 67 or port 68 or port 546 or port 547)";
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
    if let Err(e) = cap.filter(CAPTURE_FILTER, true) {
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
            Err(crate::pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue, // a single bad read shouldn't kill the sniffer
        }
    }
}

/// Ethernet/VLAN -> IPv4 -> UDP -> DHCPv4, or IPv6 -> UDP -> DHCPv6,
/// reusing exactly the same parsing building blocks `l2_engine` uses for
/// everything else - this is the one function in this file that knows what
/// a "DHCP packet" looks like on the wire.
fn decode_frame(frame: &[u8]) -> Option<DhcpMessageWire> {
    let link = l2_frame::parse_link(frame)?;
    let ip_payload = frame.get(link.payload_offset..)?;
    if l2_frame::is_ipv4_ethertype(link.ethertype) {
        let ip = l2_frame::parse_ipv4(ip_payload)?;
        if ip.protocol != l2_frame::udp_protocol() {
            return None;
        }
        let udp = l2_frame::parse_udp(ip_payload.get(ip.l4_offset..)?)?;
        let is_dhcp_port = |p: u16| p == 67 || p == 68;
        if !is_dhcp_port(udp.source_port) || !is_dhcp_port(udp.destination_port) {
            return None; // the software fallback for when the BPF filter above didn't apply
        }
        dhcp::parse_dhcp_message(udp.payload, link.vlan)
    } else if l2_frame::is_ipv6_ethertype(link.ethertype) {
        let ip = l2_frame::parse_ipv6(ip_payload)?;
        if ip.protocol != l2_frame::udp_protocol() {
            return None;
        }
        let udp = l2_frame::parse_udp(ip_payload.get(ip.l4_offset..)?)?;
        let is_dhcpv6_port = |p: u16| p == 546 || p == 547;
        if !is_dhcpv6_port(udp.source_port) || !is_dhcpv6_port(udp.destination_port) {
            return None;
        }
        dhcpv6::parse_dhcpv6_message(udp.payload, link.vlan, ip.source, ip.destination)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    /// Ethernet (optionally VLAN-tagged) + IPv6 + UDP + payload, built by hand.
    fn v6_frame(vlan: Option<u16>, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x33, 0x33, 0, 1, 0, 2]; // IPv6 multicast MAC for ff02::1:2
        f.extend(CLIENT_MAC);
        if let Some(v) = vlan {
            f.extend([0x81, 0x00]);
            f.extend(v.to_be_bytes());
        }
        f.extend([0x86, 0xdd]);
        let udp_len = (8 + payload.len()) as u16;
        f.extend([0x60, 0, 0, 0]); // version 6, class, flow
        f.extend(udp_len.to_be_bytes());
        f.extend([17, 1]); // next header UDP, hop limit
        f.extend(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
        f.extend(std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2).octets());
        f.extend(src_port.to_be_bytes());
        f.extend(dst_port.to_be_bytes());
        f.extend(udp_len.to_be_bytes());
        f.extend([0, 0]); // checksum (not checked)
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn dhcpv6_solicit_is_captured_from_a_frame() {
        let solicit = [1, 0xab, 0xcd, 0xef, 0, 8, 0, 2, 0, 0];
        let msg = decode_frame(&v6_frame(Some(20), 546, 547, &solicit)).unwrap();
        assert_eq!(msg.version, dhcp::DhcpVersion::V6);
        assert_eq!(msg.xid, 0x00ab_cdef);
        assert_eq!(msg.message_type, "SOLICIT");
        assert_eq!(msg.vlan, Some(20));
        assert_eq!(msg.src_ip.as_deref(), Some("fe80::1"));
        assert_eq!(msg.dst_ip.as_deref(), Some("ff02::1:2"));
    }

    /// Real DHCPv6 datagram over IPv6 loopback, through the same BPF filter
    /// and decoder as the live sniffer. Needs raw-socket privileges and
    /// working `::1` (and port 546 to bind); skipped without them.
    #[test]
    fn dhcpv6_on_loopback_passes_the_capture_filter() {
        use crate::pcap::{Capture, Device, Error};

        let Ok(devices) = Device::list() else { return };
        let Some(lo) = devices.into_iter().find(|d| d.flags.is_loopback()) else { return };
        let Ok(mut cap) = Capture::from_device(lo)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .timeout(100)
            .open()
        else {
            eprintln!("skipped: cannot open loopback (no privileges)");
            return;
        };
        cap.filter(CAPTURE_FILTER, true).unwrap();
        let Ok(client) = std::net::UdpSocket::bind("[::1]:546") else {
            eprintln!("skipped: cannot bind [::1]:546");
            return;
        };

        let solicit = [1, 0x12, 0x34, 0x56, 0, 8, 0, 2, 0, 0];
        let noise = std::net::UdpSocket::bind("[::1]:0").unwrap();
        for _ in 0..3 {
            noise.send_to(b"not dhcp", "[::1]:40000").unwrap();
            client.send_to(&solicit, "[::1]:547").unwrap();
        }
        let mut seen = None;
        for _ in 0..30 {
            match cap.next_packet() {
                Ok(p) => {
                    if let Some(msg) = decode_frame(p.data) {
                        seen = Some(msg);
                        break;
                    }
                }
                Err(Error::TimeoutExpired) => {}
                Err(e) => panic!("{e}"),
            }
        }
        let msg = seen.expect("the DHCPv6 datagram was not captured");
        assert_eq!(msg.xid, 0x12_3456);
        assert_eq!(msg.message_type, "SOLICIT");
        assert_eq!(msg.src_ip.as_deref(), Some("::1"));
    }

    #[test]
    fn other_udp_traffic_and_truncated_frames_are_ignored() {
        let solicit = [1, 0, 0, 1];
        assert!(decode_frame(&v6_frame(None, 5000, 5001, &solicit)).is_none());
        assert!(decode_frame(&v6_frame(None, 546, 547, &[])).is_none());
        let frame = v6_frame(None, 546, 547, &solicit);
        assert!(decode_frame(&frame[..30]).is_none(), "cut inside the IPv6 header");
        assert!(decode_frame(&[]).is_none());
    }
}
