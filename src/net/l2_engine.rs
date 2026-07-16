//! The L2 job engine: owns the one raw capture handle for the whole helper
//! process, and processes jobs **strictly one at a time** off a single
//! channel on a single dedicated OS thread. That's the entire mechanism
//! behind "never more than one ping in flight" - there's no concurrency here
//! to reason about, by construction, not by a lock we have to remember to
//! take.
//!
//! `L2Job` is deliberately the extension point for future scan methods: a
//! `TcpConnectScan`/`UdpNullScan` variant would reuse `l2_frame`'s Ethernet/
//! VLAN/IPv4 building blocks and this same one-at-a-time processing loop -
//! only the L4 build/match logic in a new `do_*` function would be new.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::util::MacAddr;
use tokio::sync::{mpsc, oneshot};

use super::l2_frame::{
    self, build_arp_request, build_ethernet_frame, build_icmp_echo_request, build_ipv4_packet,
    parse_arp_reply, parse_icmp_echo_reply, parse_ipv4, parse_link, InterfaceContext,
    BROADCAST_MAC,
};

/// One outstanding piece of work for the engine. Each variant carries its
/// own `oneshot` reply channel, so callers just `await` their own result
/// without needing to correlate anything themselves - that bookkeeping
/// happens one layer up, in `l2_helper`, which maps IPC request ids to these
/// oneshots.
pub enum L2Job {
    Ping {
        target: Ipv4Addr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2PingOutcome>,
    },
    CheckDuplicate {
        target: Ipv4Addr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2DuplicateOutcome>,
    },
}

#[derive(Debug, Clone)]
pub enum L2PingOutcome {
    Success { rtt: Duration },
    Timeout,
    Error(String),
}

#[derive(Debug, Clone)]
pub enum L2DuplicateOutcome {
    /// Zero or one distinct MAC answered - nothing to flag.
    Clear,
    /// More than one distinct MAC answered for the same IP.
    Duplicate { macs: Vec<String> },
    Error(String),
}

/// Start the engine on its own blocking OS thread and return the channel to
/// send jobs to it. Call once, from the helper process's startup.
pub fn spawn_engine() -> mpsc::Sender<L2Job> {
    let (tx, rx) = mpsc::channel::<L2Job>(64);
    tokio::task::spawn_blocking(move || engine_loop(rx));
    tx
}

fn engine_loop(mut rx: mpsc::Receiver<L2Job>) {
    let ctx = match l2_frame::resolve_default_interface() {
        Ok(c) => c,
        Err(e) => {
            drain_with_error(&mut rx, format!("No usable network interface: {e}"));
            return;
        }
    };

    let mut cap = match open_capture(&ctx.name) {
        Ok(c) => c,
        Err(e) => {
            drain_with_error(&mut rx, format!("Failed to open '{}': {e}", ctx.name));
            return;
        }
    };

    // IP -> MAC, so a continuously-pinged target doesn't need a fresh ARP
    // resolution every single round.
    let mut arp_cache: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let mut next_identifier: u16 = 1;

    while let Some(job) = rx.blocking_recv() {
        match job {
            L2Job::Ping {
                target,
                vlan,
                timeout,
                respond_to,
            } => {
                let ident = next_identifier;
                next_identifier = next_identifier.wrapping_add(1);
                let outcome = do_ping(&mut cap, &ctx, &mut arp_cache, target, vlan, ident, timeout);
                let _ = respond_to.send(outcome);
            }
            L2Job::CheckDuplicate {
                target,
                vlan,
                timeout,
                respond_to,
            } => {
                let outcome = do_duplicate_check(&mut cap, &ctx, target, vlan, timeout);
                let _ = respond_to.send(outcome);
            }
        }
    }
}

fn drain_with_error(rx: &mut mpsc::Receiver<L2Job>, message: String) {
    while let Some(job) = rx.blocking_recv() {
        match job {
            L2Job::Ping { respond_to, .. } => {
                let _ = respond_to.send(L2PingOutcome::Error(message.clone()));
            }
            L2Job::CheckDuplicate { respond_to, .. } => {
                let _ = respond_to.send(L2DuplicateOutcome::Error(message.clone()));
            }
        }
    }
}

fn open_capture(interface_name: &str) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or(pcap::Error::PcapError(format!(
            "interface '{interface_name}' not found by pcap"
        )))?;
    pcap::Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .timeout(100)
        .open()
}

/// Read captured frames for up to `deadline`, calling `on_frame` for each -
/// return early as soon as `on_frame` returns `Some`. Shared by ARP
/// resolution, duplicate-checking, and ICMP echo waiting; a future TCP/UDP
/// job would use this exact same helper with a different `on_frame` matcher.
fn read_until<T>(
    cap: &mut pcap::Capture<pcap::Active>,
    deadline: Instant,
    mut on_frame: impl FnMut(&[u8]) -> Option<T>,
) -> Option<T> {
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(result) = on_frame(packet.data) {
                    return Some(result);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue, // a single bad read shouldn't abort the whole wait
        }
    }
    None
}

/// Resolve `target`'s MAC via ARP (checking the cache first), taking the
/// *first* reply - used for actually routing a ping, as opposed to
/// `do_duplicate_check`, which deliberately keeps listening for more.
fn resolve_mac(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    cache: &mut HashMap<Ipv4Addr, MacAddr>,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> Result<MacAddr, String> {
    if let Some(mac) = cache.get(&target) {
        return Ok(*mac);
    }

    let arp_payload = build_arp_request(ctx.mac, ctx.ipv4, target);
    let frame = build_ethernet_frame(BROADCAST_MAC, ctx.mac, vlan, 0x0806, &arp_payload);
    cap.sendpacket(frame)
        .map_err(|e| format!("Failed to send ARP request: {e}"))?;

    let deadline = Instant::now() + timeout;
    let found = read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_arp_ethertype(link.ethertype) {
            return None;
        }
        let (sender_ip, sender_mac) = parse_arp_reply(&data[link.payload_offset..])?;
        (sender_ip == target).then_some(sender_mac)
    });

    match found {
        Some(mac) => {
            cache.insert(target, mac);
            Ok(mac)
        }
        None => Err(format!("ARP resolution for {target} timed out")),
    }
}

fn do_ping(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    arp_cache: &mut HashMap<Ipv4Addr, MacAddr>,
    target: Ipv4Addr,
    vlan: Option<u16>,
    identifier: u16,
    timeout: Duration,
) -> L2PingOutcome {
    // On-link targets are ARPed directly; anything else is routed via the
    // default gateway's MAC (the IP header still names the real target -
    // this is exactly what normal IP routing does at L2).
    let resolve_target = if ctx.is_on_link(target) {
        target
    } else {
        match ctx.gateway {
            Some(gw) => gw,
            None => {
                return L2PingOutcome::Error(
                    "Target is off-link and no default gateway is known".to_owned(),
                );
            }
        }
    };

    let dst_mac = match resolve_mac(cap, ctx, arp_cache, resolve_target, vlan, timeout) {
        Ok(mac) => mac,
        Err(e) => return L2PingOutcome::Error(e),
    };

    let icmp_payload = build_icmp_echo_request(identifier, 0);
    let ip_packet = build_ipv4_packet(ctx.ipv4, target, l2_frame::icmp_protocol(), identifier, &icmp_payload);
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x0800, &ip_packet);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send ICMP echo: {e}"));
    }

    let deadline = sent_at + timeout;
    let matched = read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_ipv4_ethertype(link.ethertype) {
            return None;
        }
        let ip = parse_ipv4(&data[link.payload_offset..])?;
        if ip.source != target || ip.destination != ctx.ipv4 {
            return None;
        }
        let l4 = &data[link.payload_offset + ip.l4_offset..];
        let (reply_ident, _seq) = parse_icmp_echo_reply(l4)?;
        (reply_ident == identifier).then_some(())
    });

    match matched {
        Some(()) => L2PingOutcome::Success {
            rtt: sent_at.elapsed(),
        },
        None => L2PingOutcome::Timeout,
    }
}

/// ARP for `target` and keep listening for the *whole* window rather than
/// stopping at the first reply, collecting every distinct MAC that answers.
/// More than one distinct MAC answering the same IP is an unambiguous
/// duplicate; fewer than two is not - though a duplicate host that simply
/// doesn't answer within the window will be missed (see the explanation
/// given alongside this feature).
fn do_duplicate_check(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcome {
    let arp_payload = build_arp_request(ctx.mac, ctx.ipv4, target);
    let frame = build_ethernet_frame(BROADCAST_MAC, ctx.mac, vlan, 0x0806, &arp_payload);
    if let Err(e) = cap.sendpacket(frame) {
        return L2DuplicateOutcome::Error(format!("Failed to send ARP request: {e}"));
    }

    let mut seen: Vec<MacAddr> = Vec::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let Some(link) = parse_link(packet.data) else {
                    continue;
                };
                if link.vlan != vlan || !l2_frame::is_arp_ethertype(link.ethertype) {
                    continue;
                }
                let Some((sender_ip, sender_mac)) = parse_arp_reply(&packet.data[link.payload_offset..])
                else {
                    continue;
                };
                if sender_ip == target && !seen.contains(&sender_mac) {
                    seen.push(sender_mac);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }

    if seen.len() > 1 {
        L2DuplicateOutcome::Duplicate {
            macs: seen.iter().map(|m| m.to_string()).collect(),
        }
    } else {
        L2DuplicateOutcome::Clear
    }
}
