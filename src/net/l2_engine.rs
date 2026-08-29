//! The L2 job engine: owns the one raw capture handle for the whole helper
//! process, and processes jobs **strictly one at a time** off a single
//! channel on a single dedicated OS thread. That's the entire mechanism
//! behind "never more than one ping in flight" - there's no concurrency here
//! to reason about, by construction, not by a lock we have to remember to
//! take.
//!
//! Every job branches on `IpAddr::V4`/`V6` right at the top - V4 uses ARP +
//! ICMPv4 (as before), V6 uses NDP + ICMPv6 (see `l2_frame` for both). The
//! actual send/wait/match loop shape is identical either way; only frame
//! construction and reply matching differ.
//!
//! Duplicate checking is about the *source* IP the user intends to ping
//! from, not the ping target: before claiming an address as ours, we check
//! whether anyone else already answers for it, using the standard
//! address-availability probes (RFC 5227 ARP Probe for V4, RFC 4862
//! Duplicate Address Detection for V6) - both of which use an *unspecified*
//! sender address, distinct from the normal "I'm already using this
//! address" resolution request `resolve_mac` sends when actually routing a
//! ping.
//!
//! `L2Job` is deliberately the extension point for future scan methods -
//! `ArpPing` (below) is the first of those; a `TcpConnectScan`/`UdpNullScan`
//! variant would follow the same shape, reusing `l2_frame`'s Ethernet/VLAN/
//! IPv4/IPv6 building blocks and this same one-at-a-time processing loop -
//! only the L4 build/match logic in a new `do_*` function would be new.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use pnet_base::MacAddr;
use tokio::sync::{mpsc, oneshot};

use super::l2_frame::{
    self, build_arp_probe, build_arp_reply, build_arp_request, build_ethernet_frame,
    build_icmp_echo_request, build_icmp_timestamp_request, build_icmpv6_echo_request,
    build_ipv4_packet, build_ipv6_packet, build_neighbor_advertisement, build_neighbor_solicitation,
    multicast_mac_for_ipv6, parse_arp_reply, parse_arp_request, parse_icmp_echo_reply,
    parse_icmp_timestamp_reply, parse_icmpv6_echo_reply, parse_ipv4, parse_ipv6, parse_link,
    parse_neighbor_advertisement, parse_neighbor_solicitation, solicited_node_multicast,
    InterfaceContext, BROADCAST_MAC,
};

/// One outstanding piece of work for the engine. Each variant carries its
/// own `oneshot` reply channel, so callers just `await` their own result
/// without needing to correlate anything themselves - that bookkeeping
/// happens one layer up, in `l2_helper`, which maps IPC request ids to these
/// oneshots. Addresses being plain `IpAddr` (rather than separate V4/V6
/// variants) keeps the job type - and everything above it in
/// `l2_manager`/`l2_pinger` - address-family-agnostic; only this file
/// actually branches on which family it is.
pub enum L2Job {
    /// Ping `target`, using `source_ip` as the packet's source address (the
    /// address the user intends to send *from* - not necessarily this
    /// interface's own configured address).
    Ping {
        source_ip: IpAddr,
        target: IpAddr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2PingOutcome>,
    },
    /// Same idea as `Ping`, but a bare ARP (V4) / Neighbor Solicitation
    /// (V6) exchange instead of a full ICMP echo - see `do_arp_ping`.
    ArpPing {
        source_ip: IpAddr,
        target: IpAddr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2PingOutcome>,
    },
    /// Same idea as `Ping`, but an ICMP Timestamp request/reply (type
    /// 13/14) instead of echo - IPv4-only, no ICMPv6 equivalent (see
    /// `l2_frame`'s dedicated section). Useful as a second data point:
    /// some stacks/firewalls let one ICMP type through while blocking
    /// another.
    TimestampPing {
        source_ip: IpAddr,
        target: IpAddr,
        vlan: Option<u16>,
        timeout: Duration,
        respond_to: oneshot::Sender<L2PingOutcome>,
    },
    /// Check whether `candidate` (an address the user is considering using
    /// as a source) is already claimed by someone else on the network.
    CheckDuplicate {
        candidate: IpAddr,
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

    let mut cap = match open_capture(&ctx) {
        Ok(c) => c,
        Err(e) => {
            drain_with_error(&mut rx, format!("Failed to open '{}': {e}", ctx.name));
            return;
        }
    };

    // IP -> MAC, so a continuously-pinged target doesn't need a fresh
    // ARP/NDP resolution every single round. Shared across both address
    // families since `IpAddr` already distinguishes them.
    let mut neighbor_cache: HashMap<IpAddr, MacAddr> = HashMap::new();
    let mut next_identifier: u16 = 1;

    while let Some(job) = rx.blocking_recv() {
        match job {
            L2Job::Ping {
                source_ip,
                target,
                vlan,
                timeout,
                respond_to,
            } => {
                let ident = next_identifier;
                next_identifier = next_identifier.wrapping_add(1);
                let outcome = do_ping(
                    &mut cap,
                    &ctx,
                    &mut neighbor_cache,
                    source_ip,
                    target,
                    vlan,
                    ident,
                    timeout,
                );
                let _ = respond_to.send(outcome);
            }
            L2Job::ArpPing {
                source_ip,
                target,
                vlan,
                timeout,
                respond_to,
            } => {
                let outcome = do_arp_ping(&mut cap, &ctx, source_ip, target, vlan, timeout);
                let _ = respond_to.send(outcome);
            }
            L2Job::TimestampPing {
                source_ip,
                target,
                vlan,
                timeout,
                respond_to,
            } => {
                let ident = next_identifier;
                next_identifier = next_identifier.wrapping_add(1);
                let outcome = do_timestamp_ping(
                    &mut cap,
                    &ctx,
                    &mut neighbor_cache,
                    source_ip,
                    target,
                    vlan,
                    ident,
                    timeout,
                );
                let _ = respond_to.send(outcome);
            }
            L2Job::CheckDuplicate {
                candidate,
                vlan,
                timeout,
                respond_to,
            } => {
                let outcome = do_duplicate_check(&mut cap, &ctx, candidate, vlan, timeout);
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
            L2Job::ArpPing { respond_to, .. } => {
                let _ = respond_to.send(L2PingOutcome::Error(message.clone()));
            }
            L2Job::TimestampPing { respond_to, .. } => {
                let _ = respond_to.send(L2PingOutcome::Error(message.clone()));
            }
            L2Job::CheckDuplicate { respond_to, .. } => {
                let _ = respond_to.send(L2DuplicateOutcome::Error(message.clone()));
            }
        }
    }
}

/// `pub(crate)` (not just `fn`) so `dhcp_sniffer` can open its own,
/// independent capture handle on the same interface with the exact same
/// settings, rather than duplicating them - it never shares *this* handle,
/// since that would mean competing with the job engine's one-at-a-time
/// send/wait loop for reads.
///
/// Matches by name first (works as-is on Linux/macOS, where `default-net`
/// and `pcap` both report the plain OS interface name, e.g. "eth0") and
/// falls back to matching by this interface's own IPv4 address. The
/// fallback is what actually matters on Windows: `default-net` sets
/// `InterfaceContext::name` from `GetAdaptersAddresses`'s `AdapterName`,
/// which is the bare adapter GUID (e.g. "{4D36E972-...}"), while Npcap
/// names the same device "\\Device\\NPF_{4D36E972-...}" - never equal, so a
/// name-only match here silently failed on every Windows machine
/// regardless of privileges. Matching by address sidesteps the naming
/// convention entirely.
pub(crate) fn open_capture(ctx: &InterfaceContext) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
    let target_ip = IpAddr::V4(ctx.ipv4);
    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == ctx.name || d.addresses.iter().any(|a| a.addr == target_ip))
        .ok_or_else(|| {
            pcap::Error::PcapError(format!(
                "no pcap device found matching interface '{}' (name or address {})",
                ctx.name, ctx.ipv4
            ))
        })?;
    pcap::Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .timeout(100)
        .open()
}

/// Read captured frames for up to `deadline`, calling `on_frame` for each -
/// return early as soon as `on_frame` returns `Some`. Shared by ARP/NDP
/// resolution, duplicate-checking, and ICMP(v6) echo waiting; a future
/// TCP/UDP job would use this exact same helper with a different `on_frame`
/// matcher.
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

/// Resolve `target`'s MAC (checking the cache first), dispatching to ARP
/// (V4) or NDP (V6). Takes the *first* reply - used for actually routing a
/// ping (a genuine "I'm here, who are you" exchange), as opposed to
/// `do_duplicate_check`, which uses an unspecified sender and deliberately
/// keeps listening for more than one reply.
fn resolve_mac(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    cache: &mut HashMap<IpAddr, MacAddr>,
    target: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> Result<MacAddr, String> {
    if let Some(mac) = cache.get(&target) {
        return Ok(*mac);
    }

    let mac = match target {
        IpAddr::V4(target_v4) => resolve_mac_v4(cap, ctx, target_v4, vlan, timeout)?,
        IpAddr::V6(target_v6) => resolve_mac_v6(cap, ctx, target_v6, vlan, timeout)?,
    };
    cache.insert(target, mac);
    Ok(mac)
}

fn resolve_mac_v4(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> Result<MacAddr, String> {
    let arp_payload = build_arp_request(ctx.mac, ctx.ipv4, target);
    let frame = build_ethernet_frame(BROADCAST_MAC, ctx.mac, vlan, 0x0806, &arp_payload);
    cap.sendpacket(frame)
        .map_err(|e| format!("Failed to send ARP request: {e}"))?;

    let deadline = Instant::now() + timeout;
    read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_arp_ethertype(link.ethertype) {
            return None;
        }
        let (sender_ip, sender_mac) = parse_arp_reply(&data[link.payload_offset..])?;
        (sender_ip == target).then_some(sender_mac)
    })
        .ok_or_else(|| format!("ARP resolution for {target} timed out"))
}

fn resolve_mac_v6(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    target: Ipv6Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> Result<MacAddr, String> {
    let Some(our_ipv6) = ctx.ipv6 else {
        return Err("This interface has no IPv6 address configured".to_owned());
    };

    let solicited_node = solicited_node_multicast(target);
    let dst_mac = multicast_mac_for_ipv6(solicited_node);

    let ns_payload = build_neighbor_solicitation(ctx.mac, target);
    let ip_packet = build_ipv6_packet(
        our_ipv6,
        solicited_node,
        l2_frame::icmpv6_protocol(),
        l2_frame::ndp_hop_limit(),
        &ns_payload,
    );
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x86DD, &ip_packet);
    cap.sendpacket(frame)
        .map_err(|e| format!("Failed to send Neighbor Solicitation: {e}"))?;

    let deadline = Instant::now() + timeout;
    read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_ipv6_ethertype(link.ethertype) {
            return None;
        }
        let ip = parse_ipv6(&data[link.payload_offset..])?;
        if ip.protocol != l2_frame::icmpv6_protocol() {
            return None;
        }
        let l4 = &data[link.payload_offset + ip.l4_offset..];
        let (advertised, mac) = parse_neighbor_advertisement(l4)?;
        if advertised != target {
            return None;
        }
        mac
    })
        .ok_or_else(|| format!("Neighbor resolution for {target} timed out"))
}

fn do_ping(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    neighbor_cache: &mut HashMap<IpAddr, MacAddr>,
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    identifier: u16,
    timeout: Duration,
) -> L2PingOutcome {
    match (source_ip, target) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            do_ping_v4(cap, ctx, neighbor_cache, src, dst, vlan, identifier, timeout)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            do_ping_v6(cap, ctx, neighbor_cache, src, dst, vlan, identifier, timeout)
        }
        _ => L2PingOutcome::Error(
            "Source IP and target IP must be the same address family".to_owned(),
        ),
    }
}

fn do_ping_v4(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    neighbor_cache: &mut HashMap<IpAddr, MacAddr>,
    source_ip: Ipv4Addr,
    target: Ipv4Addr,
    vlan: Option<u16>,
    identifier: u16,
    timeout: Duration,
) -> L2PingOutcome {
    // On-link-ness is about the interface's *actual* physical attachment to
    // a subnet, so this stays based on `ctx`'s real configuration - not
    // `source_ip`, which may be a candidate address that isn't really ours.
    let resolve_target = if ctx.is_on_link(target) {
        target
    } else {
        match ctx.gateway {
            Some(gw) => gw,
            None => {
                return L2PingOutcome::Error(
                    "Target is off-link and no default IPv4 gateway is known".to_owned(),
                );
            }
        }
    };

    let dst_mac = match resolve_mac(cap, ctx, neighbor_cache, IpAddr::V4(resolve_target), vlan, timeout) {
        Ok(mac) => mac,
        Err(e) => return L2PingOutcome::Error(e),
    };

    let icmp_payload = build_icmp_echo_request(identifier, 0);
    let ip_packet = build_ipv4_packet(source_ip, target, l2_frame::icmp_protocol(), identifier, &icmp_payload);
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x0800, &ip_packet);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send ICMP echo: {e}"));
    }

    // The reply is addressed to whatever we claimed as our source, not
    // necessarily this interface's real configured address. If `source_ip`
    // isn't otherwise claimed by anyone, whoever's replying first has to
    // resolve it via ARP - and since nobody legitimately owns it, that
    // resolution would normally get no answer, and the reply would be
    // silently dropped. So while we wait, we also proxy-answer any ARP
    // request asking about `source_ip` with our own real MAC - the same
    // technique used for ARP-based address takeover/failover.
    let deadline = sent_at + timeout;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let Some(link) = parse_link(packet.data) else {
                    continue;
                };
                if link.vlan != vlan {
                    continue;
                }

                if l2_frame::is_arp_ethertype(link.ethertype) {
                    if let Some((req_ip, req_mac, asking_about)) =
                        parse_arp_request(&packet.data[link.payload_offset..])
                    {
                        if asking_about == source_ip {
                            let reply_payload =
                                build_arp_reply(ctx.mac, source_ip, req_mac, req_ip);
                            let reply_frame = build_ethernet_frame(
                                req_mac,
                                ctx.mac,
                                vlan,
                                0x0806,
                                &reply_payload,
                            );
                            let _ = cap.sendpacket(reply_frame);
                        }
                    }
                    continue;
                }

                if !l2_frame::is_ipv4_ethertype(link.ethertype) {
                    continue;
                }
                let Some(ip) = parse_ipv4(&packet.data[link.payload_offset..]) else {
                    continue;
                };
                if ip.source != target || ip.destination != source_ip {
                    continue;
                }
                let l4 = &packet.data[link.payload_offset + ip.l4_offset..];
                if let Some((reply_ident, _seq)) = parse_icmp_echo_reply(l4) {
                    if reply_ident == identifier {
                        return L2PingOutcome::Success {
                            rtt: sent_at.elapsed(),
                        };
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }
    L2PingOutcome::Timeout
}

fn do_ping_v6(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    neighbor_cache: &mut HashMap<IpAddr, MacAddr>,
    source_ip: Ipv6Addr,
    target: Ipv6Addr,
    vlan: Option<u16>,
    identifier: u16,
    timeout: Duration,
) -> L2PingOutcome {
    // Same reasoning as v4: on-link-ness is about `ctx`'s real attachment,
    // not the (possibly-candidate) `source_ip`. If this interface has no
    // IPv6 configured at all, `is_on_link_v6` just returns false for
    // everything, falling through to the gateway-or-error path below -
    // no separate "no IPv6 configured" check needed up front here.
    let resolve_target = if ctx.is_on_link_v6(target) {
        target
    } else {
        match ctx.ipv6_gateway {
            Some(gw) => gw,
            None => {
                return L2PingOutcome::Error(
                    "Target is off-link and no default IPv6 gateway is known".to_owned(),
                );
            }
        }
    };

    let dst_mac = match resolve_mac(cap, ctx, neighbor_cache, IpAddr::V6(resolve_target), vlan, timeout) {
        Ok(mac) => mac,
        Err(e) => return L2PingOutcome::Error(e),
    };

    let icmp_payload = build_icmpv6_echo_request(source_ip, target, identifier, 0);
    let ip_packet = build_ipv6_packet(
        source_ip,
        target,
        l2_frame::icmpv6_protocol(),
        l2_frame::icmp_echo_hop_limit(),
        &icmp_payload,
    );
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x86DD, &ip_packet);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send ICMPv6 echo: {e}"));
    }

    // Same reasoning as v4's wait loop: if `source_ip` isn't otherwise
    // claimed, whoever's replying has to resolve it via Neighbor
    // Solicitation first, and normally gets no answer - so we proxy-answer
    // any NS asking about `source_ip` with our own real MAC while we wait.
    let deadline = sent_at + timeout;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let Some(link) = parse_link(packet.data) else {
                    continue;
                };
                if link.vlan != vlan || !l2_frame::is_ipv6_ethertype(link.ethertype) {
                    continue;
                }
                let Some(ip) = parse_ipv6(&packet.data[link.payload_offset..]) else {
                    continue;
                };
                if ip.protocol != l2_frame::icmpv6_protocol() {
                    continue;
                }
                let l4 = &packet.data[link.payload_offset + ip.l4_offset..];

                if let Some((solicited, requester_mac)) = parse_neighbor_solicitation(l4) {
                    if solicited == source_ip {
                        if let Some(requester_mac) = requester_mac {
                            let na_payload =
                                build_neighbor_advertisement(ctx.mac, source_ip, ip.source);
                            let na_packet = build_ipv6_packet(
                                source_ip,
                                ip.source,
                                l2_frame::icmpv6_protocol(),
                                l2_frame::ndp_hop_limit(),
                                &na_payload,
                            );
                            let na_frame = build_ethernet_frame(
                                requester_mac,
                                ctx.mac,
                                vlan,
                                0x86DD,
                                &na_packet,
                            );
                            let _ = cap.sendpacket(na_frame);
                        }
                        // No Source Link-Layer Address option means we have
                        // no MAC to send our answer to - nothing we can do
                        // for this particular solicitation.
                    }
                    continue;
                }

                if ip.source != target || ip.destination != source_ip {
                    continue;
                }
                if let Some((reply_ident, _seq)) = parse_icmpv6_echo_reply(l4) {
                    if reply_ident == identifier {
                        return L2PingOutcome::Success {
                            rtt: sent_at.elapsed(),
                        };
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }
    L2PingOutcome::Timeout
}

/// ICMP Timestamp has no IPv6 equivalent (see `l2_frame`'s dedicated
/// section) - unlike `do_ping`/`do_arp_ping`, there's no `_v6` sibling to
/// dispatch to here; a V6 source/target is simply rejected up front rather
/// than silently doing the wrong thing.
///
/// Otherwise identical in shape to `do_ping_v4`: resolve the target's MAC,
/// send one request, wait for a matching reply while proxy-answering any
/// ARP request asking about our claimed `source_ip` (see `do_ping_v4`'s
/// comment on why that's needed) - only the frame content and the reply
/// matcher differ.
fn do_timestamp_ping(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    neighbor_cache: &mut HashMap<IpAddr, MacAddr>,
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    identifier: u16,
    timeout: Duration,
) -> L2PingOutcome {
    let (IpAddr::V4(source_ip), IpAddr::V4(target)) = (source_ip, target) else {
        return L2PingOutcome::Error(
            "ICMP Timestamp has no IPv6 equivalent - use ICMP echo for an IPv6 target".to_owned(),
        );
    };

    let resolve_target = if ctx.is_on_link(target) {
        target
    } else {
        match ctx.gateway {
            Some(gw) => gw,
            None => {
                return L2PingOutcome::Error(
                    "Target is off-link and no default IPv4 gateway is known".to_owned(),
                );
            }
        }
    };

    let dst_mac = match resolve_mac(cap, ctx, neighbor_cache, IpAddr::V4(resolve_target), vlan, timeout) {
        Ok(mac) => mac,
        Err(e) => return L2PingOutcome::Error(e),
    };

    let icmp_payload = build_icmp_timestamp_request(identifier, 0);
    let ip_packet =
        build_ipv4_packet(source_ip, target, l2_frame::icmp_protocol(), identifier, &icmp_payload);
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x0800, &ip_packet);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send ICMP timestamp request: {e}"));
    }

    let deadline = sent_at + timeout;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let Some(link) = parse_link(packet.data) else {
                    continue;
                };
                if link.vlan != vlan {
                    continue;
                }

                if l2_frame::is_arp_ethertype(link.ethertype) {
                    if let Some((req_ip, req_mac, asking_about)) =
                        parse_arp_request(&packet.data[link.payload_offset..])
                    {
                        if asking_about == source_ip {
                            let reply_payload =
                                build_arp_reply(ctx.mac, source_ip, req_mac, req_ip);
                            let reply_frame = build_ethernet_frame(
                                req_mac,
                                ctx.mac,
                                vlan,
                                0x0806,
                                &reply_payload,
                            );
                            let _ = cap.sendpacket(reply_frame);
                        }
                    }
                    continue;
                }

                if !l2_frame::is_ipv4_ethertype(link.ethertype) {
                    continue;
                }
                let Some(ip) = parse_ipv4(&packet.data[link.payload_offset..]) else {
                    continue;
                };
                if ip.source != target || ip.destination != source_ip {
                    continue;
                }
                let l4 = &packet.data[link.payload_offset + ip.l4_offset..];
                if let Some((reply_ident, _seq)) = parse_icmp_timestamp_reply(l4) {
                    if reply_ident == identifier {
                        return L2PingOutcome::Success {
                            rtt: sent_at.elapsed(),
                        };
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }
    L2PingOutcome::Timeout
}

fn do_arp_ping(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    source_ip: IpAddr,
    target: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcome {
    match (source_ip, target) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => do_arp_ping_v4(cap, ctx, src, dst, vlan, timeout),
        (IpAddr::V6(src), IpAddr::V6(dst)) => do_arp_ping_v6(cap, ctx, src, dst, vlan, timeout),
        _ => L2PingOutcome::Error(
            "Source IP and target IP must be the same address family".to_owned(),
        ),
    }
}

/// ARP-based reachability check: send an ARP request for `target`, claiming
/// to be `source_ip`, and time how long a reply takes - the same
/// "who-has/is-at" exchange `resolve_mac_v4` uses internally to learn a MAC
/// before routing a ping, but run here as a first-class, directly-timed
/// result of its own rather than a caching side-effect. Deliberately
/// doesn't touch `neighbor_cache` or route through a gateway the way
/// `do_ping_v4` does for an off-link target: ARP itself has no such
/// concept - it's always a direct broadcast on the local segment, so a
/// target that isn't actually on this segment simply times out here,
/// which is the correct, meaningful answer for an ARP ping specifically
/// (as opposed to a full ICMP ping, which can still succeed off-link via
/// the gateway).
fn do_arp_ping_v4(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    source_ip: Ipv4Addr,
    target: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcome {
    let arp_payload = build_arp_request(ctx.mac, source_ip, target);
    let frame = build_ethernet_frame(BROADCAST_MAC, ctx.mac, vlan, 0x0806, &arp_payload);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send ARP request: {e}"));
    }

    let deadline = sent_at + timeout;
    let found = read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_arp_ethertype(link.ethertype) {
            return None;
        }
        let (sender_ip, _sender_mac) = parse_arp_reply(&data[link.payload_offset..])?;
        (sender_ip == target).then_some(())
    });

    match found {
        Some(()) => L2PingOutcome::Success { rtt: sent_at.elapsed() },
        None => L2PingOutcome::Timeout,
    }
}

/// Same idea as `do_arp_ping_v4`, using a Neighbor Solicitation/
/// Advertisement exchange instead - IPv6 has no ARP, NDP is the direct
/// analog, and (like a solicited-node multicast NS in general) this is
/// still inherently local-segment-only, same reasoning as the v4 side.
/// Doesn't require this interface to have any IPv6 address of its own
/// configured, unlike `resolve_mac_v6`: `source_ip` (which may be a
/// candidate address, not this interface's real one) is what goes on the
/// wire as the solicitation's source, not `ctx.ipv6`.
fn do_arp_ping_v6(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    source_ip: Ipv6Addr,
    target: Ipv6Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2PingOutcome {
    let solicited_node = solicited_node_multicast(target);
    let dst_mac = multicast_mac_for_ipv6(solicited_node);

    let ns_payload = build_neighbor_solicitation(ctx.mac, target);
    let ip_packet = build_ipv6_packet(
        source_ip,
        solicited_node,
        l2_frame::icmpv6_protocol(),
        l2_frame::ndp_hop_limit(),
        &ns_payload,
    );
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x86DD, &ip_packet);

    let sent_at = Instant::now();
    if let Err(e) = cap.sendpacket(frame) {
        return L2PingOutcome::Error(format!("Failed to send Neighbor Solicitation: {e}"));
    }

    let deadline = sent_at + timeout;
    let found = read_until(cap, deadline, |data| {
        let link = parse_link(data)?;
        if link.vlan != vlan || !l2_frame::is_ipv6_ethertype(link.ethertype) {
            return None;
        }
        let ip = parse_ipv6(&data[link.payload_offset..])?;
        if ip.protocol != l2_frame::icmpv6_protocol() {
            return None;
        }
        let l4 = &data[link.payload_offset + ip.l4_offset..];
        let (advertised, _mac) = parse_neighbor_advertisement(l4)?;
        (advertised == target).then_some(())
    });

    match found {
        Some(()) => L2PingOutcome::Success { rtt: sent_at.elapsed() },
        None => L2PingOutcome::Timeout,
    }
}

fn do_duplicate_check(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    candidate: IpAddr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcome {
    match candidate {
        IpAddr::V4(candidate_v4) => do_duplicate_check_v4(cap, ctx, candidate_v4, vlan, timeout),
        IpAddr::V6(candidate_v6) => do_duplicate_check_v6(cap, ctx, candidate_v6, vlan, timeout),
    }
}

/// ARP-Probe for `candidate` (RFC 5227 §2.1.1: sender protocol address
/// 0.0.0.0) and keep listening for the *whole* window rather than stopping
/// at the first reply, collecting every distinct MAC that answers. Any
/// reply at all means someone already claims `candidate` - a single
/// answering MAC is already `Duplicate`; listening the full window instead
/// of returning on the first reply exists to also catch every other MAC if
/// more than one host answers (worth showing all of them), not to require
/// more than one before calling it a duplicate. A duplicate host that
/// simply doesn't answer within the window will still be missed (see the
/// explanation given alongside this feature).
fn do_duplicate_check_v4(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    candidate: Ipv4Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcome {
    let arp_payload = build_arp_probe(ctx.mac, candidate);
    let frame = build_ethernet_frame(BROADCAST_MAC, ctx.mac, vlan, 0x0806, &arp_payload);
    if let Err(e) = cap.sendpacket(frame) {
        return L2DuplicateOutcome::Error(format!("Failed to send ARP probe: {e}"));
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
                if sender_ip == candidate && !seen.contains(&sender_mac) {
                    seen.push(sender_mac);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }

    if seen.is_empty() {
        L2DuplicateOutcome::Clear
    } else {
        L2DuplicateOutcome::Duplicate {
            macs: seen.iter().map(|m| m.to_string()).collect(),
        }
    }
}

/// Same idea as `do_duplicate_check_v4`, using IPv6 Duplicate Address
/// Detection (RFC 4862 §5.4: Neighbor Solicitation with source address `::`)
/// instead of an ARP Probe. Doesn't need this interface to have any IPv6
/// configured of its own - DAD probes with the unspecified address either
/// way, since it's inherently a check against `candidate`, not against
/// whatever we might already have.
fn do_duplicate_check_v6(
    cap: &mut pcap::Capture<pcap::Active>,
    ctx: &InterfaceContext,
    candidate: Ipv6Addr,
    vlan: Option<u16>,
    timeout: Duration,
) -> L2DuplicateOutcome {
    let solicited_node = solicited_node_multicast(candidate);
    let dst_mac = multicast_mac_for_ipv6(solicited_node);

    let ns_payload = build_neighbor_solicitation(ctx.mac, candidate);
    let ip_packet = build_ipv6_packet(
        Ipv6Addr::UNSPECIFIED,
        solicited_node,
        l2_frame::icmpv6_protocol(),
        l2_frame::ndp_hop_limit(),
        &ns_payload,
    );
    let frame = build_ethernet_frame(dst_mac, ctx.mac, vlan, 0x86DD, &ip_packet);
    if let Err(e) = cap.sendpacket(frame) {
        return L2DuplicateOutcome::Error(format!("Failed to send Neighbor Solicitation: {e}"));
    }

    let mut seen: Vec<MacAddr> = Vec::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                let Some(link) = parse_link(packet.data) else {
                    continue;
                };
                if link.vlan != vlan || !l2_frame::is_ipv6_ethertype(link.ethertype) {
                    continue;
                }
                let Some(ip) = parse_ipv6(&packet.data[link.payload_offset..]) else {
                    continue;
                };
                if ip.protocol != l2_frame::icmpv6_protocol() {
                    continue;
                }
                let l4 = &packet.data[link.payload_offset + ip.l4_offset..];
                let Some((advertised, Some(mac))) = parse_neighbor_advertisement(l4) else {
                    continue;
                };
                if advertised == candidate && !seen.contains(&mac) {
                    seen.push(mac);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => continue,
        }
    }

    if seen.is_empty() {
        L2DuplicateOutcome::Clear
    } else {
        L2DuplicateOutcome::Duplicate {
            macs: seen.iter().map(|m| m.to_string()).collect(),
        }
    }
}