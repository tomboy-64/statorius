//! Low-level Layer-2 frame construction/parsing, plus interface/gateway
//! resolution.
//!
//! Kept deliberately protocol-agnostic where it can be: Ethernet framing
//! (with optional 802.1Q VLAN tagging) and IPv4/IPv6 wrapping are shared by
//! *every* L2 scan method. Only the L4 payload build/match (ICMP echo today;
//! TCP connect-scan and UDP null-scan later) is method-specific - see
//! `l2_engine.rs` for where that split happens.
//!
//! IPv6 support mirrors IPv4 throughout: ARP's role is played by NDP
//! (Neighbor Solicitation/Advertisement, RFC 4861) for address resolution
//! and duplicate detection, and ICMPv6 echo plays ICMP's role - but ICMPv6's
//! checksum (unlike ICMPv4's) is computed over a pseudo-header including the
//! source/destination addresses, so those checksum functions take extra
//! arguments where the IPv4 ones didn't need them.

use std::net::{Ipv4Addr, Ipv6Addr};

use pnet_base::MacAddr;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::icmp::{
    echo_reply, echo_request, IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket,
};
use pnet_packet::Packet;
use pnet_packet::icmpv6::ndp::{
    MutableNeighborAdvertPacket, MutableNeighborSolicitPacket, NdpOptionTypes,
    NeighborAdvertPacket, NeighborSolicitPacket,
};
use pnet_packet::icmpv6::{
    echo_reply as icmpv6_echo_reply, echo_request as icmpv6_echo_request, Icmpv6Packet,
    Icmpv6Types,
};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet_packet::udp::UdpPacket;
use pnet_packet::{ethernet::EtherType, ethernet::MutableEthernetPacket};

pub const ETH_HEADER_LEN: usize = 14;
pub const VLAN_TAG_LEN: usize = 4;
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ARP_PACKET_LEN: usize = 28;
/// Fixed part of a Neighbor Solicit/Advert (ICMPv6 header + reserved/flags +
/// target address), before any NDP options.
const NDP_FIXED_LEN: usize = 24;
/// A Source/Target Link-Layer Address option carrying a 6-byte Ethernet MAC:
/// 1 byte type + 1 byte length(in 8-byte units) + 6 bytes MAC = 8 bytes.
const NDP_LLADDR_OPTION_LEN: usize = 8;
/// NDP messages must use hop limit 255 (RFC 4861 §4.1-4.4) - a receiving
/// host uses this to reject anything that could have come from off-link
/// (a real router/host can only send with hop limit 255 if it's on-link,
/// since routers decrement hop limit).
const NDP_HOP_LIMIT: u8 = 255;
const ICMP_ECHO_HOP_LIMIT: u8 = 64;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;

pub const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/// What we know about the network we're sending on: our own MAC/IP(s), the
/// subnet(s) we're directly attached to, and the default gateway(s) for
/// off-link destinations. IPv6 fields are `Option`/best-effort: a machine
/// (or this specific interface) might simply not have IPv6 configured, in
/// which case IPv6 pings against it fail with a clear error rather than
/// blocking IPv4 use.
#[derive(Debug, Clone)]
pub struct InterfaceContext {
    pub name: String,
    pub mac: MacAddr,
    pub ipv4: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub ipv6_prefix_len: Option<u8>,
    pub ipv6_gateway: Option<Ipv6Addr>,
}

impl InterfaceContext {
    /// Whether `target` is on the same subnet as us (and so should be
    /// ARP-resolved directly, rather than routed via the gateway's MAC).
    pub fn is_on_link(&self, target: Ipv4Addr) -> bool {
        let mask: u32 = if self.prefix_len >= 32 {
            u32::MAX
        } else {
            !0u32 << (32 - self.prefix_len)
        };
        (u32::from(self.ipv4) & mask) == (u32::from(target) & mask)
    }

    /// Same idea as `is_on_link`, for IPv6 - `u128`-based since a v6 address
    /// doesn't fit in `u32`. Only meaningful if we actually have an IPv6
    /// address/prefix on this interface; callers check `self.ipv6` first.
    pub fn is_on_link_v6(&self, target: Ipv6Addr) -> bool {
        let Some(our_prefix_len) = self.ipv6_prefix_len else {
            return false;
        };
        let Some(our_addr) = self.ipv6 else {
            return false;
        };
        let mask: u128 = if our_prefix_len >= 128 {
            u128::MAX
        } else {
            !0u128 << (128 - our_prefix_len)
        };
        (u128::from(our_addr) & mask) == (u128::from(target) & mask)
    }
}

/// Resolve the machine's default network interface (name, MAC, IPv4/IPv6
/// address+prefix, gateways) via `default-net`. This is what "which
/// interface do we actually send raw frames on" comes down to for now - a
/// future version could let the user pick a specific interface instead of
/// always using the default one. The IPv6 fields were added by symmetry
/// with the IPv4 ones below rather than independently confirmed - if a
/// compile error lands here, check them against `default-net`'s actual
/// field/method names first.
pub fn resolve_default_interface() -> Result<InterfaceContext, String> {
    let iface = default_net::get_default_interface()
        .map_err(|e| format!("Could not determine the default network interface: {e}"))?;

    let mac_bytes = iface
        .mac_addr
        .as_ref()
        .ok_or_else(|| "Default interface has no MAC address".to_owned())?
        .octets();
    let mac = MacAddr::new(
        mac_bytes[0],
        mac_bytes[1],
        mac_bytes[2],
        mac_bytes[3],
        mac_bytes[4],
        mac_bytes[5],
    );

    let ipv4_net = iface
        .ipv4
        .first()
        .ok_or_else(|| "Default interface has no IPv4 address".to_owned())?;

    let gateway = iface.gateway.as_ref().and_then(|g| match g.ip_addr {
        std::net::IpAddr::V4(ipv4) => Some(ipv4),
        _ => None,
    });

    // IPv6 is best-effort: absence just means V6 pings will fail cleanly
    // later, not that the whole interface resolution fails.
    let ipv6_net = iface.ipv6.first();
    let ipv6_gateway = iface.gateway.as_ref().and_then(|g| match g.ip_addr {
        std::net::IpAddr::V6(ipv6) => Some(ipv6),
        _ => None,
    });

    Ok(InterfaceContext {
        name: iface.name,
        mac,
        ipv4: ipv4_net.addr,
        prefix_len: ipv4_net.prefix_len,
        gateway,
        ipv6: ipv6_net.map(|n| n.addr),
        ipv6_prefix_len: ipv6_net.map(|n| n.prefix_len),
        ipv6_gateway,
    })
}

// ---------------------------------------------------------------------
// Ethernet / VLAN - shared by every scan method.
// ---------------------------------------------------------------------

/// Build a complete Ethernet frame, optionally 802.1Q VLAN-tagged, wrapping
/// `payload` (already-built L3 bytes) under `inner_ethertype`.
pub fn build_ethernet_frame(
    dst_mac: MacAddr,
    src_mac: MacAddr,
    vlan: Option<u16>,
    inner_ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let vlan_len = if vlan.is_some() { VLAN_TAG_LEN } else { 0 };
    let mut buf = vec![0u8; ETH_HEADER_LEN + vlan_len + payload.len()];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..ETH_HEADER_LEN])
            .expect("ethernet header buffer is exactly the right size");
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherType::new(if vlan.is_some() {
            ETHERTYPE_VLAN
        } else {
            inner_ethertype
        }));
    }

    let mut offset = ETH_HEADER_LEN;
    if let Some(vlan_id) = vlan {
        // 802.1Q tag: 3 bits priority (0) + 1 bit DEI (0) + 12 bits VLAN ID,
        // followed by the real ethertype - inserted between the Ethernet
        // header and the L3 payload.
        let tci = vlan_id & 0x0FFF;
        buf[offset] = (tci >> 8) as u8;
        buf[offset + 1] = (tci & 0xFF) as u8;
        buf[offset + 2] = (inner_ethertype >> 8) as u8;
        buf[offset + 3] = (inner_ethertype & 0xFF) as u8;
        offset += VLAN_TAG_LEN;
    }

    buf[offset..].copy_from_slice(payload);
    buf
}

/// Parsed view of an incoming frame's Ethernet+VLAN framing: the inner
/// ethertype (post-VLAN, if any), the VLAN ID if tagged, and the byte offset
/// where the L3 payload starts.
pub struct ParsedLink {
    pub vlan: Option<u16>,
    pub ethertype: u16,
    pub payload_offset: usize,
}

/// Parse just enough of an incoming frame to know its VLAN tag (if any) and
/// inner ethertype - reused by every job in `l2_engine` to decide whether a
/// captured frame is even worth looking at further.
pub fn parse_link(frame: &[u8]) -> Option<ParsedLink> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < ETH_HEADER_LEN + VLAN_TAG_LEN {
            return None;
        }
        let tci = u16::from_be_bytes([frame[14], frame[15]]);
        let inner_ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        Some(ParsedLink {
            vlan: Some(tci & 0x0FFF),
            ethertype: inner_ethertype,
            payload_offset: ETH_HEADER_LEN + VLAN_TAG_LEN,
        })
    } else {
        Some(ParsedLink {
            vlan: None,
            ethertype,
            payload_offset: ETH_HEADER_LEN,
        })
    }
}

pub fn is_ipv4_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_IPV4
}

pub fn is_ipv6_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_IPV6
}

pub fn is_arp_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_ARP
}

// ---------------------------------------------------------------------
// ARP (IPv4) - used for gateway/on-link MAC resolution and duplicate-IP
// checks. NDP (below) plays the same role for IPv6.
// ---------------------------------------------------------------------

/// Build an ARP "who has `target_ip`" request payload (to be wrapped in an
/// Ethernet frame with a broadcast destination MAC).
pub fn build_arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; ARP_PACKET_LEN];
    let mut arp = MutableArpPacket::new(&mut buf).expect("arp buffer is exactly the right size");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherType::new(ETHERTYPE_IPV4));
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
    arp.set_target_proto_addr(target_ip);
    buf
}

/// Build an ARP Probe (RFC 5227 §2.1.1): sender protocol address 0.0.0.0,
/// asking "who has `candidate_ip`". This is the standard way to check
/// whether an address is free to *become* ours - unlike a normal ARP
/// request (above), which states our real address as the sender because
/// we're already using it to communicate. Used for the "is this source IP
/// already in use" check, never for actually resolving a ping's route.
pub fn build_arp_probe(src_mac: MacAddr, candidate_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; ARP_PACKET_LEN];
    let mut arp = MutableArpPacket::new(&mut buf).expect("arp buffer is exactly the right size");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherType::new(ETHERTYPE_IPV4));
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(Ipv4Addr::UNSPECIFIED);
    arp.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
    arp.set_target_proto_addr(candidate_ip);
    buf
}

/// If `payload` (the L3 bytes after Ethernet/VLAN) is an ARP reply, return
/// its sender IP + MAC.
pub fn parse_arp_reply(payload: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let arp = ArpPacket::new(payload)?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

/// Build an ARP reply claiming "`claimed_ip` is at `claimed_mac`", addressed
/// to a specific requester. When pinging with a spoofed `source_ip`, the
/// Ethernet frame's *source MAC* is still genuinely ours, but the IP-layer
/// source is not an address anyone else recognizes - so whoever we're
/// pinging (or anyone else needing to route a reply to it) has to resolve
/// it via ARP, and if `source_ip` is otherwise unclaimed, nobody answers,
/// and the reply gets silently dropped. Proxy-answering that resolution
/// with our own real MAC is what makes replies to a spoofed source actually
/// arrive.
pub fn build_arp_reply(
    claimed_mac: MacAddr,
    claimed_ip: Ipv4Addr,
    requester_mac: MacAddr,
    requester_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; ARP_PACKET_LEN];
    let mut arp = MutableArpPacket::new(&mut buf).expect("arp buffer is exactly the right size");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherType::new(ETHERTYPE_IPV4));
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Reply);
    arp.set_sender_hw_addr(claimed_mac);
    arp.set_sender_proto_addr(claimed_ip);
    arp.set_target_hw_addr(requester_mac);
    arp.set_target_proto_addr(requester_ip);
    buf
}

/// If `payload` is an ARP request, return (requester IP, requester MAC, the
/// IP they're asking about) - used to notice "someone's trying to resolve
/// our spoofed source IP" while a ping is in flight.
pub fn parse_arp_request(payload: &[u8]) -> Option<(Ipv4Addr, MacAddr, Ipv4Addr)> {
    let arp = ArpPacket::new(payload)?;
    if arp.get_operation() != ArpOperations::Request {
        return None;
    }
    Some((
        arp.get_sender_proto_addr(),
        arp.get_sender_hw_addr(),
        arp.get_target_proto_addr(),
    ))
}

// ---------------------------------------------------------------------
// NDP (IPv6) - Neighbor Solicitation/Advertisement, RFC 4861. Plays ARP's
// role: resolving a target's MAC, and (via multiple distinct responders)
// detecting a duplicate address.
// ---------------------------------------------------------------------

/// The solicited-node multicast address for `target` (RFC 4291 §2.7.1):
/// `ff02::1:ffXX:XXXX`, where the low 24 bits come from `target` itself.
pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let o = target.octets();
    Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 0x0001,
        0xff00 | (o[13] as u16),
        ((o[14] as u16) << 8) | (o[15] as u16),
    )
}

/// The Ethernet multicast MAC an IPv6 multicast address maps onto (RFC
/// 2464 §7): `33:33` followed by the low-order 32 bits of the address.
pub fn multicast_mac_for_ipv6(addr: Ipv6Addr) -> MacAddr {
    let o = addr.octets();
    MacAddr::new(0x33, 0x33, o[12], o[13], o[14], o[15])
}

/// Build a Neighbor Solicitation payload asking "who has `target_ip`",
/// including a Source Link-Layer Address option so the responder knows our
/// MAC without needing a separate resolution round-trip of its own.
pub fn build_neighbor_solicitation(src_mac: MacAddr, target_ip: Ipv6Addr) -> Vec<u8> {
    let total_len = NDP_FIXED_LEN + NDP_LLADDR_OPTION_LEN;
    let mut buf = vec![0u8; total_len];
    {
        let mut ns = MutableNeighborSolicitPacket::new(&mut buf)
            .expect("neighbor solicitation buffer sized correctly");
        ns.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ns.set_icmpv6_code(pnet_packet::icmpv6::ndp::Icmpv6Codes::NoCode);
        ns.set_reserved(0);
        ns.set_target_addr(target_ip);
        ns.set_checksum(0);
    }
    write_lladdr_option(&mut buf[NDP_FIXED_LEN..], NdpOptionTypes::SourceLLAddr, src_mac);
    buf
}

/// If `l4_payload` is a Neighbor Advertisement, return the address it's
/// advertising and the MAC from its Target Link-Layer Address option (if
/// present - it normally is, for a solicited response, but NDP doesn't
/// strictly require it).
pub fn parse_neighbor_advertisement(l4_payload: &[u8]) -> Option<(Ipv6Addr, Option<MacAddr>)> {
    let na = NeighborAdvertPacket::new(l4_payload)?;
    if na.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }
    let target_addr = na.get_target_addr();
    let mac = read_lladdr_option(
        &l4_payload[NDP_FIXED_LEN.min(l4_payload.len())..],
        NdpOptionTypes::TargetLLAddr,
    );
    Some((target_addr, mac))
}

/// If `l4_payload` is a Neighbor Solicitation, return the address being
/// solicited and the requester's MAC (from its Source Link-Layer Address
/// option, if present) - used to notice "someone's trying to resolve our
/// spoofed source IP" while a ping is in flight, and to know where to send
/// our proxy answer, mirroring `parse_arp_request`.
pub fn parse_neighbor_solicitation(l4_payload: &[u8]) -> Option<(Ipv6Addr, Option<MacAddr>)> {
    let ns = NeighborSolicitPacket::new(l4_payload)?;
    if ns.get_icmpv6_type() != Icmpv6Types::NeighborSolicit {
        return None;
    }
    let target_addr = ns.get_target_addr();
    let mac = read_lladdr_option(
        &l4_payload[NDP_FIXED_LEN.min(l4_payload.len())..],
        NdpOptionTypes::SourceLLAddr,
    );
    Some((target_addr, mac))
}

/// Build a Neighbor Advertisement claiming "`claimed_ip` is at
/// `claimed_mac`", with Solicited+Override set (RFC 4861 §4.4: "yes, I'm
/// answering your solicitation, and yes, believe me over any previous
/// entry"), addressed back to whoever asked. Same role as `build_arp_reply`
/// for IPv4: without proxy-answering this, a spoofed `source_ip` that isn't
/// otherwise claimed has nobody to resolve it, and any reply to it is
/// silently dropped by whoever's trying to send it.
pub fn build_neighbor_advertisement(
    claimed_mac: MacAddr,
    claimed_ip: Ipv6Addr,
    requester_ip: Ipv6Addr,
) -> Vec<u8> {
    let total_len = NDP_FIXED_LEN + NDP_LLADDR_OPTION_LEN;
    let mut buf = vec![0u8; total_len];
    {
        let mut na = MutableNeighborAdvertPacket::new(&mut buf)
            .expect("neighbor advertisement buffer sized correctly");
        na.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        na.set_icmpv6_code(pnet_packet::icmpv6::ndp::Icmpv6Codes::NoCode);
        na.set_flags(0x60); // Solicited (bit 6) + Override (bit 5)
        na.set_reserved(0);
        na.set_target_addr(claimed_ip);
        na.set_checksum(0);
    }
    write_lladdr_option(&mut buf[NDP_FIXED_LEN..], NdpOptionTypes::TargetLLAddr, claimed_mac);
    let checksum = pnet_packet::icmpv6::checksum(
        &Icmpv6Packet::new(&buf).expect("just built this"),
        &claimed_ip,
        &requester_ip,
    );
    let mut na =
        MutableNeighborAdvertPacket::new(&mut buf).expect("neighbor advertisement buffer sized correctly");
    na.set_checksum(checksum);
    buf
}

/// Write one Link-Layer-Address NDP option (type + length + 6-byte MAC)
/// into `buf`, which must be exactly `NDP_LLADDR_OPTION_LEN` bytes.
fn write_lladdr_option(buf: &mut [u8], option_type: pnet_packet::icmpv6::ndp::NdpOptionType, mac: MacAddr) {
    buf[0] = option_type.0;
    buf[1] = 1; // length in 8-byte units: 1 * 8 = 8 bytes total
    let octets = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];
    buf[2..8].copy_from_slice(&octets);
}

/// Scan an NDP options list for a Link-Layer-Address option of the given
/// type and return its MAC, if present. Options are TLV-ish: 1 byte type, 1
/// byte length-in-8-byte-units (including the type/length bytes
/// themselves), then `length*8 - 2` bytes of data.
fn read_lladdr_option(
    options: &[u8],
    option_type: pnet_packet::icmpv6::ndp::NdpOptionType,
) -> Option<MacAddr> {
    let mut i = 0;
    while i + 2 <= options.len() {
        let this_type = options[i];
        let length_units = options[i + 1];
        if length_units == 0 {
            break; // malformed - avoid looping forever
        }
        let option_len = (length_units as usize) * 8;
        if i + option_len > options.len() {
            break;
        }
        if this_type == option_type.0 && option_len >= NDP_LLADDR_OPTION_LEN {
            let mac_bytes = &options[i + 2..i + 8];
            return Some(MacAddr::new(
                mac_bytes[0],
                mac_bytes[1],
                mac_bytes[2],
                mac_bytes[3],
                mac_bytes[4],
                mac_bytes[5],
            ));
        }
        i += option_len;
    }
    None
}

// ---------------------------------------------------------------------
// IPv4 - shared wrapper for every L4 protocol (ICMP now, TCP/UDP later).
// ---------------------------------------------------------------------

/// Build an IPv4 header + `l4_payload`, with a correct header checksum.
/// `protocol` selects the L4 type (e.g. `IpNextHeaderProtocols::Icmp` today;
/// `Tcp`/`Udp` for future scan methods reuse this exact function).
pub fn build_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: pnet_packet::ip::IpNextHeaderProtocol,
    identification: u16,
    l4_payload: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + l4_payload.len();
    let mut buf = vec![0u8; total_len];
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer sized correctly");
        ip.set_version(4);
        ip.set_header_length(5); // 5 * 4 = 20 bytes, no options
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(protocol);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_payload(l4_payload);
        ip.set_checksum(0);
    }
    let checksum = pnet_packet::ipv4::checksum(&Ipv4Packet::new(&buf).expect("just built this"));
    let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer sized correctly");
    ip.set_checksum(checksum);
    buf
}

/// Parsed view of an incoming IPv4 packet: source, destination, protocol,
/// and where the L4 payload starts within the given slice.
pub struct ParsedIpv4 {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: pnet_packet::ip::IpNextHeaderProtocol,
    pub l4_offset: usize,
}

pub fn parse_ipv4(payload: &[u8]) -> Option<ParsedIpv4> {
    let ip = Ipv4Packet::new(payload)?;
    let header_len = ip.get_header_length() as usize * 4;
    if header_len < IPV4_HEADER_LEN || payload.len() < header_len {
        return None;
    }
    Some(ParsedIpv4 {
        source: ip.get_source(),
        destination: ip.get_destination(),
        protocol: ip.get_next_level_protocol(),
        l4_offset: header_len,
    })
}

pub fn icmp_protocol() -> pnet_packet::ip::IpNextHeaderProtocol {
    IpNextHeaderProtocols::Icmp
}

// ---------------------------------------------------------------------
// UDP - shared L4 parsing for anything riding over it. Today that's just
// the DHCP sniffer (`net::dhcp_sniffer`), listening for the well-known
// server/client ports; a future mDNS/SSDP/etc. listener would reuse this
// same parse. There's no `build_udp_packet` here (nothing in this codebase
// sends UDP yet) - only the receive side is needed.
// ---------------------------------------------------------------------

pub const UDP_HEADER_LEN: usize = 8;

/// Parsed view of a UDP datagram: both ports, and the payload slice
/// (trimmed to the header's own declared length where that's shorter than
/// what was actually captured, e.g. trailing Ethernet padding on a short
/// DHCP packet).
pub struct ParsedUdp<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(l4_payload: &[u8]) -> Option<ParsedUdp<'_>> {
    let udp = UdpPacket::new(l4_payload)?;
    let declared_len = udp.get_length() as usize;
    let end = declared_len.max(UDP_HEADER_LEN).min(l4_payload.len());
    if end < UDP_HEADER_LEN {
        return None;
    }
    Some(ParsedUdp {
        source_port: udp.get_source(),
        destination_port: udp.get_destination(),
        payload: &l4_payload[UDP_HEADER_LEN..end],
    })
}

pub fn udp_protocol() -> pnet_packet::ip::IpNextHeaderProtocol {
    IpNextHeaderProtocols::Udp
}

// ---------------------------------------------------------------------
// IPv6 - mirrors the IPv4 section above. No header checksum field (IPv6
// moved that responsibility entirely to L4), and no variable header length
// (always exactly `IPV6_HEADER_LEN`, extension headers aside - not used
// here).
// ---------------------------------------------------------------------

/// Build an IPv6 header + `l4_payload`. `hop_limit` is exposed (rather than
/// hardcoded like IPv4's TTL) because NDP specifically requires 255, while
/// ICMPv6 echo uses a normal hop limit.
pub fn build_ipv6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: pnet_packet::ip::IpNextHeaderProtocol,
    hop_limit: u8,
    l4_payload: &[u8],
) -> Vec<u8> {
    let total_len = IPV6_HEADER_LEN + l4_payload.len();
    let mut buf = vec![0u8; total_len];
    let mut ip = MutableIpv6Packet::new(&mut buf).expect("ipv6 buffer sized correctly");
    ip.set_version(6);
    ip.set_traffic_class(0);
    ip.set_flow_label(0);
    ip.set_payload_length(l4_payload.len() as u16);
    ip.set_next_header(next_header);
    ip.set_hop_limit(hop_limit);
    ip.set_source(src);
    ip.set_destination(dst);
    ip.set_payload(l4_payload);
    buf
}

/// Parsed view of an incoming IPv6 packet - mirrors `ParsedIpv4`, but the
/// header length is always fixed (no options/IHL field to read).
pub struct ParsedIpv6 {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub protocol: pnet_packet::ip::IpNextHeaderProtocol,
    pub l4_offset: usize,
}

pub fn parse_ipv6(payload: &[u8]) -> Option<ParsedIpv6> {
    if payload.len() < IPV6_HEADER_LEN {
        return None;
    }
    let ip = Ipv6Packet::new(payload)?;
    Some(ParsedIpv6 {
        source: ip.get_source(),
        destination: ip.get_destination(),
        protocol: ip.get_next_header(),
        l4_offset: IPV6_HEADER_LEN,
    })
}

pub fn icmpv6_protocol() -> pnet_packet::ip::IpNextHeaderProtocol {
    IpNextHeaderProtocols::Icmpv6
}

pub fn ndp_hop_limit() -> u8 {
    NDP_HOP_LIMIT
}

pub fn icmp_echo_hop_limit() -> u8 {
    ICMP_ECHO_HOP_LIMIT
}

// ---------------------------------------------------------------------
// ICMP echo (v4) - today's only L4 scan method for IPv4; TCP-SYN/UDP-null
// are the natural next additions alongside this, reusing everything above.
// ---------------------------------------------------------------------

/// Build an ICMP echo request payload (checksummed) for `identifier`/`sequence`.
pub fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let payload = b"statorius-l2";
    let mut buf = vec![0u8; echo_request::MutableEchoRequestPacket::minimum_packet_size() + payload.len()];
    {
        let mut echo = echo_request::MutableEchoRequestPacket::new(&mut buf)
            .expect("icmp echo buffer sized correctly");
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_icmp_code(echo_request::IcmpCodes::NoCode);
        echo.set_identifier(identifier);
        echo.set_sequence_number(sequence);
        echo.set_payload(payload);
        echo.set_checksum(0);
    }
    let checksum = pnet_packet::icmp::checksum(&IcmpPacket::new(&buf).expect("just built this"));
    let mut echo =
        echo_request::MutableEchoRequestPacket::new(&mut buf).expect("icmp echo buffer sized correctly");
    echo.set_checksum(checksum);
    buf
}

/// If `l4_payload` is an ICMP echo reply, return (identifier, sequence).
pub fn parse_icmp_echo_reply(l4_payload: &[u8]) -> Option<(u16, u16)> {
    let icmp = IcmpPacket::new(l4_payload)?;
    if icmp.get_icmp_type() != IcmpTypes::EchoReply {
        return None;
    }
    let reply = echo_reply::EchoReplyPacket::new(l4_payload)?;
    Some((reply.get_identifier(), reply.get_sequence_number()))
}

// ---------------------------------------------------------------------
// ICMPv6 echo - IPv6's equivalent of the above. Checksummed differently:
// ICMPv6's checksum covers a pseudo-header of source+destination+length+
// next-header, so building/parsing both need the addresses on hand, unlike
// ICMPv4's self-contained checksum.
// ---------------------------------------------------------------------

/// Build an ICMPv6 echo request payload (checksummed against the IPv6
/// pseudo-header) for `identifier`/`sequence`.
pub fn build_icmpv6_echo_request(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    let payload = b"statorius-l2";
    let mut buf = vec![
        0u8;
        icmpv6_echo_request::MutableEchoRequestPacket::minimum_packet_size() + payload.len()
    ];
    {
        let mut echo = icmpv6_echo_request::MutableEchoRequestPacket::new(&mut buf)
            .expect("icmpv6 echo buffer sized correctly");
        echo.set_icmpv6_type(Icmpv6Types::EchoRequest);
        echo.set_icmpv6_code(icmpv6_echo_request::Icmpv6Codes::NoCode);
        echo.set_identifier(identifier);
        echo.set_sequence_number(sequence);
        echo.set_payload(payload);
        echo.set_checksum(0);
    }
    let checksum = pnet_packet::icmpv6::checksum(
        &Icmpv6Packet::new(&buf).expect("just built this"),
        &src,
        &dst,
    );
    let mut echo = icmpv6_echo_request::MutableEchoRequestPacket::new(&mut buf)
        .expect("icmpv6 echo buffer sized correctly");
    echo.set_checksum(checksum);
    buf
}

/// If `l4_payload` is an ICMPv6 echo reply, return (identifier, sequence).
/// (No checksum verification on the receive side - same as the IPv4 path.)
pub fn parse_icmpv6_echo_reply(l4_payload: &[u8]) -> Option<(u16, u16)> {
    let icmp = Icmpv6Packet::new(l4_payload)?;
    if icmp.get_icmpv6_type() != Icmpv6Types::EchoReply {
        return None;
    }
    let reply = icmpv6_echo_reply::EchoReplyPacket::new(l4_payload)?;
    Some((reply.get_identifier(), reply.get_sequence_number()))
}

// ---------------------------------------------------------------------
// ICMP Timestamp (v4-only, RFC 792 §4.3) - no ICMPv6 equivalent, unlike
// echo. Same "does this host answer" liveness check, but a different
// message type - useful as a second data point, since some stacks/
// firewalls let one ICMP type through while blocking another. pnet has no
// dedicated `timestamp_request`/`timestamp_reply` submodule (only
// `echo_request`/`echo_reply`), so this hand-builds the body directly on
// top of the generic `Icmp`/`IcmpPacket`, whose `payload` covers
// everything after the shared type/code/checksum header.
// ---------------------------------------------------------------------

/// Size of an ICMP Timestamp message's body (the generic `IcmpPacket`'s
/// `payload`, i.e. everything after type/code/checksum): identifier(2) +
/// sequence(2) + originate/receive/transmit timestamp (4 bytes each) = 16.
const ICMP_TIMESTAMP_BODY_LEN: usize = 16;

/// Build an ICMP Timestamp request (type 13) for `identifier`/`sequence`.
/// The originate timestamp is left as 0 rather than computed (RFC 792
/// defines it as milliseconds since UTC midnight) - a responder doesn't
/// require it to be accurate in order to reply, and this is used purely as
/// a liveness probe timed by our own wall clock (`Instant::elapsed`), not
/// to read the three timestamp fields back out of the reply.
pub fn build_icmp_timestamp_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut buf = vec![0u8; IcmpPacket::minimum_packet_size() + ICMP_TIMESTAMP_BODY_LEN];
    {
        let mut icmp =
            MutableIcmpPacket::new(&mut buf).expect("icmp timestamp buffer sized correctly");
        icmp.set_icmp_type(IcmpTypes::Timestamp);
        icmp.set_icmp_code(IcmpCode::new(0));
        icmp.set_checksum(0);
        let mut body = [0u8; ICMP_TIMESTAMP_BODY_LEN];
        body[0..2].copy_from_slice(&identifier.to_be_bytes());
        body[2..4].copy_from_slice(&sequence.to_be_bytes());
        // Bytes 4..16 (originate/receive/transmit timestamps) stay zero.
        icmp.set_payload(&body);
    }
    let checksum = pnet_packet::icmp::checksum(&IcmpPacket::new(&buf).expect("just built this"));
    let mut icmp = MutableIcmpPacket::new(&mut buf).expect("icmp timestamp buffer sized correctly");
    icmp.set_checksum(checksum);
    buf
}

/// If `l4_payload` is an ICMP Timestamp Reply (type 14), return its
/// (identifier, sequence) - same return shape as `parse_icmp_echo_reply`,
/// so `l2_engine::do_timestamp_ping` matches it identically. The three
/// timestamp fields in the reply aren't surfaced - see the note on
/// `build_icmp_timestamp_request` above.
pub fn parse_icmp_timestamp_reply(l4_payload: &[u8]) -> Option<(u16, u16)> {
    let icmp = IcmpPacket::new(l4_payload)?;
    if icmp.get_icmp_type() != IcmpTypes::TimestampReply {
        return None;
    }
    let body = icmp.payload();
    if body.len() < 4 {
        return None;
    }
    let identifier = u16::from_be_bytes([body[0], body[1]]);
    let sequence = u16::from_be_bytes([body[2], body[3]]);
    Some((identifier, sequence))
}