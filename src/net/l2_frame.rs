//! Low-level Layer-2 frame construction/parsing, plus interface/gateway
//! resolution.
//!
//! Kept deliberately protocol-agnostic where it can be: Ethernet framing
//! (with optional 802.1Q VLAN tagging) and IPv4 wrapping are shared by
//! *every* L2 scan method. Only the L4 payload build/match (ICMP echo today;
//! TCP connect-scan and UDP null-scan later) is method-specific - see
//! `l2_engine.rs` for where that split happens.

use std::net::{Ipv4Addr};

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::util::MacAddr;
use pnet::packet::{ethernet::MutableEthernetPacket, ip::IpNextHeaderProtocols};
use pnet::packet::{arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket}};
use pnet::packet::{ethernet::EtherType};

pub const ETH_HEADER_LEN: usize = 14;
pub const VLAN_TAG_LEN: usize = 4;
pub const IPV4_HEADER_LEN: usize = 20;
pub const ARP_PACKET_LEN: usize = 28;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;

pub const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/// What we know about the network we're sending on: our own MAC/IP, the
/// subnet we're directly attached to, and the default gateway (if any) for
/// off-link destinations.
#[derive(Debug, Clone)]
pub struct InterfaceContext {
    pub name: String,
    pub mac: MacAddr,
    pub ipv4: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
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
}

/// Resolve the machine's default network interface (name, MAC, IPv4/prefix,
/// gateway) via `default-net`. This is what "which interface do we actually
/// send raw frames on" comes down to for now - a future version could let
/// the user pick a specific interface instead of always using the default
/// one. NOTE: this is the one part of the L2 stack not verified against the
/// crate's actual source in this session - double check `default-net`'s
/// exact field/method names here first if this is where a compile error
/// lands.
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

    let gateway = iface.gateway.and_then(|g| match g.ip_addr {
        std::net::IpAddr::V4(ipv4) => Some(ipv4),
        _ => None,
    });

    Ok(InterfaceContext {
        name: iface.name,
        mac,
        ipv4: ipv4_net.addr,
        prefix_len: ipv4_net.prefix_len,
        gateway,
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

pub fn is_arp_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_ARP
}

// ---------------------------------------------------------------------
// ARP - used for gateway/on-link MAC resolution and duplicate-IP checks.
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

/// If `payload` (the L3 bytes after Ethernet/VLAN) is an ARP reply, return
/// its sender IP + MAC.
pub fn parse_arp_reply(payload: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let arp = ArpPacket::new(payload)?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
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
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
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
    let checksum = pnet::packet::ipv4::checksum(&Ipv4Packet::new(&buf).expect("just built this"));
    let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer sized correctly");
    ip.set_checksum(checksum);
    buf
}

/// Parsed view of an incoming IPv4 packet: source, destination, protocol,
/// and where the L4 payload starts within the given slice.
pub struct ParsedIpv4 {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: pnet::packet::ip::IpNextHeaderProtocol,
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

pub fn icmp_protocol() -> pnet::packet::ip::IpNextHeaderProtocol {
    IpNextHeaderProtocols::Icmp
}

// ---------------------------------------------------------------------
// ICMP echo - today's only L4 scan method; TCP-SYN/UDP-null are the
// natural next additions alongside this, reusing everything above.
// ---------------------------------------------------------------------

/// Build an ICMP echo request payload (checksummed) for `identifier`/`sequence`.
pub fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let payload = b"kammer-pinger-l2";
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
    let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(&buf).expect("just built this"));
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