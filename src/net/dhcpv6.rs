//! DHCPv6 (RFC 8415) packet parsing and option decoding, the IPv6 counterpart
//! of `dhcp.rs`. Like that module it only ever *reads* captured traffic for
//! the "DHCP" tab; nothing here sends a packet.
//!
//! A message is decoded into the same `DhcpMessageWire` as a DHCPv4 one:
//! the 24-bit transaction id becomes `xid`, options are rendered to display
//! strings, and the DHCPv6-specific context (DUIDs, addresses and prefixes
//! carried in IA options, the IPv6 source and destination) goes into the
//! extra fields. Relay messages (RELAY-FORW / RELAY-REPL) are unwrapped:
//! the message they carry (option 9) supplies the transaction id, DUIDs and
//! addresses, and its options are listed after the relay's own.
//!
//! Option names, message types and status codes come from a bundled lookup
//! table (`dhcpv6_options.json`, embedded at compile time), the same way
//! `dhcp.rs` does it for DHCPv4. Codes the table doesn't list are shown as
//! "Unknown option N" with a hex dump of their data.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

use serde::Deserialize;

use super::dhcp::{self, DhcpMessageWire, DhcpOptionWire, DhcpVersion};

const LOOKUP_JSON: &str = include_str!("dhcpv6_options.json");

/// Relay messages nested deeper than this are not followed (a relay chain
/// longer than 8 hops doesn't occur: the RFC's hop limit is 32 and real
/// networks use one or two).
const MAX_RELAY_DEPTH: u8 = 8;
const MSG_RELAY_FORW: u8 = 12;
const MSG_RELAY_REPL: u8 = 13;
/// Highest message type decoded (LEASEQUERY-DATA); anything above is
/// treated as not DHCPv6.
const MAX_MESSAGE_TYPE: u8 = 17;
const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IA_TA: u16 = 4;
const OPT_IAADDR: u16 = 5;
const OPT_RELAY_MSG: u16 = 9;
const OPT_STATUS_CODE: u16 = 13;
const OPT_IA_PD: u16 = 25;
const OPT_IAPREFIX: u16 = 26;

// ---------------------------------------------------------------------
// Lookup table
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OptionDef {
    name: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    rfc: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawOptionDef {
    code: u16,
    #[serde(flatten)]
    def: OptionDef,
}

#[derive(Debug, Deserialize)]
struct RawNamed {
    code: u16,
    name: String,
}

#[derive(Debug, Deserialize)]
struct LookupTable {
    options: Vec<RawOptionDef>,
    message_types: Vec<RawNamed>,
    status_codes: Vec<RawNamed>,
}

struct Lookup {
    options: HashMap<u16, OptionDef>,
    message_types: HashMap<u16, String>,
    status_codes: HashMap<u16, String>,
}

fn lookup() -> &'static Lookup {
    static LOOKUP: OnceLock<Lookup> = OnceLock::new();
    LOOKUP.get_or_init(|| {
        let table: LookupTable = serde_json::from_str(LOOKUP_JSON)
            .expect("dhcpv6_options.json is bundled at compile time and must parse");
        Lookup {
            options: table.options.into_iter().map(|o| (o.code, o.def)).collect(),
            message_types: table.message_types.into_iter().map(|m| (m.code, m.name)).collect(),
            status_codes: table.status_codes.into_iter().map(|s| (s.code, s.name)).collect(),
        }
    })
}

fn message_type_name(code: u8) -> String {
    lookup()
        .message_types
        .get(&u16::from(code))
        .cloned()
        .unwrap_or_else(|| format!("Unknown ({code})"))
}

fn option_name(code: u16) -> String {
    lookup()
        .options
        .get(&code)
        .map(|d| d.name.clone())
        .unwrap_or_else(|| format!("Unknown option {code}"))
}

/// A short explainer plus the defining standard of an option, for the hover
/// tooltip on its name - `None` where the table has neither.
pub fn option_help(code: u16) -> Option<String> {
    let def = lookup().options.get(&code)?;
    match (&def.description, &def.rfc) {
        (Some(desc), Some(rfc)) => Some(format!("{desc}\n\n{rfc}")),
        (Some(desc), None) => Some(desc.clone()),
        (None, Some(rfc)) => Some(rfc.clone()),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------
// Wire parsing
// ---------------------------------------------------------------------

/// Scan one option area: 2 bytes code, 2 bytes length, `length` bytes of
/// value (RFC 8415 §21.1). Unlike DHCPv4 there is no padding or end marker
/// and a repeated code is a separate option, so the result keeps every
/// option, in order. A value cut short by the end of the buffer is kept as
/// far as it goes and ends the scan.
fn scan_options(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let code = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = usize::from(u16::from_be_bytes([buf[i + 2], buf[i + 3]]));
        let start = i + 4;
        let end = (start + len).min(buf.len());
        out.push((code, buf[start..end].to_vec()));
        if end < start + len {
            break;
        }
        i = end;
    }
    out
}

/// A client/server message, or a relay message with the message it carries.
struct Message {
    msg_type: u8,
    xid: u32,
    /// `(hop count, link address, peer address)` of a relay message.
    relay: Option<(u8, Ipv6Addr, Ipv6Addr)>,
    options: Vec<(u16, Vec<u8>)>,
    inner: Option<Box<Message>>,
}

impl Message {
    /// The client/server message at the end of any relay chain.
    fn innermost(&self) -> &Message {
        match &self.inner {
            Some(inner) => inner.innermost(),
            None => self,
        }
    }
}

fn ipv6_at(buf: &[u8], at: usize) -> Option<Ipv6Addr> {
    let bytes: [u8; 16] = buf.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(bytes))
}

/// `None` for anything too short or whose type isn't a DHCPv6 message
/// (this also quietly rejects other traffic that happened to use
/// ports 546/547).
fn parse_message(buf: &[u8], depth: u8) -> Option<Message> {
    if depth > MAX_RELAY_DEPTH {
        return None;
    }
    let msg_type = *buf.first()?;
    if msg_type == MSG_RELAY_FORW || msg_type == MSG_RELAY_REPL {
        // type, hop-count, link-address (16), peer-address (16), options
        let hop = *buf.get(1)?;
        let link = ipv6_at(buf, 2)?;
        let peer = ipv6_at(buf, 18)?;
        let options = scan_options(&buf[34..]);
        let inner = options
            .iter()
            .find(|(code, _)| *code == OPT_RELAY_MSG)
            .and_then(|(_, data)| parse_message(data, depth + 1))
            .map(Box::new);
        let xid = inner.as_ref().map_or(0, |m| m.xid);
        return Some(Message { msg_type, xid, relay: Some((hop, link, peer)), options, inner });
    }
    if msg_type == 0 || msg_type > MAX_MESSAGE_TYPE || buf.len() < 4 {
        return None;
    }
    let xid = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]);
    Some(Message { msg_type, xid, relay: None, options: scan_options(&buf[4..]), inner: None })
}

fn describe_type(m: &Message) -> String {
    let name = message_type_name(m.msg_type);
    match &m.relay {
        None => name,
        Some((hop, link, peer)) => {
            let mut text = format!("{name} (hop {hop}, link {link}, peer {peer})");
            if let Some(inner) = &m.inner {
                text.push_str(" carrying ");
                text.push_str(&describe_type(inner));
            }
            text
        }
    }
}

/// Parse a UDP payload (ports 546/547) into a ready-to-send
/// `DhcpMessageWire`. `src`/`dst` are the IPv6 addresses of the captured
/// packet and `vlan` its link-layer VLAN, kept as context.
pub fn parse_dhcpv6_message(
    payload: &[u8],
    vlan: Option<u16>,
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Option<DhcpMessageWire> {
    let message = parse_message(payload, 0)?;
    let core = message.innermost();

    let first = |code: u16| core.options.iter().find(|(c, _)| *c == code).map(|(_, d)| d);

    let mut options = Vec::new();
    flatten_options(&message, &mut options);

    Some(DhcpMessageWire {
        captured_at_unix_ms: dhcp::now_unix_ms(),
        version: DhcpVersion::V6,
        xid: message.xid,
        message_type: describe_type(&message),
        client_mac: None,
        ciaddr: None,
        yiaddr: None,
        siaddr: None,
        giaddr: None,
        vlan,
        options,
        client_duid: first(OPT_CLIENTID).map(|d| format_duid(d)),
        server_duid: first(OPT_SERVERID).map(|d| format_duid(d)),
        src_ip: Some(src.to_string()),
        dst_ip: Some(dst.to_string()),
        addresses: collect_addresses(&core.options),
    })
}

/// The relay chain's options first, outermost to innermost, ending with the
/// carried message's own.
fn flatten_options(m: &Message, out: &mut Vec<DhcpOptionWire>) {
    for (code, data) in &m.options {
        out.push(decode_option(*code, data));
    }
    if let Some(inner) = &m.inner {
        flatten_options(inner, out);
    }
}

/// Every address and prefix in the IA_NA / IA_TA / IA_PD options.
fn collect_addresses(options: &[(u16, Vec<u8>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (code, data) in options {
        let header = match *code {
            OPT_IA_NA | OPT_IA_PD => 12,
            OPT_IA_TA => 4,
            _ => continue,
        };
        let Some(sub) = data.get(header..) else { continue };
        for (sub_code, sub_data) in scan_options(sub) {
            match sub_code {
                OPT_IAADDR => {
                    if let Some(addr) = ipv6_at(&sub_data, 0) {
                        out.push(addr.to_string());
                    }
                }
                OPT_IAPREFIX => {
                    if let (Some(&len), Some(prefix)) = (sub_data.get(8), ipv6_at(&sub_data, 9)) {
                        out.push(format!("{prefix}/{len}"));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

// ---------------------------------------------------------------------
// Option rendering
// ---------------------------------------------------------------------

/// How a `format` hint is encoded on the wire - shown next to the value.
/// Formats shared with DHCPv4 use that module's wording.
fn type_label(format: Option<&str>) -> String {
    match format {
        Some("duid") => "DUID (variable length)".to_owned(),
        Some("ia-na") | Some("ia-pd") => {
            "identity association: IAID, T1, T2 (32 bits each) and sub-options".to_owned()
        }
        Some("ia-ta") => "identity association: IAID (32 bits) and sub-options".to_owned(),
        Some("ia-addr") => "IPv6 address, preferred/valid lifetimes and sub-options".to_owned(),
        Some("ia-prefix") => "lifetimes, prefix length and IPv6 prefix".to_owned(),
        Some("ipv6") => "IPv6 address (16 bytes)".to_owned(),
        Some("ipv6-list") => "list of IPv6 addresses (16 bytes each)".to_owned(),
        Some("option-code-list") => "list of 16-bit option codes".to_owned(),
        Some("u16-list") => "list of unsigned 16-bit integers".to_owned(),
        Some("elapsed") => "unsigned 16-bit integer (hundredths of a second)".to_owned(),
        Some("relay-message") => "embedded DHCPv6 message".to_owned(),
        Some("status-code") => "status code (16 bits) and message".to_owned(),
        Some("user-class") => "list of length-prefixed opaque strings".to_owned(),
        Some("vendor-class") => "enterprise number (32 bits) and class data".to_owned(),
        Some("vendor-opts") => "enterprise number (32 bits) and sub-options".to_owned(),
        Some("domain-list") => "domain names (DNS label encoding)".to_owned(),
        Some("fqdn") => "flags (8 bits) and domain name".to_owned(),
        Some("message-type") => "unsigned 8-bit integer (enumerated)".to_owned(),
        other => dhcp::type_label(other),
    }
}

fn decode_option(code: u16, raw: &[u8]) -> DhcpOptionWire {
    let (name, data_type, value) = match lookup().options.get(&code) {
        Some(def) => {
            let format = def.format.as_deref();
            let value = match format {
                Some(format) => format_value(format, raw),
                None => dhcp::format_hex(raw),
            };
            (def.name.clone(), type_label(format), value)
        }
        None => (format!("Unknown option {code}"), type_label(None), dhcp::format_hex(raw)),
    };
    DhcpOptionWire { code, name, data_type, value }
}

fn life(secs: u32) -> String {
    dhcp::format_duration(secs)
}

fn u32_at(raw: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = raw.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn format_value(format: &str, raw: &[u8]) -> String {
    match format {
        "duid" => format_duid(raw),
        "ia-na" | "ia-pd" => format_ia(raw, true),
        "ia-ta" => format_ia(raw, false),
        "ia-addr" => describe_sub(OPT_IAADDR, raw),
        "ia-prefix" => describe_sub(OPT_IAPREFIX, raw),
        "ipv6" => ipv6_at(raw, 0).map_or_else(|| dhcp::format_hex(raw), |a| a.to_string()),
        "ipv6-list" => {
            let addrs: Vec<String> = raw
                .chunks_exact(16)
                .filter_map(|c| ipv6_at(c, 0))
                .map(|a| a.to_string())
                .collect();
            if addrs.is_empty() || raw.len() % 16 != 0 {
                dhcp::format_hex(raw)
            } else {
                addrs.join("\n")
            }
        }
        "option-code-list" => {
            if raw.is_empty() || raw.len() % 2 != 0 {
                return dhcp::format_hex(raw);
            }
            raw.chunks_exact(2)
                .map(|c| {
                    let code = u16::from_be_bytes([c[0], c[1]]);
                    format!("{} ({code})", option_name(code))
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        "u16-list" => {
            if raw.is_empty() || raw.len() % 2 != 0 {
                return dhcp::format_hex(raw);
            }
            raw.chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
        "elapsed" => match raw {
            [a, b] => format!("{} ms", u32::from(u16::from_be_bytes([*a, *b])) * 10),
            _ => dhcp::format_hex(raw),
        },
        "relay-message" => match parse_message(raw, 1) {
            Some(m) => format!(
                "{} (xid 0x{:06x}), {} option(s) - listed below",
                describe_type(&m),
                m.xid,
                m.innermost().options.len()
            ),
            None => dhcp::format_hex(raw),
        },
        "status-code" => format_status(raw),
        "user-class" => format_user_class(raw),
        "vendor-class" => format_vendor_class(raw),
        "vendor-opts" => format_vendor_opts(raw),
        "domain-list" => match decode_domains(raw) {
            Some(names) => names.join("\n"),
            None => dhcp::format_hex(raw),
        },
        "fqdn" => match raw.split_first() {
            Some((flags, rest)) => match decode_domains(rest) {
                Some(names) => format!("{} (flags 0x{flags:02x})", names.join(", ")),
                None => dhcp::format_hex(raw),
            },
            None => dhcp::format_hex(raw),
        },
        "message-type" => raw
            .first()
            .map(|c| message_type_name(*c))
            .unwrap_or_else(|| dhcp::format_hex(raw)),
        // "empty", "string", "u8", "u16", "u32", "duration-secs", "hex" and
        // anything unrecognized: the same rendering as DHCPv4.
        other => dhcp::format_value(other, raw),
    }
}

/// DUID (RFC 8415 §11): a 16-bit type, then type-specific content.
fn format_duid(raw: &[u8]) -> String {
    let Some(kind) = raw.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return dhcp::format_hex(raw);
    };
    let hardware = |at: usize| -> Option<(String, String)> {
        let hw = u16::from_be_bytes([*raw.get(at)?, *raw.get(at + 1)?]);
        let addr = raw.get(at + 2 + if kind == 1 { 4 } else { 0 }..)?;
        let hw_name = if hw == 1 { "Ethernet".to_owned() } else { format!("hardware type {hw}") };
        Some((hw_name, dhcp::format_hex(addr)))
    };
    match kind {
        1 => match (hardware(2), u32_at(raw, 4)) {
            (Some((hw, addr)), Some(time)) => {
                format!("DUID-LLT, {hw} {addr}, time {time} s since 2000-01-01")
            }
            _ => dhcp::format_hex(raw),
        },
        2 => match u32_at(raw, 2) {
            Some(enterprise) => format!(
                "DUID-EN, enterprise {enterprise}, id {}",
                dhcp::format_hex(&raw[6..])
            ),
            None => dhcp::format_hex(raw),
        },
        3 => match hardware(2) {
            Some((hw, addr)) => format!("DUID-LL, {hw} {addr}"),
            None => dhcp::format_hex(raw),
        },
        4 if raw.len() == 18 => {
            let u = &raw[2..];
            format!(
                "DUID-UUID, {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12],
                u[13], u[14], u[15]
            )
        }
        _ => format!("DUID type {kind}, {}", dhcp::format_hex(&raw[2..])),
    }
}

/// IA_NA / IA_PD (`with_timers`, 12-byte header) or IA_TA (4-byte header),
/// followed by the sub-options (addresses, prefixes, status).
fn format_ia(raw: &[u8], with_timers: bool) -> String {
    let header = if with_timers { 12 } else { 4 };
    let Some(iaid) = u32_at(raw, 0) else {
        return dhcp::format_hex(raw);
    };
    if raw.len() < header {
        return dhcp::format_hex(raw);
    }
    let mut lines = Vec::new();
    if with_timers {
        let (t1, t2) = (u32_at(raw, 4).unwrap_or(0), u32_at(raw, 8).unwrap_or(0));
        lines.push(format!("IAID 0x{iaid:08x}, T1 {}, T2 {}", life(t1), life(t2)));
    } else {
        lines.push(format!("IAID 0x{iaid:08x}"));
    }
    for (code, data) in scan_options(&raw[header..]) {
        lines.push(describe_sub(code, &data));
    }
    lines.join("\n")
}

/// One sub-option of an IA: an address, a prefix or a status code; anything
/// else by name with a hex dump.
fn describe_sub(code: u16, data: &[u8]) -> String {
    match code {
        OPT_IAADDR => match (ipv6_at(data, 0), u32_at(data, 16), u32_at(data, 20)) {
            (Some(addr), Some(preferred), Some(valid)) => {
                let mut text =
                    format!("address {addr} (preferred {}, valid {})", life(preferred), life(valid));
                for (c, d) in scan_options(&data[24..]) {
                    text.push_str("\n  ");
                    text.push_str(&describe_sub(c, &d));
                }
                text
            }
            _ => dhcp::format_hex(data),
        },
        OPT_IAPREFIX => match (u32_at(data, 0), u32_at(data, 4), data.get(8), ipv6_at(data, 9)) {
            (Some(preferred), Some(valid), Some(len), Some(prefix)) => {
                let mut text = format!(
                    "prefix {prefix}/{len} (preferred {}, valid {})",
                    life(preferred),
                    life(valid)
                );
                for (c, d) in scan_options(&data[25..]) {
                    text.push_str("\n  ");
                    text.push_str(&describe_sub(c, &d));
                }
                text
            }
            _ => dhcp::format_hex(data),
        },
        OPT_STATUS_CODE => format!("status {}", format_status(data)),
        _ => format!("{} ({code}): {}", option_name(code), dhcp::format_hex(data)),
    }
}

/// Status code option: a 16-bit code and an optional text message.
fn format_status(raw: &[u8]) -> String {
    let Some(code) = raw.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return dhcp::format_hex(raw);
    };
    let name = lookup()
        .status_codes
        .get(&code)
        .cloned()
        .unwrap_or_else(|| format!("code {code}"));
    let message = String::from_utf8_lossy(&raw[2..]);
    if message.is_empty() {
        name
    } else {
        format!("{name}: {message}")
    }
}

/// Domain names in DNS label encoding (RFC 1035 §3.1, no compression), one
/// after the other; `None` if the data isn't well-formed.
fn decode_domains(raw: &[u8]) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let mut labels = Vec::new();
        loop {
            let len = usize::from(*raw.get(i)?);
            i += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            labels.push(String::from_utf8_lossy(raw.get(i..i + len)?).into_owned());
            i += len;
        }
        names.push(if labels.is_empty() { ".".to_owned() } else { labels.join(".") });
    }
    if names.is_empty() { None } else { Some(names) }
}

/// A list of `(2-byte length, data)` entries, as used by User Class and
/// Vendor Class; `None` if the lengths don't add up.
fn length_prefixed_list(raw: &[u8]) -> Option<Vec<&[u8]>> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let len = usize::from(u16::from_be_bytes([*raw.get(i)?, *raw.get(i + 1)?]));
        entries.push(raw.get(i + 2..i + 2 + len)?);
        i += 2 + len;
    }
    Some(entries)
}

fn format_user_class(raw: &[u8]) -> String {
    match length_prefixed_list(raw) {
        Some(entries) if !entries.is_empty() => entries
            .iter()
            .map(|e| format!("\"{}\"", String::from_utf8_lossy(e)))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => dhcp::format_hex(raw),
    }
}

fn format_vendor_class(raw: &[u8]) -> String {
    let (Some(enterprise), Some(rest)) = (u32_at(raw, 0), raw.get(4..)) else {
        return dhcp::format_hex(raw);
    };
    match length_prefixed_list(rest) {
        Some(entries) => {
            let mut lines = vec![format!("enterprise {enterprise}")];
            lines.extend(entries.iter().map(|e| format!("\"{}\"", String::from_utf8_lossy(e))));
            lines.join("\n")
        }
        None => dhcp::format_hex(raw),
    }
}

fn format_vendor_opts(raw: &[u8]) -> String {
    let (Some(enterprise), Some(rest)) = (u32_at(raw, 0), raw.get(4..)) else {
        return dhcp::format_hex(raw);
    };
    let mut lines = vec![format!("enterprise {enterprise}")];
    for (code, data) in scan_options(rest) {
        lines.push(format!("sub-option {code}: {}", dhcp::format_hex(&data)));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

    /// One option: code, length, data.
    fn opt(code: u16, data: &[u8]) -> Vec<u8> {
        let mut v = code.to_be_bytes().to_vec();
        v.extend((data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn message(msg_type: u8, xid: u32, options: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![msg_type];
        v.extend_from_slice(&xid.to_be_bytes()[1..]);
        for o in options {
            v.extend_from_slice(o);
        }
        v
    }

    const DUID_LLT: [u8; 14] = [0, 1, 0, 1, 0x2c, 0x3b, 0x9a, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const DUID_LL: [u8; 10] = [0, 3, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn ia_na_with_address() -> Vec<u8> {
        // IAID, T1, T2, then IAADDR 2001:db8::5 (preferred 3600, valid 7200)
        let mut addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets().to_vec();
        addr.extend(3600u32.to_be_bytes());
        addr.extend(7200u32.to_be_bytes());
        let mut ia = vec![0, 0, 0, 1];
        ia.extend(1800u32.to_be_bytes());
        ia.extend(2880u32.to_be_bytes());
        ia.extend(opt(OPT_IAADDR, &addr));
        opt(OPT_IA_NA, &ia)
    }

    #[test]
    fn solicit_is_decoded() {
        let payload = message(
            1,
            0x00ab_cdef,
            &[
                opt(OPT_CLIENTID, &DUID_LLT),
                opt(8, &[0, 0]),
                opt(6, &[0, 23, 0, 24]),
                opt(OPT_IA_NA, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            ],
        );
        let msg = parse_dhcpv6_message(&payload, Some(10), SRC, DST).unwrap();
        assert_eq!(msg.version, DhcpVersion::V6);
        assert_eq!(msg.xid, 0x00ab_cdef);
        assert_eq!(msg.message_type, "SOLICIT");
        assert_eq!(msg.vlan, Some(10));
        assert_eq!(msg.src_ip.as_deref(), Some("fe80::1"));
        assert_eq!(msg.dst_ip.as_deref(), Some("ff02::1:2"));
        assert!(msg.client_duid.as_deref().unwrap().starts_with("DUID-LLT, Ethernet aa:bb:cc:dd:ee:ff"));
        assert!(msg.server_duid.is_none());
        assert_eq!(msg.options.len(), 4);
        let oro = &msg.options[2];
        assert_eq!(oro.name, "Option Request");
        assert_eq!(oro.value, "DNS Recursive Name Server (23)\nDomain Search List (24)");
        assert_eq!(msg.options[1].value, "0 ms");
    }

    #[test]
    fn advertise_shows_addresses_dns_and_status() {
        let dns = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53).octets();
        let payload = message(
            2,
            1,
            &[
                opt(OPT_CLIENTID, &DUID_LL),
                opt(OPT_SERVERID, &DUID_LLT),
                ia_na_with_address(),
                opt(23, &dns),
                opt(7, &[255]),
                opt(OPT_STATUS_CODE, &[0, 0, b'o', b'k']),
            ],
        );
        let msg = parse_dhcpv6_message(&payload, None, SRC, DST).unwrap();
        assert_eq!(msg.message_type, "ADVERTISE");
        assert_eq!(msg.addresses, vec!["2001:db8::5".to_owned()]);
        assert!(msg.server_duid.is_some());
        let ia = msg.options.iter().find(|o| o.code == 3).unwrap();
        assert!(ia.value.contains("IAID 0x00000001, T1 30m 0s, T2 48m 0s"), "{}", ia.value);
        assert!(ia.value.contains("address 2001:db8::5 (preferred 1h 0m, valid 2h 0m)"), "{}", ia.value);
        let dns_opt = msg.options.iter().find(|o| o.code == 23).unwrap();
        assert_eq!(dns_opt.value, "2001:db8::53");
        assert_eq!(msg.options.iter().find(|o| o.code == 13).unwrap().value, "Success: ok");
    }

    #[test]
    fn prefix_delegation_lists_the_prefix() {
        let mut prefix = vec![];
        prefix.extend(3600u32.to_be_bytes());
        prefix.extend(7200u32.to_be_bytes());
        prefix.push(56);
        prefix.extend(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0).octets());
        let mut ia = vec![0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0];
        ia.extend(opt(OPT_IAPREFIX, &prefix));
        let payload = message(7, 2, &[opt(OPT_IA_PD, &ia)]);
        let msg = parse_dhcpv6_message(&payload, None, SRC, DST).unwrap();
        assert_eq!(msg.addresses, vec!["2001:db8:1::/56".to_owned()]);
        assert!(msg.options[0].value.contains("prefix 2001:db8:1::/56"));
    }

    #[test]
    fn relay_messages_are_unwrapped() {
        let inner = message(1, 0x123456, &[opt(OPT_CLIENTID, &DUID_LL)]);
        let mut relay = vec![MSG_RELAY_FORW, 0];
        relay.extend(Ipv6Addr::new(0x2001, 0xdb8, 5, 0, 0, 0, 0, 1).octets());
        relay.extend(SRC.octets());
        relay.extend(opt(18, b"eth1"));
        relay.extend(opt(OPT_RELAY_MSG, &inner));
        let msg = parse_dhcpv6_message(&relay, None, SRC, DST).unwrap();
        assert_eq!(msg.xid, 0x123456, "transaction id comes from the carried message");
        assert_eq!(
            msg.message_type,
            "RELAY-FORW (hop 0, link 2001:db8:5::1, peer fe80::1) carrying SOLICIT"
        );
        assert!(msg.client_duid.as_deref().unwrap().starts_with("DUID-LL, Ethernet 11:22:33:44:55:66"));
        // Relay options first (Interface-Id, Relay Message), then the client's.
        let names: Vec<&str> = msg.options.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["Interface-Id", "Relay Message", "Client Identifier"]);
        assert!(msg.options[1].value.starts_with("SOLICIT (xid 0x123456)"));
    }

    #[test]
    fn garbage_and_truncated_input_is_rejected_or_survives() {
        assert!(parse_dhcpv6_message(&[], None, SRC, DST).is_none());
        assert!(parse_dhcpv6_message(&[1, 0, 0], None, SRC, DST).is_none(), "too short");
        assert!(parse_dhcpv6_message(&[0, 0, 0, 1], None, SRC, DST).is_none(), "type 0");
        assert!(parse_dhcpv6_message(&[99, 0, 0, 1], None, SRC, DST).is_none(), "unknown type");
        assert!(parse_dhcpv6_message(&[MSG_RELAY_FORW, 0, 1, 2], None, SRC, DST).is_none());
        // An option running past the end of the packet is kept as far as it goes.
        let mut cut = message(1, 1, &[opt(OPT_CLIENTID, &DUID_LL)]);
        cut.truncate(cut.len() - 3);
        let msg = parse_dhcpv6_message(&cut, None, SRC, DST).unwrap();
        assert_eq!(msg.options.len(), 1);
        // A relay message nested into itself deeper than the limit stops.
        let mut deep = message(1, 1, &[]);
        for _ in 0..(MAX_RELAY_DEPTH + 2) {
            let mut relay = vec![MSG_RELAY_FORW, 0];
            relay.extend([0u8; 32]);
            relay.extend(opt(OPT_RELAY_MSG, &deep));
            deep = relay;
        }
        let msg = parse_dhcpv6_message(&deep, None, SRC, DST).unwrap();
        assert_eq!(msg.xid, 0, "too deep to reach the carried message");
    }

    #[test]
    fn duids_are_described() {
        assert_eq!(
            format_duid(&DUID_LL),
            "DUID-LL, Ethernet 11:22:33:44:55:66"
        );
        let mut en = vec![0, 2];
        en.extend(311u32.to_be_bytes());
        en.extend([1, 2, 3]);
        assert_eq!(format_duid(&en), "DUID-EN, enterprise 311, id 01:02:03");
        let mut uuid = vec![0, 4];
        uuid.extend(0u8..16);
        assert_eq!(
            format_duid(&uuid),
            "DUID-UUID, 00010203-0405-0607-0809-0a0b0c0d0e0f"
        );
        assert_eq!(format_duid(&[0, 9, 1]), "DUID type 9, 01");
        assert_eq!(format_duid(&[7]), "07");
    }

    #[test]
    fn domain_lists_and_fqdn_decode() {
        let list = [3, b'f', b'o', b'o', 2, b'd', b'e', 0, 3, b'b', b'a', b'r', 0];
        assert_eq!(decode_domains(&list), Some(vec!["foo.de".to_owned(), "bar".to_owned()]));
        assert_eq!(decode_domains(&[3, b'f']), None, "label runs past the end");
        assert_eq!(decode_domains(&[]), None);
        let mut fqdn = vec![1];
        fqdn.extend([4, b'h', b'o', b's', b't', 0]);
        assert_eq!(format_value("fqdn", &fqdn), "host (flags 0x01)");
    }

    #[test]
    fn status_user_and_vendor_class_options_render() {
        assert_eq!(format_status(&[0, 2]), "NoAddrsAvail");
        assert_eq!(format_status(&[0, 99, b'x']), "code 99: x");
        assert_eq!(format_value("user-class", &[0, 2, b'h', b'i']), "\"hi\"");
        let mut vc = 311u32.to_be_bytes().to_vec();
        vc.extend([0, 5]);
        vc.extend(b"MSFT ");
        assert_eq!(format_value("vendor-class", &vc), "enterprise 311\n\"MSFT \"");
        // Malformed lengths fall back to a hex dump instead of panicking.
        assert_eq!(format_value("user-class", &[0, 9, 1]), "00:09:01");
    }

    #[test]
    fn unknown_options_and_types_keep_their_data() {
        let payload = message(1, 1, &[opt(4000, &[0xde, 0xad])]);
        let msg = parse_dhcpv6_message(&payload, None, SRC, DST).unwrap();
        assert_eq!(msg.options[0].name, "Unknown option 4000");
        assert_eq!(msg.options[0].value, "de:ad");
        assert_eq!(message_type_name(15), "LEASEQUERY-REPLY");
        assert_eq!(message_type_name(200), "Unknown (200)");
    }

    #[test]
    fn every_table_entry_has_a_name_and_known_format() {
        const FORMATS: &[&str] = &[
            "duid", "ia-na", "ia-ta", "ia-addr", "ia-prefix", "ipv6", "ipv6-list", "option-code-list",
            "u16-list", "elapsed", "relay-message", "status-code", "user-class", "vendor-class",
            "vendor-opts", "domain-list", "fqdn", "message-type", "ia-pd", "empty", "string", "u8",
            "u16", "u32", "duration-secs", "hex",
        ];
        for (code, def) in &lookup().options {
            assert!(!def.name.is_empty(), "option {code}");
            if let Some(format) = &def.format {
                assert!(FORMATS.contains(&format.as_str()), "option {code}: format {format}");
            }
        }
        assert_eq!(message_type_name(1), "SOLICIT");
        assert_eq!(message_type_name(13), "RELAY-REPL");
    }
}
