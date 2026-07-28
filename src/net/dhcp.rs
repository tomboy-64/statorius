//! DHCP (RFC 2131/RFC 2132) packet parsing and option decoding, layered on
//! top of `l2_frame`'s Ethernet/VLAN/IPv4/UDP building blocks. This module
//! only ever *reads* captured traffic for the "DHCP" tab's passive exchange
//! log - there's no DHCP client or server here, and nothing it does ever
//! sends a packet.
//!
//! Option **names** (and, for a growing subset, how to render their
//! **value**) come from a bundled lookup table (`dhcp_options.json`,
//! embedded into the binary at compile time via `include_str!` and parsed
//! once on first use) rather than being hardcoded in this file. Only a
//! modest set of the best-known options carry a real `format` hint for now
//! - see the comment at the top of that file. Everything else still gets
//! its correct IANA-registered name, just rendered as a plain hex dump of
//! its raw bytes until a format is added for it - extending coverage later
//! is a matter of editing the JSON, not this module.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::ops::Range;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use pnet_base::MacAddr;
use serde::{Deserialize, Serialize};

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Fixed BOOTP header length (RFC 951/2131), up to but not including the
/// 4-byte magic cookie that marks "this is DHCP, not plain BOOTP".
const BOOTP_FIXED_LEN: usize = 236;
const CHADDR_RANGE: Range<usize> = 28..44;
const SNAME_RANGE: Range<usize> = 44..108;
const FILE_RANGE: Range<usize> = 108..236;

/// One decoded option, ready for the UI - `name` and `value` are both
/// already human-readable strings, so the GUI side never needs to know
/// anything about DHCP itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOptionWire {
    pub code: u8,
    pub name: String,
    pub value: String,
}

/// One captured DHCP/BOOTP message, fully decoded - what the helper sends
/// to the GUI (`L2Message::DhcpEvent`) as soon as it's captured, and what
/// `dhcp_state::DhcpState` groups by `xid` on the GUI side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpMessageWire {
    /// Milliseconds since the Unix epoch - `Instant`/`SystemTime` aren't
    /// serde-friendly across the IPC boundary, so this is the wire-safe
    /// form; the UI formats it for display.
    pub captured_at_unix_ms: u64,
    pub xid: u32,
    /// "DHCPDISCOVER" etc. (resolved from option 53 via the lookup table),
    /// or a fallback label for BOOTP traffic that carries no option 53 at
    /// all.
    pub message_type: String,
    pub client_mac: Option<String>,
    /// Only ever `Some` for a nonzero address - these fixed BOOTP fields
    /// are always present on the wire, but 0.0.0.0 means "not set" and
    /// isn't worth showing.
    pub ciaddr: Option<String>,
    pub yiaddr: Option<String>,
    pub siaddr: Option<String>,
    pub giaddr: Option<String>,
    pub vlan: Option<u16>,
    pub options: Vec<DhcpOptionWire>,
}

/// Scan one TLV option area (RFC 2132 §2): 1 byte code, 1 byte length,
/// `length` bytes of value - except `Pad`(0) and `End`(255), which have no
/// length byte at all. Repeated codes are merged by concatenation (RFC
/// 3396, for options too long to fit in one 255-byte slot), which is also
/// exactly what's needed to fold the overloaded `sname`/`file` areas back
/// into the same option space as the primary one.
fn scan_options(buf: &[u8], out: &mut BTreeMap<u8, Vec<u8>>) {
    let mut i = 0;
    while i < buf.len() {
        let code = buf[i];
        if code == 0 {
            i += 1; // Pad
            continue;
        }
        if code == 255 {
            break; // End
        }
        if i + 1 >= buf.len() {
            break; // truncated - no length byte to read
        }
        let len = buf[i + 1] as usize;
        let start = i + 2;
        let end = (start + len).min(buf.len());
        out.entry(code).or_default().extend_from_slice(&buf[start..end]);
        if end < start + len {
            break; // truncated mid-value - nothing sane left after this
        }
        i = end;
    }
}

/// Raw, undecoded view of one captured message - built purely from bytes,
/// with no knowledge of the lookup table yet.
struct DhcpCore {
    xid: u32,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    client_mac: Option<MacAddr>,
    options: BTreeMap<u8, Vec<u8>>,
}

/// Parse a UDP payload as a BOOTP/DHCP message (RFC 2131 §2) - `None` for
/// anything too short, or missing the magic cookie, or with a nonsensical
/// `op` (this also quietly rejects non-DHCP traffic that happened to land
/// on ports 67/68).
fn parse_core(payload: &[u8]) -> Option<DhcpCore> {
    if payload.len() < BOOTP_FIXED_LEN + 4 {
        return None;
    }
    if payload[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4] != MAGIC_COOKIE {
        return None;
    }
    let op = payload[0];
    if op != 1 && op != 2 {
        return None; // not BOOTREQUEST or BOOTREPLY
    }
    let htype = payload[1];
    let hlen = payload[2] as usize;
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    let siaddr = Ipv4Addr::new(payload[20], payload[21], payload[22], payload[23]);
    let giaddr = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);

    // htype 1 / hlen 6 is Ethernet (by far the common case for anything
    // this app would ever capture); anything else, we don't know how to
    // read as a MAC, so leave it unset rather than guessing.
    let chaddr = &payload[CHADDR_RANGE];
    let client_mac = if htype == 1 && hlen == 6 {
        Some(MacAddr::new(
            chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
        ))
    } else {
        None
    };

    let mut options: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    scan_options(&payload[BOOTP_FIXED_LEN + 4..], &mut options);

    // RFC 2131 §4.1 / §3.19: Option 52 ("Option Overload") says the legacy
    // `sname`/`file` fields have been reused to carry more options, for
    // messages too big to fit everything in the primary options area.
    if let Some(overload) = options.get(&52).and_then(|v| v.first().copied()) {
        if overload & 1 != 0 {
            scan_options(&payload[FILE_RANGE], &mut options);
        }
        if overload & 2 != 0 {
            scan_options(&payload[SNAME_RANGE], &mut options);
        }
    }

    Some(DhcpCore {
        xid,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        client_mac,
        options,
    })
}

/// Parse+decode a UDP payload into a ready-to-send `DhcpMessageWire`, if it
/// looks like a BOOTP/DHCP message. `vlan` is passed through from the
/// captured frame's link-layer info - it isn't part of the DHCP payload
/// itself, just useful context to keep attached to the message.
pub fn parse_dhcp_message(payload: &[u8], vlan: Option<u16>) -> Option<DhcpMessageWire> {
    let core = parse_core(payload)?;
    let captured_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let message_type = core
        .options
        .get(&53)
        .and_then(|v| v.first())
        .map(|code| message_type_name(*code))
        .unwrap_or_else(|| "BOOTP (no message type option)".to_owned());

    let options = core
        .options
        .iter()
        .map(|(code, raw)| decode_option(*code, raw))
        .collect();

    Some(DhcpMessageWire {
        captured_at_unix_ms,
        xid: core.xid,
        message_type,
        client_mac: core.client_mac.map(|m| m.to_string()),
        ciaddr: non_zero(core.ciaddr),
        yiaddr: non_zero(core.yiaddr),
        siaddr: non_zero(core.siaddr),
        giaddr: non_zero(core.giaddr),
        vlan,
        options,
    })
}

fn non_zero(addr: Ipv4Addr) -> Option<String> {
    if addr.is_unspecified() {
        None
    } else {
        Some(addr.to_string())
    }
}

// ---------------------------------------------------------------------
// Lookup table: option names/formats + message type names, bundled at
// compile time (`include_str!`) and parsed once on first use (a plain
// `OnceLock`, not a build-time const - `serde_json` parsing isn't
// `const fn`-able, and re-parsing a small embedded string once per process
// is not worth avoiding). Extending decoding coverage later is purely a
// matter of editing `dhcp_options.json`, never this file.
// ---------------------------------------------------------------------

const LOOKUP_JSON: &str = include_str!("dhcp_options.json");

#[derive(Debug, Deserialize)]
struct OptionDef {
    name: String,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawOptionDef {
    code: u8,
    #[serde(flatten)]
    def: OptionDef,
}

#[derive(Debug, Deserialize)]
struct RawMessageTypeDef {
    code: u8,
    name: String,
}

#[derive(Debug, Deserialize)]
struct LookupTable {
    options: Vec<RawOptionDef>,
    message_types: Vec<RawMessageTypeDef>,
}

struct Lookup {
    options: HashMap<u8, OptionDef>,
    message_types: HashMap<u8, String>,
}

fn lookup() -> &'static Lookup {
    static LOOKUP: OnceLock<Lookup> = OnceLock::new();
    LOOKUP.get_or_init(|| {
        let table: LookupTable = serde_json::from_str(LOOKUP_JSON)
            .expect("dhcp_options.json is bundled at compile time and must parse");
        Lookup {
            options: table.options.into_iter().map(|o| (o.code, o.def)).collect(),
            message_types: table
                .message_types
                .into_iter()
                .map(|m| (m.code, m.name))
                .collect(),
        }
    })
}

fn message_type_name(code: u8) -> String {
    lookup()
        .message_types
        .get(&code)
        .cloned()
        .unwrap_or_else(|| format!("Unknown ({code})"))
}

/// Decode one raw option into its display name/value, using the bundled
/// lookup table for the name and (if present) a `format` hint for the
/// value. A code the table doesn't list at all (shouldn't normally happen -
/// the table aims to cover every IANA-registered tag) still gets a usable
/// fallback rather than being dropped.
fn decode_option(code: u8, raw: &[u8]) -> DhcpOptionWire {
    let (name, value) = match lookup().options.get(&code) {
        Some(def) => {
            let value = match def.format.as_deref() {
                Some(format) => format_value(format, raw),
                None => format_hex(raw),
            };
            (def.name.clone(), value)
        }
        None => (format!("Unknown option {code}"), format_hex(raw)),
    };
    DhcpOptionWire { code, name, value }
}

/// Render one option's raw bytes according to its lookup-table `format`
/// hint. Unrecognized/absent formats (including plain `"hex"`) all fall
/// through to `format_hex` - the always-correct, if unlovely, default.
fn format_value(format: &str, raw: &[u8]) -> String {
    match format {
        "empty" => String::new(),
        "ipv4" => raw
            .chunks_exact(4)
            .next()
            .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
            .unwrap_or_else(|| format_hex(raw)),
        "ipv4-list" => {
            let addrs: Vec<String> = raw
                .chunks_exact(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                .collect();
            if addrs.is_empty() {
                format_hex(raw)
            } else {
                addrs.join("\n")
            }
        }
        "string" => String::from_utf8_lossy(raw).trim_end_matches('\0').to_string(),
        "bool" => match raw.first() {
            Some(0) => "No".to_owned(),
            Some(_) => "Yes".to_owned(),
            None => format_hex(raw),
        },
        "u8" => raw.first().map(|b| b.to_string()).unwrap_or_else(|| format_hex(raw)),
        "u16" => {
            if raw.len() >= 2 {
                u16::from_be_bytes([raw[0], raw[1]]).to_string()
            } else {
                format_hex(raw)
            }
        }
        "u32" => {
            if raw.len() >= 4 {
                u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]).to_string()
            } else {
                format_hex(raw)
            }
        }
        "i32" => {
            if raw.len() >= 4 {
                i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]).to_string()
            } else {
                format_hex(raw)
            }
        }
        "duration-secs" => {
            if raw.len() >= 4 {
                format_duration(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
            } else {
                format_hex(raw)
            }
        }
        "message-type" => raw
            .first()
            .map(|c| message_type_name(*c))
            .unwrap_or_else(|| format_hex(raw)),
        "option-code-list" => {
            if raw.is_empty() {
                format_hex(raw)
            } else {
                raw.iter()
                    .map(|c| match lookup().options.get(c) {
                        Some(d) => format!("{} ({c})", d.name),
                        None => format!("Unknown ({c})"),
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        _ => format_hex(raw),
    }
}

/// `0xffffffff` (RFC 2131 §3.3: "infinite" lease) gets its own label rather
/// than printing out as roughly 136 years.
fn format_duration(secs: u32) -> String {
    if secs == u32::MAX {
        return "infinite".to_owned();
    }
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn format_hex(raw: &[u8]) -> String {
    if raw.is_empty() {
        return "(empty)".to_owned();
    }
    raw.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}