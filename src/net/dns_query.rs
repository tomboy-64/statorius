//! On-demand DNS message construction and sending for the "DNS" tab's
//! Query panel - dig-like: pick a record type and some standard options,
//! send the query to one or more servers, see the raw response back
//! (status, flags, timing, every section) rather than just resolved
//! addresses, unlike `dns::resolve` (which the Ping tab uses and only
//! ever wants A/AAAA).
//!
//! This deliberately doesn't go through `hickory_resolver::TokioResolver`
//! (which decides transport/retries/EDNS on its own, and only ever hands
//! back addresses) - a query panel needs to control exactly what goes on
//! the wire (an arbitrary record type, TCP vs UDP, the RD/CD/DO bits) and
//! see exactly what comes back. So this builds and parses `Message`s
//! directly against `hickory_resolver::proto` - a re-export of
//! `hickory-proto`, already pulled in transitively by the
//! `hickory-resolver` dependency `dns.rs` already uses, so no new crate is
//! needed - and sends them over a plain `tokio::net` UDP/TCP socket rather
//! than a resolver-managed connection.
//!
//! Two entry points, both called from `dns.rs`'s `dns_worker`:
//! - `query_all` - a normal query, fanned out to every selected server.
//! - `trace` - dig's `+trace`: walks the delegation chain by hand,
//!   starting at the root hints, independent of whatever's selected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use hickory_resolver::proto::op::{Edns, Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// How long to wait for a single UDP/TCP round trip before giving up on
/// that server. Applied per attempt - a `+trace` job tries several
/// servers per hop, so one slow/unreachable server costs at most
/// `TRACE_HOP_TIMEOUT`, not the whole trace.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Same idea, shorter - used for each individual server tried during a
/// `+trace` hop, where a root/TLD server being unreachable from this
/// network (firewalled, IPv6-only, etc.) is expected often enough that
/// waiting the full `QUERY_TIMEOUT` on each one before moving to the next
/// candidate would make a trace painfully slow.
const TRACE_HOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Modern EDNS UDP payload size - large enough for most DNSSEC-signed
/// answers without a second round trip, but per the 2020 "DNS Flag Day"
/// guidance, kept below the ~1280 byte IPv6 minimum MTU so mid-path
/// fragmentation doesn't silently drop the response before it gets here.
/// `dig` has defaulted to the same value since BIND 9.16.
const EDNS_MAX_PAYLOAD: u16 = 1232;

/// How many delegations `trace` will follow before giving up - a generous
/// ceiling against a referral loop (misconfigured or hostile zone), well
/// above the ~10 hops a real chain ever needs.
const MAX_TRACE_HOPS: usize = 20;

/// Every dig-like knob the Query panel exposes.
#[derive(Debug, Clone, Copy)]
pub struct QueryOptions {
    pub record_type: RecordType,
    /// dig's `+tcp` - use TCP even if the query would fit in a single UDP
    /// datagram.
    pub use_tcp: bool,
    /// dig's `+[no]recurse` (the RD bit).
    pub recursion_desired: bool,
    /// dig's `+dnssec` - sets the EDNS DO bit, so a signed zone includes
    /// its RRSIG/DNSKEY/etc. records in the response. This only requests
    /// and displays them; it does not itself validate any signature - see
    /// the DNS tab's tooltip for why that's the right scope here.
    pub dnssec_ok: bool,
    /// dig's `+cdflag` (the CD bit) - tells an upstream validating
    /// resolver not to withhold an answer that fails its own DNSSEC
    /// validation. Mainly useful paired with `dnssec_ok` when deliberately
    /// inspecting a broken/bogus zone.
    pub checking_disabled: bool,
}

/// One server's reply to a single query - or the reason it didn't get one.
#[derive(Debug, Clone)]
pub struct QueryOutcome {
    pub server: IpAddr,
    pub elapsed: Duration,
    pub result: Result<DnsAnswer, String>,
}

/// Everything worth showing about one response: dig prints a status line,
/// a flags line, and then the answer/authority/additional sections - this
/// is that, with each record already formatted via `Record`'s own
/// `Display` (which already knows how to print every record type's rdata
/// correctly) rather than hand-rolled formatting here.
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    /// dig-style short mnemonic - "NOERROR", "NXDOMAIN", etc. - see
    /// `response_code_label`.
    pub response_code: String,
    pub flags: ResponseFlags,
    /// Size of the response on the wire, in bytes.
    pub message_size: usize,
    /// `true` if this went out over UDP but came back truncated (the TC
    /// bit) and was automatically retried over TCP - the same thing `dig`
    /// does, not something the user has to notice and redo by hand.
    pub retried_over_tcp: bool,
    pub answers: Vec<String>,
    pub authorities: Vec<String>,
    pub additionals: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseFlags {
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    /// The AD bit - the *responding server's own* claim that it validated
    /// DNSSEC for this answer. Read straight off the response header, not
    /// re-derived here - see `QueryOptions::dnssec_ok`.
    pub authenticated_data: bool,
    pub checking_disabled: bool,
}

/// One hop of a `+trace` run: which server answered, what it said, and
/// (for the 13 root servers only) a cosmetic hostname label - dig prints
/// e.g. "from a.root-servers.net" for those, so this does too, but doesn't
/// bother re-deriving a label for every hop after the root, where it isn't
/// worth the trouble.
#[derive(Debug, Clone)]
pub struct TraceHop {
    pub server: IpAddr,
    pub server_label: Option<String>,
    pub elapsed: Duration,
    pub result: Result<DnsAnswer, String>,
}

#[derive(Debug, Clone)]
pub struct TraceOutcome {
    pub hops: Vec<TraceHop>,
    /// Set if the trace stopped for a reason that isn't itself a hop (a
    /// referral with no NS records, every server for a delegation being
    /// unreachable, the hop cap being hit) - `None` if the last hop's own
    /// answer is the natural end of the trace.
    pub note: Option<String>,
}

/// The well-known, rarely-changing set of 13 root server addresses (both
/// families) - current as of the IANA `named.root` file dated 2026-07-29.
/// `+trace` always starts here, regardless of which servers happen to be
/// checked on the DNS tab - same as plain `dig +trace` without an
/// `@server` - so a trace's very first hop can't be broken by whatever the
/// user has (or hasn't) checked above.
const ROOT_HINTS: &[(&str, IpAddr)] = &[
    ("a.root-servers.net", IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4))),
    (
        "a.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30)),
    ),
    ("b.root-servers.net", IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2))),
    (
        "b.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb)),
    ),
    ("c.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12))),
    (
        "c.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 2, 0, 0, 0, 0, 0xc)),
    ),
    ("d.root-servers.net", IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13))),
    (
        "d.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd)),
    ),
    ("e.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10))),
    (
        "e.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe)),
    ),
    ("f.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241))),
    (
        "f.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf)),
    ),
    ("g.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4))),
    (
        "g.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d)),
    ),
    ("h.root-servers.net", IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53))),
    (
        "h.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 1, 0, 0, 0, 0, 0x53)),
    ),
    ("i.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17))),
    (
        "i.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53)),
    ),
    ("j.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30))),
    (
        "j.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 2, 0x30)),
    ),
    ("k.root-servers.net", IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129))),
    (
        "k.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 1)),
    ),
    ("l.root-servers.net", IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42))),
    (
        "l.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42)),
    ),
    ("m.root-servers.net", IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33))),
    (
        "m.root-servers.net",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35)),
    ),
];

/// Sends `name`/`options.record_type` to every one of `servers`, in
/// parallel, and waits for all of them to either answer or fail. Each
/// server gets its own spawned task (not just polled concurrently in a
/// join), so one slow/unreachable server can't delay how quickly the
/// others' results become available.
pub async fn query_all(name: &str, servers: &[IpAddr], options: QueryOptions) -> Vec<QueryOutcome> {
    let parsed_name = match parse_query_name(name, options.record_type) {
        Ok(n) => n,
        Err(e) => {
            return servers
                .iter()
                .map(|&server| QueryOutcome {
                    server,
                    elapsed: Duration::ZERO,
                    result: Err(e.clone()),
                })
                .collect();
        }
    };

    let handles: Vec<_> = servers
        .iter()
        .map(|&server| {
            let name = parsed_name.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                let result = send_query_to_server(server, &name, options, QUERY_TIMEOUT)
                    .await
                    .map(|raw| to_dns_answer(&raw.message, raw.message_size, raw.retried_over_tcp));
                QueryOutcome { server, elapsed: start.elapsed(), result }
            })
        })
        .collect();

    let mut outcomes = Vec::with_capacity(handles.len());
    for (server, handle) in servers.iter().zip(handles) {
        let outcome = handle.await.unwrap_or_else(|e| QueryOutcome {
            server: *server,
            elapsed: Duration::ZERO,
            result: Err(format!("Internal error while querying {server}: {e}")),
        });
        outcomes.push(outcome);
    }
    outcomes
}

/// dig's `+trace`: starts at the 13 root hints and walks the delegation
/// chain by hand - query a server, and if it isn't authoritative, follow
/// the NS records (and glue, if present) it hands back for the next zone
/// cut down - until a server actually answers or the chain ends
/// (NXDOMAIN, no further delegation, or `MAX_TRACE_HOPS` is hit).
/// `fallback_servers` is only used if a referral is missing glue and an NS
/// name needs an ordinary recursive lookup to get an address - normally
/// whatever's checked on the DNS tab, so that lookup doesn't depend on
/// this trace already having a working resolver.
pub async fn trace(
    name: &str,
    record_type: RecordType,
    dnssec_ok: bool,
    fallback_servers: &[IpAddr],
) -> TraceOutcome {
    let target_name = match parse_query_name(name, record_type) {
        Ok(n) => n,
        Err(e) => return TraceOutcome { hops: Vec::new(), note: Some(e) },
    };

    let options = QueryOptions {
        record_type,
        use_tcp: false,
        // Iterative, not recursive: each server here is asked only to say
        // what it itself knows (a real answer or a referral), never to
        // chase the rest of the chain on our behalf - that's the whole
        // point of walking it by hand.
        recursion_desired: false,
        dnssec_ok,
        checking_disabled: false,
    };

    let mut hops: Vec<TraceHop> = Vec::new();
    let mut candidates: Vec<(IpAddr, Option<String>)> = ROOT_HINTS
        .iter()
        .map(|&(label, ip)| (ip, Some(label.to_owned())))
        .collect();

    loop {
        if hops.len() >= MAX_TRACE_HOPS {
            return TraceOutcome {
                hops,
                note: Some(format!("Stopped after {MAX_TRACE_HOPS} hops without a final answer")),
            };
        }

        let (server, label, raw, elapsed) =
            match query_first_responsive(&candidates, &target_name, options).await {
                Ok(hit) => hit,
                Err(e) => {
                    return TraceOutcome {
                        hops,
                        note: Some(format!("No server for this delegation responded ({e})")),
                    };
                }
            };

        hops.push(TraceHop {
            server,
            server_label: label,
            elapsed,
            result: Ok(to_dns_answer(&raw.message, raw.message_size, raw.retried_over_tcp)),
        });

        // A real answer, or a terminal error (NXDOMAIN and friends), ends
        // the trace - there's nothing left to delegate further.
        if !raw.message.answers.is_empty() || raw.message.metadata.response_code != ResponseCode::NoError {
            return TraceOutcome { hops, note: None };
        }

        // No answer, NOERROR: a referral. The next hop's servers are named
        // in the authority section's NS records; their addresses, if
        // included as glue, are in the additional section right alongside.
        let ns_names: Vec<Name> = raw
            .message
            .authorities
            .iter()
            .filter_map(ns_target)
            .collect();

        if ns_names.is_empty() {
            return TraceOutcome {
                hops,
                note: Some("Referral had no NS records to follow".to_owned()),
            };
        }

        let mut next_candidates: Vec<(IpAddr, Option<String>)> = raw
            .message
            .additionals
            .iter()
            .filter_map(|r| glue_address(r, &ns_names))
            .collect();

        if next_candidates.is_empty() {
            // No glue in the referral itself - fall back to resolving one
            // of the NS names the ordinary (recursive) way, same as dig
            // does when a delegation doesn't hand back glue for it.
            next_candidates = resolve_ns_glue(&ns_names, fallback_servers).await;
        }

        if next_candidates.is_empty() {
            return TraceOutcome {
                hops,
                note: Some(
                    "Could not resolve an address for the next delegation's servers".to_owned(),
                ),
            };
        }

        candidates = next_candidates;
    }
}

/// Tries each of `candidates` in turn - not in parallel, since only the
/// first one to answer matters for a trace hop - until one responds,
/// returning that server's own outcome plus how long it took. `Err` (with
/// the last candidate's own failure reason) only if every candidate timed
/// out or otherwise failed.
async fn query_first_responsive(
    candidates: &[(IpAddr, Option<String>)],
    name: &Name,
    options: QueryOptions,
) -> Result<(IpAddr, Option<String>, RawResponse, Duration), String> {
    let mut last_error = "No servers to try for this delegation".to_owned();
    for (server, label) in candidates {
        let start = Instant::now();
        match send_query_to_server(*server, name, options, TRACE_HOP_TIMEOUT).await {
            Ok(raw) => return Ok((*server, label.clone(), raw, start.elapsed())),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// Resolves one address for the first of `ns_names` that a server in
/// `fallback_servers` can answer for - used only when a referral's
/// additional section didn't include glue for any of its NS records. Only
/// the first NS name is worth resolving: one working address is enough to
/// continue the trace, and dig does the same rather than resolving every
/// sibling NS just to have spares.
async fn resolve_ns_glue(ns_names: &[Name], fallback_servers: &[IpAddr]) -> Vec<(IpAddr, Option<String>)> {
    let Some(ns_name) = ns_names.first() else {
        return Vec::new();
    };
    if fallback_servers.is_empty() {
        return Vec::new();
    }

    let options = QueryOptions {
        record_type: RecordType::A,
        use_tcp: false,
        recursion_desired: true,
        dnssec_ok: false,
        checking_disabled: false,
    };

    for &server in fallback_servers {
        if let Ok(raw) = send_query_to_server(server, ns_name, options, TRACE_HOP_TIMEOUT).await {
            let ips: Vec<(IpAddr, Option<String>)> = raw
                .message
                .answers
                .iter()
                .filter_map(|r| match r.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    _ => None,
                })
                .map(|ip| (ip, Some(ns_name.to_string())))
                .collect();
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    Vec::new()
}

/// The target name from an NS record's rdata - `None` for anything that
/// isn't actually an NS record.
fn ns_target(record: &Record) -> Option<Name> {
    match &record.data {
        RData::NS(ns) => Some(ns.0.clone()),
        _ => None,
    }
}

/// If `record` is an A/AAAA record whose owner name matches one of
/// `ns_names`, its address - i.e. this is glue for one of the servers a
/// referral just named. `None` for anything else in the additional
/// section (e.g. an OPT pseudo-record, or glue for an NS name that isn't
/// part of this delegation).
fn glue_address(record: &Record, ns_names: &[Name]) -> Option<(IpAddr, Option<String>)> {
    if !ns_names.iter().any(|n| *n == record.name) {
        return None;
    }
    let ip = match record.data {
        RData::A(a) => IpAddr::V4(a.0),
        RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
        _ => return None,
    };
    Some((ip, Some(record.name.to_string())))
}

/// Parses `input` as a DNS name for the query - almost always just
/// `Name::from_ascii`, except for PTR: typing a literal IP address
/// implements a reverse lookup (dig's `-x` convenience) rather than making
/// the user spell out `...in-addr.arpa.`/`...ip6.arpa.` by hand.
fn parse_query_name(input: &str, record_type: RecordType) -> Result<Name, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a name to query".to_owned());
    }
    if record_type == RecordType::PTR {
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(Name::from(ip));
        }
    }
    Name::from_ascii(trimmed).map_err(|e| format!("'{trimmed}' is not a valid name: {e}"))
}

/// What `send_query_to_server` hands back on success - the parsed message
/// plus the bits about the exchange itself (size, whether TCP was needed)
/// that don't live on `Message` but are still worth showing.
struct RawResponse {
    message: Message,
    message_size: usize,
    retried_over_tcp: bool,
}

/// Sends one query for `name`/`options.record_type` to exactly `server`
/// and returns the parsed response - or why there isn't one. This is the
/// one place that actually puts a packet on the wire; `query_all` calls it
/// once per selected server, `trace` calls it once per candidate at each
/// hop.
async fn send_query_to_server(
    server: IpAddr,
    name: &Name,
    options: QueryOptions,
    timeout: Duration,
) -> Result<RawResponse, String> {
    let query_msg = build_query_message(name, options);
    let wire = query_msg.to_vec().map_err(|e| format!("Failed to encode query: {e}"))?;

    let (response, message_size, retried_over_tcp) = if options.use_tcp {
        let bytes = send_tcp(server, &wire, timeout).await?;
        let msg = Message::from_vec(&bytes)
            .map_err(|e| format!("Failed to parse response from {server}: {e}"))?;
        (msg, bytes.len(), false)
    } else {
        let udp_bytes = send_udp(server, &wire, timeout).await?;
        let udp_msg = Message::from_vec(&udp_bytes)
            .map_err(|e| format!("Failed to parse response from {server}: {e}"))?;
        if udp_msg.metadata.truncation {
            let tcp_bytes = send_tcp(server, &wire, timeout).await?;
            let tcp_msg = Message::from_vec(&tcp_bytes)
                .map_err(|e| format!("Failed to parse response from {server}: {e}"))?;
            (tcp_msg, tcp_bytes.len(), true)
        } else {
            (udp_msg, udp_bytes.len(), false)
        }
    };

    if response.metadata.id != query_msg.metadata.id {
        return Err(format!(
            "Response from {server} had a mismatched transaction ID (possible stray/spoofed packet)"
        ));
    }

    Ok(RawResponse { message: response, message_size, retried_over_tcp })
}

/// Builds the query message itself: `Message::query()` already gives a
/// randomized transaction ID (via hickory-proto's own RNG, so this doesn't
/// need `rand` as a direct dependency just for this), everything else is
/// this function's own doing. EDNS is always attached (not just when
/// `+dnssec` is checked) so a UDP response can exceed the pre-EDNS 512
/// byte ceiling before this needs to fall back to TCP - see
/// `EDNS_MAX_PAYLOAD`.
fn build_query_message(name: &Name, options: QueryOptions) -> Message {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = options.recursion_desired;
    msg.metadata.checking_disabled = options.checking_disabled;
    msg.add_query(Query::query(name.clone(), options.record_type));

    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_MAX_PAYLOAD);
    edns.set_dnssec_ok(options.dnssec_ok);
    msg.set_edns(edns);

    msg
}

/// Sends `wire` to `server:53/udp` and returns whatever comes back.
async fn send_udp(server: IpAddr, wire: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let bind_addr: std::net::SocketAddr = match server {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to open a UDP socket: {e}"))?;
    socket
        .connect((server, 53))
        .await
        .map_err(|e| format!("Failed to reach {server}:53/udp: {e}"))?;
    socket
        .send(wire)
        .await
        .map_err(|e| format!("Failed to send query to {server}: {e}"))?;

    // Bigger than what we advertise via EDNS (see EDNS_MAX_PAYLOAD) - a
    // safety margin in case a server ignores that and answers larger
    // anyway, rather than this silently truncating a real answer itself.
    let mut buf = [0u8; 8192];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| format!("Timed out waiting for {server} to respond"))?
        .map_err(|e| format!("Failed reading response from {server}: {e}"))?;
    Ok(buf[..n].to_vec())
}

/// Sends `wire` to `server:53/tcp`, framed per RFC 1035 §4.2.2 (a 2-byte
/// big-endian length prefix ahead of the same wire format UDP uses), and
/// returns the response body.
async fn send_tcp(server: IpAddr, wire: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((server, 53)))
        .await
        .map_err(|_| format!("Timed out connecting to {server}:53/tcp"))?
        .map_err(|e| format!("Failed to connect to {server}:53/tcp: {e}"))?;

    let len = u16::try_from(wire.len())
        .map_err(|_| "Query too large to send over DNS-over-TCP".to_owned())?;
    let mut framed = Vec::with_capacity(2 + wire.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);

    tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .map_err(|_| format!("Timed out sending query to {server}"))?
        .map_err(|e| format!("Failed to send query to {server}: {e}"))?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| format!("Timed out waiting for {server} to respond"))?
        .map_err(|e| format!("Failed reading response from {server}: {e}"))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; response_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut response_buf))
        .await
        .map_err(|_| format!("Timed out reading response from {server}"))?
        .map_err(|e| format!("Failed reading response from {server}: {e}"))?;
    Ok(response_buf)
}

/// Turns a parsed response into the display-ready shape the UI actually
/// renders. Each record's formatting comes straight from `Record`'s own
/// `Display` impl - it already knows how to print every record type's
/// rdata correctly (an MX's priority and exchange, a TXT's quoted string,
/// an SOA's five fields, ...), so there's no per-type formatting to
/// maintain here.
fn to_dns_answer(response: &Message, message_size: usize, retried_over_tcp: bool) -> DnsAnswer {
    DnsAnswer {
        response_code: response_code_label(response.metadata.response_code),
        flags: ResponseFlags {
            authoritative: response.metadata.authoritative,
            truncated: response.metadata.truncation,
            recursion_available: response.metadata.recursion_available,
            authenticated_data: response.metadata.authentic_data,
            checking_disabled: response.metadata.checking_disabled,
        },
        message_size,
        retried_over_tcp,
        answers: response.answers.iter().map(Record::to_string).collect(),
        authorities: response.authorities.iter().map(Record::to_string).collect(),
        additionals: response.additionals.iter().map(Record::to_string).collect(),
    }
}

/// dig-style short mnemonic for a response code ("NOERROR", "NXDOMAIN",
/// ...) rather than the crate's own human-sentence `Display` ("No Error",
/// "Non-Existent Domain") - this is what the value is actually called in
/// every RFC, BIND log line, and `dig` transcript, so it's what a network
/// engineer will recognize here too.
fn response_code_label(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".to_owned(),
        ResponseCode::FormErr => "FORMERR".to_owned(),
        ResponseCode::ServFail => "SERVFAIL".to_owned(),
        ResponseCode::NXDomain => "NXDOMAIN".to_owned(),
        ResponseCode::NotImp => "NOTIMP".to_owned(),
        ResponseCode::Refused => "REFUSED".to_owned(),
        ResponseCode::YXDomain => "YXDOMAIN".to_owned(),
        ResponseCode::YXRRSet => "YXRRSET".to_owned(),
        ResponseCode::NXRRSet => "NXRRSET".to_owned(),
        ResponseCode::NotAuth => "NOTAUTH".to_owned(),
        ResponseCode::NotZone => "NOTZONE".to_owned(),
        ResponseCode::BADVERS => "BADVERS".to_owned(),
        ResponseCode::BADSIG => "BADSIG".to_owned(),
        ResponseCode::BADKEY => "BADKEY".to_owned(),
        ResponseCode::BADTIME => "BADTIME".to_owned(),
        ResponseCode::BADMODE => "BADMODE".to_owned(),
        ResponseCode::BADNAME => "BADNAME".to_owned(),
        ResponseCode::BADALG => "BADALG".to_owned(),
        ResponseCode::BADTRUNC => "BADTRUNC".to_owned(),
        ResponseCode::BADCOOKIE => "BADCOOKIE".to_owned(),
        ResponseCode::Unknown(code) => format!("UNKNOWN({code})"),
    }
}