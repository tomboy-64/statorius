//! System DNS server discovery, plus name resolution against a
//! user-chosen subset of those servers.
//!
//! Three independent things live here, mirroring `dhcp_state`/`l2_manager`'s
//! shared-state shape:
//! - a background task that re-lists the OS's configured DNS servers every
//!   `REFRESH_INTERVAL` and publishes them via `SharedDnsServers` (read by
//!   the "DNS" tab every frame - no channel involved, same as
//!   `SharedL2Status`);
//! - an on-demand resolver: the Ping tab sends a `DnsCommand::Resolve` job
//!   over this module's command channel, this task resolves it against
//!   whichever servers the user checked, and replies on the included
//!   oneshot channel;
//! - the DNS tab's own Query panel: `DnsCommand::Query` (a normal query,
//!   fanned out to every checked server) and `DnsCommand::Trace` (dig's
//!   `+trace`) - both spawned rather than awaited inline here, since
//!   unlike a single `Resolve`, either can take several seconds (several
//!   servers/hops, each with its own timeout) and shouldn't stall the 10s
//!   refresh tick or a concurrent request while they run. See
//!   `dns_query` for how they're actually built and sent.
//!
//! Listing the system's servers and doing `Resolve` lookups both go
//! through `hickory_resolver`: `system_conf::read_system_conf()` already
//! knows how to read `/etc/resolv.conf` on Linux and the registry on
//! Windows, and the resolver itself already follows CNAME chains as part
//! of a normal A/AAAA lookup - neither needs bespoke platform code here.
//! DNSSEC is never requested or validated for a `Resolve` (that's
//! `ResolverOpts`'s default, and this module never turns it on) - `Query`
//! and `Trace` are a separate, lower-level path specifically so DNSSEC
//! (among other things) can be requested and shown on demand instead; see
//! `dns_query`'s module docs for why full validation isn't part of that.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::TokioResolver;
use tokio::sync::{mpsc, oneshot};

use super::dns_query::{self, QueryOptions, QueryOutcome, TraceOutcome};

/// How often the background task re-lists the OS's configured DNS servers.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// One request the UI can send to `dns_worker`.
pub enum DnsCommand {
    /// Resolve `name` against exactly `servers` (whichever the user
    /// checked in the DNS tab) - both A and AAAA, in parallel, merging
    /// whatever succeeds. Used by the Ping tab.
    Resolve {
        name: String,
        servers: Vec<IpAddr>,
        respond_to: oneshot::Sender<Result<Vec<IpAddr>, String>>,
    },

    /// One dig-like query for `name`/`options.record_type`, sent to every
    /// one of `servers` in parallel. Used by the DNS tab's Query panel
    /// when `+trace` isn't checked.
    Query {
        name: String,
        servers: Vec<IpAddr>,
        options: QueryOptions,
        respond_to: oneshot::Sender<Vec<QueryOutcome>>,
    },

    /// `+trace`: walks the delegation chain by hand, starting at the root
    /// hints - see `dns_query::trace` for why that's independent of
    /// whichever servers are checked on the DNS tab. `fallback_servers` is
    /// only used if a referral is missing glue and an NS name needs an
    /// ordinary recursive lookup to get an address.
    Trace {
        name: String,
        record_type: RecordType,
        dnssec_ok: bool,
        fallback_servers: Vec<IpAddr>,
        respond_to: oneshot::Sender<TraceOutcome>,
    },
}

/// Read-mostly snapshot of the OS's currently-configured DNS servers,
/// refreshed by `dns_worker` every `REFRESH_INTERVAL`. Same shape as
/// `SharedL2Status`: a plain `Arc<Mutex<..>>` the UI reads fresh every
/// frame; nothing here needs a channel, since it's just "the current
/// value".
#[derive(Clone)]
pub struct SharedDnsServers(Arc<Mutex<Vec<IpAddr>>>);

impl SharedDnsServers {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(list_system_dns_servers())))
    }

    /// Every DNS server the OS currently has configured, as of the last
    /// `REFRESH_INTERVAL` tick.
    pub fn get(&self) -> Vec<IpAddr> {
        self.0.lock().unwrap().clone()
    }

    fn set(&self, servers: Vec<IpAddr>) {
        *self.0.lock().unwrap() = servers;
    }
}

impl Default for SharedDnsServers {
    fn default() -> Self {
        Self::new()
    }
}

/// Every DNS server address the OS currently has configured (e.g.
/// `/etc/resolv.conf` on Linux, the registry on Windows) - deduplicated,
/// order preserved. Cheap enough to call on every refresh tick: this only
/// re-reads local configuration, no network I/O. An unreadable/unparsable
/// configuration is treated as "no servers" rather than an error the UI
/// has to do anything special with - the DNS tab just shows an empty
/// list, and resolution then fails the same way it would with none
/// selected.
fn list_system_dns_servers() -> Vec<IpAddr> {
    let Ok((config, _opts)) = read_system_conf() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    config
        .name_servers()
        .iter()
        .map(|ns| ns.ip)
        .filter(|ip| seen.insert(*ip))
        .collect()
}

/// Background task: keeps `shared` refreshed every `REFRESH_INTERVAL`, and
/// serves `DnsCommand::Resolve` jobs as they arrive. Spawned once at
/// startup, same as `l2_manager_task` / `l2_pinger_worker`.
pub async fn dns_worker(mut rx: mpsc::Receiver<DnsCommand>, shared: SharedDnsServers) {
    let mut tick = tokio::time::interval(REFRESH_INTERVAL);
    // `SharedDnsServers::new()` already did the first read - skip the
    // immediate first tick so the next refresh actually lands
    // `REFRESH_INTERVAL` later, not right away.
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                shared.set(list_system_dns_servers());
            }
            command = rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    DnsCommand::Resolve { name, servers, respond_to } => {
                        let outcome = resolve(&name, &servers).await;
                        let _ = respond_to.send(outcome);
                    }
                    DnsCommand::Query { name, servers, options, respond_to } => {
                        // Spawned - see the module docs above for why.
                        tokio::spawn(async move {
                            let outcomes = dns_query::query_all(&name, &servers, options).await;
                            let _ = respond_to.send(outcomes);
                        });
                    }
                    DnsCommand::Trace { name, record_type, dnssec_ok, fallback_servers, respond_to } => {
                        tokio::spawn(async move {
                            let outcome =
                                dns_query::trace(&name, record_type, dnssec_ok, &fallback_servers).await;
                            let _ = respond_to.send(outcome);
                        });
                    }
                }
            }
        }
    }
}

/// Resolves `name` against exactly `servers`: builds a one-off resolver
/// configured with only those nameservers (so "use those servers" means
/// literally that - nothing else is ever consulted), queries A and AAAA in
/// parallel, and returns the union of whichever succeed. CNAME chains are
/// followed automatically by `hickory_resolver` itself as part of that
/// lookup - not something this function needs to do by hand. Only errors
/// if both record types fail, or if the name resolves to no addresses at
/// all.
async fn resolve(name: &str, servers: &[IpAddr]) -> Result<Vec<IpAddr>, String> {
    if servers.is_empty() {
        return Err("No DNS servers selected".to_owned());
    }

    let name_servers: Vec<NameServerConfig> =
        servers.iter().map(|ip| NameServerConfig::udp_and_tcp(*ip)).collect();
    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);

    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    let resolver = builder
        .build()
        .map_err(|e| format!("Failed to set up the resolver: {e}"))?;

    let lookup = resolver
        .lookup_ip(name)
        .await
        .map_err(|e| format!("Could not resolve '{name}': {e}"))?;

    let mut seen = HashSet::new();
    let addrs: Vec<IpAddr> = lookup.iter().filter(|ip| seen.insert(*ip)).collect();
    if addrs.is_empty() {
        Err(format!("'{name}' resolved to no A/AAAA records"))
    } else {
        Ok(addrs)
    }
}