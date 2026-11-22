//! IPv6 zones ("scope ids") for ping targets.
//!
//! A link-local address (`fe80::/10`) is only unique on one link, so using it
//! needs an interface: `fe80::1%eth0` (a name) or `fe80::1%3` (an index,
//! the usual spelling on Windows). The same holds for the link- and
//! interface-local multicast scopes (`ff01::`, `ff02::`). Rust's `IpAddr`
//! has no zone, so targets carry the interface index next to the address
//! (`PingKey::scope`, `0` = none) and the socket backends put it into the
//! socket address.

use std::net::IpAddr;

/// Addresses that only mean something together with an interface:
/// link-local unicast and the interface-/link-local multicast scopes.
pub fn needs_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local()
                || (v6.is_multicast() && matches!(v6.segments()[0] & 0x000f, 1 | 2))
        }
        IpAddr::V4(_) => false,
    }
}

/// Interface index for a zone given as a number or as an interface name
/// (the system name, or on Windows also the friendly name).
pub fn parse_zone(zone: &str) -> Result<u32, String> {
    let zone = zone.trim();
    if zone.is_empty() {
        return Err("no interface after '%'".to_owned());
    }
    if let Ok(index) = zone.parse::<u32>() {
        return if index == 0 {
            Err("interface index 0 is not a valid zone".to_owned())
        } else {
            Ok(index)
        };
    }
    default_net::get_interfaces()
        .into_iter()
        .find(|i| i.name == zone || i.friendly_name.as_deref() == Some(zone))
        .map(|i| i.index)
        .ok_or_else(|| format!("unknown interface '{zone}'"))
}

/// What to print after the `%` for an interface index: the friendly name
/// where there is one, else the system name, else the number itself.
pub fn zone_name(index: u32) -> String {
    default_net::get_interfaces()
        .into_iter()
        .find(|i| i.index == index)
        .map(|i| i.friendly_name.unwrap_or(i.name))
        .unwrap_or_else(|| index.to_string())
}

/// `10.0.0.1`, or `fe80::1%eth0` for a scoped address.
pub fn format_target(ip: IpAddr, scope: u32) -> String {
    if scope == 0 {
        ip.to_string()
    } else {
        format!("{ip}%{}", zone_name(scope))
    }
}

/// Parses one literal target: `ip` or `ip%zone`.
///
/// * `None` - not an IP literal at all (a hostname or CIDR range);
/// * `Some(Ok((ip, scope)))` - `scope` is `0` unless a zone was given;
/// * `Some(Err(reason))` - it is an address, but not a usable one: a zone on
///   an IPv4 or non-link-local address, an unknown interface, or a
///   link-local address without the interface it needs.
pub fn parse_literal(text: &str) -> Option<Result<(IpAddr, u32), String>> {
    let text = text.trim();
    let (addr_text, zone) = match text.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (text, None),
    };
    let ip: IpAddr = match addr_text.parse() {
        Ok(ip) => ip,
        Err(_) if zone.is_some() => {
            return Some(Err(format!("'{addr_text}' is not an IPv6 address")));
        }
        Err(_) => return None,
    };

    match zone {
        None if needs_scope(ip) => Some(Err(format!(
            "{ip} is link-local and needs an interface, e.g. {ip}%eth0 (or {ip}%<index> on Windows)"
        ))),
        None => Some(Ok((ip, 0))),
        Some(_) if ip.is_ipv4() => Some(Err("a zone (%...) only applies to IPv6 addresses".to_owned())),
        Some(_) if !needs_scope(ip) => Some(Err(format!(
            "a zone only applies to link-local addresses (fe80::/10, ff01::, ff02::), not {ip}"
        ))),
        Some(zone) => Some(parse_zone(zone).map(|scope| (ip, scope))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_addresses_have_no_scope() {
        assert_eq!(parse_literal("10.0.0.1"), Some(Ok((ip("10.0.0.1"), 0))));
        assert_eq!(parse_literal(" 2001:db8::1 "), Some(Ok((ip("2001:db8::1"), 0))));
    }

    #[test]
    fn hostnames_and_ranges_are_not_literals() {
        assert_eq!(parse_literal("example.com"), None);
        assert_eq!(parse_literal("10.0.0.0/24"), None);
        assert_eq!(parse_literal(""), None);
    }

    #[test]
    fn link_local_takes_a_numeric_zone() {
        assert_eq!(parse_literal("fe80::1%3"), Some(Ok((ip("fe80::1"), 3))));
        assert_eq!(parse_literal("ff02::1%12"), Some(Ok((ip("ff02::1"), 12))));
    }

    #[test]
    fn link_local_without_zone_is_explained() {
        let err = parse_literal("fe80::1").unwrap().unwrap_err();
        assert!(err.contains("needs an interface"), "{err}");
        assert!(parse_literal("ff02::1").unwrap().is_err());
        // Other multicast scopes and global addresses need nothing.
        assert!(parse_literal("ff0e::1").unwrap().is_ok());
    }

    #[test]
    fn zones_are_rejected_where_they_make_no_sense() {
        assert!(parse_literal("10.0.0.1%3").unwrap().is_err());
        assert!(parse_literal("2001:db8::1%3").unwrap().is_err());
        assert!(parse_literal("fe80::1%0").unwrap().is_err());
        assert!(parse_literal("fe80::1%").unwrap().is_err());
        assert!(parse_literal("fe80::1%no-such-interface-zz9").unwrap().is_err());
        assert!(parse_literal("host%3").unwrap().is_err());
    }

    #[test]
    fn scoped_addresses_print_with_their_zone() {
        assert_eq!(format_target(ip("10.0.0.1"), 0), "10.0.0.1");
        let text = format_target(ip("fe80::1"), 3);
        assert!(text.starts_with("fe80::1%"), "{text}");
    }

    /// Whatever an interface prints as must parse back to the same index.
    #[test]
    fn zone_names_round_trip() {
        for iface in default_net::get_interfaces() {
            let name = zone_name(iface.index);
            // Two interfaces can share a friendly name; only check unique ones.
            let same = default_net::get_interfaces()
                .iter()
                .filter(|i| i.friendly_name.clone().unwrap_or_else(|| i.name.clone()) == name)
                .count();
            if same == 1 && name.parse::<u32>().is_err() {
                assert_eq!(parse_zone(&name), Ok(iface.index), "{name}");
            }
        }
    }
}
