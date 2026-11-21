# Changelog

## 0.8.2

- `.deb` package for Debian/Ubuntu, built by the release workflow with `cargo-deb` from `[package.metadata.deb]` in `Cargo.toml`. libpcap and pkexec are recommended packages, since only the L2 features need them. Includes the desktop entry and icons.
- The release workflow no longer installs the Npcap SDK or libpcap-dev.
- `windows-sys` is a Windows-only dependency (no unused-dependency warning on Linux).
- The release workflow runs the unit tests on Linux and Windows for every push; a release build requires them to pass. On Linux the pcap tests also run once with raw-socket privileges.
- `arch/PKGBUILD` is at 0.8.2.

## 0.8.0

### Ping
- ICMP, TCP and UDP pingers coexist per target: a pinger is identified by address, protocol and port (ICMP has no port). Starting an identical combination restarts that pinger instead of replacing the others.
- The list has a Protocol column (`ICMP`, `TCP/443`, `UDP/53`); hovering it shows what is sent on the wire.
- Explicit failure reasons for all three protocols: TCP RST ("refused"), ICMP destination unreachable / admin-prohibited / TTL exceeded and other ICMP errors, UDP port unreachable, plus timeouts and local errors. Details (including the router that sent an ICMP error) are in the tooltip.
- ICMP error replies are no longer reported as successful echo replies.
- UDP probes without any answer show as "no reply" (open or filtered) in amber instead of red; the average badge stays neutral if every attempt was silent.
- TCP probes read the SYN's answer (SYN/ACK, RST, ICMP) and close the connection with a RST.
- A TCP/UDP ping against a hostname starts one pinger (first IPv4 address) instead of one per resolved address.
- Saved `.ips` lists contain each address once.

### Build and packaging
- Npcap/libpcap are loaded at runtime instead of being linked: the executable starts without Npcap, only the L2 features need it. The `pcap` crate is replaced by `src/pcap.rs`; the Npcap SDK is no longer needed to build.
- Unit tests for the TCP/UDP backends, pinger identity and the pcap binding.
- Documentation rewritten to describe the current behavior.
- `arch/PKGBUILD` lists libpcap as an optional dependency.