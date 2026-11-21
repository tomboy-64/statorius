# Statorius - a swiss-army-knife for network probing

A desktop tool (Rust, egui) for probing and inspecting networks. Windows and Linux.

## Features

**Ping**
- ICMP echo (configurable payload size), TCP SYN-style connect probes and UDP null probes, per target and port. One target can run an ICMP, a TCP and a UDP pinger side by side; the list shows protocol and port.
- Every failure shows its reason: timeout, TCP RST, ICMP unreachable / admin-prohibited / TTL exceeded (with the sending router), UDP port unreachable. A UDP probe that gets no answer is shown as "no reply" (open or filtered), not as a failure.
- Targets can be literal IPs, CIDR ranges (swept, up to 512 hosts) or hostnames (resolved once; TCP/UDP probe a single address, ICMP every resolved address). Optional ping count; target lists save to and load from `.ips` files.

**L2 Ping** (needs Npcap on Windows, libpcap on Linux, plus elevation for the helper process)
- ICMP echo and ARP/NDP pings sent as hand-built Ethernet frames, with optional 802.1Q VLAN tag and selectable source IP.
- Duplicate-address check for the chosen source IP (RFC 5227 ARP probe, IPv6 DAD).

**DHCP** - passive capture of DHCP exchanges (needs L2 mode) with decoded options and per-field explanations.

**DNS** - system DNS server discovery with per-server checks, manual server lists (`.dns` files) and a dig-like query panel (record type, TCP/UDP, RD/CD/DO bits, trace).

**Interfaces** - network adapters with addresses, gateways and flags.

**About** - version, license, and the graphics backend in use (Vulkan, then OpenGL, then others) with a switch; `WGPU_BACKEND` overrides it.

## Planned features

- ICMP Timestamp (type 13), Address Mask (type 17), traceroute
- True half-open TCP SYN probes, TCP ACK probes
- IP protocol ping
- TCP idle/zombie ping

## Building

```bash
git lfs pull          # ico/*.png are tracked with Git LFS and read by build.rs
cargo build --release
```

Npcap (`wpcap.dll`) and libpcap are loaded at runtime (see `src/pcap.rs`), so neither a Npcap SDK nor libpcap development files are needed to build, and the executable starts without them. Without the library only the L2 features (L2 Ping, DHCP) are unavailable.

Tests: `cargo test` (CI runs them on Linux and Windows; tests needing raw-socket privileges skip themselves without them).

Debian/Ubuntu package (version, description and recommended packages come from `[package.metadata.deb]` in `Cargo.toml`):

```bash
cargo install cargo-deb
cargo build --release
cargo deb --no-build   # -> target/debian/statorius_<version>-1_amd64.deb
```

Cross-compiling for Windows from Linux: see [cross_compile_for_windows.md](cross_compile_for_windows.md).

## License

AGPL-3.0-only, see [LICENSE](LICENSE).