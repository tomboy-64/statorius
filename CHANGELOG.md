# Changelog

## 0.8.3

- Link-local IPv6 targets (`fe80::/10`, and the `ff01::`/`ff02::` multicast scopes) work in the Ping tab for ICMP, TCP and UDP: the interface is part of the target, `fe80::1%eth0` by name or `fe80::1%3` by index (the usual spelling on Windows). A link-local address without an interface is rejected with an explanation instead of failing in the socket layer, and a zone on any other address is rejected as well. The same address on two interfaces is two pingers; saved `.ips` lists keep the `%interface`.
- DHCP tab: DHCPv6 (UDP 546/547) is captured next to DHCPv4. SOLICIT/ADVERTISE/REQUEST/REPLY and the other message types are decoded, relay messages are unwrapped, and the client and server DUIDs and every address and prefix from IA_NA/IA_TA/IA_PD are shown. About 45 options have names, explanations and value decoders (`dhcpv6_options.json`); others show as hex. DHCPv4 and DHCPv6 exchanges are listed separately and labelled.
- Interfaces tab: an interface with an IPv4 *or* an IPv6 address opens automatically on first display (previously only one with both did).
- Tests for zone parsing, scoped pinger identity, the DHCPv6 decoder, the sniffer's frame decoding (including a real IPv6 loopback datagram through the capture filter) and DHCP transaction grouping. CI runs the sniffer tests with raw-socket privileges as well.
- `arch/PKGBUILD` is at 0.8.3.

## 0.8.2

- `.deb` package for Debian/Ubuntu, built by the release workflow with `cargo-deb` from `[package.metadata.deb]` in `Cargo.toml`. libpcap and pkexec are recommended packages, since only the L2 features need them. Includes the desktop entry and icons.
- The release workflow no longer installs the Npcap SDK or libpcap-dev.
- `windows-sys` is a Windows-only dependency (no unused-dependency warning on Linux).
- The release workflow runs the unit tests on Linux and Windows for every push; a release build requires them to pass. On Linux the pcap tests also run once with raw-socket privileges.
- The About tab scrolls as a whole.
- Graphics backends the machine cannot offer are greyed out in the About tab, with the missing library (Vulkan/EGL loader) or driver and the package to install.
- If the window cannot be created after a backend was selected (broken driver), the app relaunches on the next backend (Vulkan, OpenGL, DirectX 12); `WGPU_BACKEND` set by the user is never overridden. The About tab notes an automatic fallback.
- If the window cannot be created at all, the error is shown in a dialog (`MessageBoxW` on Windows, `zenity`/`kdialog` on Linux), printed to stderr and written to `startup-error.log` in the config directory, with the libraries to install. Release builds on Windows previously exited without any message.
- Tests for backend selection, saving the setting, the fallback decision, library probing and the error report.
- Dependencies for the GUI libraries that are loaded at runtime (checked by starting the app under Xvfb with single libraries removed): the `.deb` depends on the X11 and xkbcommon-x11 libraries plus Vulkan or EGL, and recommends the Wayland libraries, Mesa drivers, libpcap and pkexec; `arch/PKGBUILD` depends on the X11 libraries and lists the rest (and polkit) as optional.
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
