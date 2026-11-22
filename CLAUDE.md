# Statorius - overview for working on this repo

Desktop network-probing tool (Rust, egui/eframe with the wgpu renderer, tokio). Windows and Linux. User-facing features are in `README.md`, release history in `CHANGELOG.md`.

## Commands

```bash
cargo build --release
cargo test                      # unit tests; tests needing raw sockets skip themselves without privileges
cargo deb --no-build            # .deb from [package.metadata.deb] in Cargo.toml (needs cargo-deb + a release build)
cargo build --target x86_64-pc-windows-gnu --release   # see cross_compile_for_windows.md
```

- Needs a recent stable Rust: edition 2024, and `Cargo.toml` uses multi-line inline tables (cargo 1.91 rejects it, 1.97 works).
- `ico/*.png` are Git LFS files and `build.rs` reads `ico/statorius-master.png`. Without `git lfs pull` (LFS pointer files) the build script panics; in a scratch environment replace the master PNG with any 750x750 PNG.
- CI: `.github/workflows/release.yml` checks version consistency, runs `cargo test` on Linux and Windows, and on a `v*` tag builds the MSI (WiX, `wix/`) and the `.deb`. `arch/PKGBUILD` is for Arch.

## Process model

One binary, two modes. The GUI is unprivileged. `statorius --l2-helper <endpoint>` (see `main.rs`, `net/l2_helper.rs`) is the same executable re-launched elevated (UAC on Windows, `pkexec` on Linux); it is the only code that touches raw frames. GUI and helper talk over a local socket/named pipe with newline-delimited JSON (`net/l2_ipc.rs`).

Async pattern used everywhere: the UI sends commands over an `mpsc` channel to a tokio task; the task writes results into a shared state (`Arc<Mutex<..>>`); the UI reads a snapshot every frame. Examples: `state::SharedState` + `net::ping_worker`, `net::l2_manager`, `net::dns`, `net::dhcp_state`.

## Module map

- `main.rs` - wires channels/tasks, window options, graphics setup, `run_native`; on failure hands over to `startup_failure`.
- `app/` - UI. `mod.rs` (app struct, tab bar) and one file per tab: `ping_tab`, `l2_tab`, `dhcp_tab`, `dns_tab`, `interfaces_tab`, `about_tab`; `widgets.rs` shared indicators.
- `state.rs` - ping state: a pinger is identified by `PingKey` (address, interface scope for link-local IPv6, protocol, port; ICMP port 0), so ICMP/TCP/UDP pingers per address coexist. `PingResult`: `Success`, `Timeout`, `Silent` (UDP no reply = open or filtered, not a failure), `Rejected{short,detail}` (RST, ICMP unreachable, ...), `Error`.
- `net/backend.rs` - `PingBackend` trait with ICMP (surge-ping; ICMP error replies are classified, not counted as success), TCP (kernel `connect()`, zero linger, so RST on close) and UDP null-probe backends. `net/mod.rs` - the ping worker and per-pinger loops.
- `net/l2*.rs` - L2 mode: `l2.rs` readiness probe, `l2_manager.rs` (GUI side), `l2_helper.rs`, `l2_engine.rs` (job engine: ARP/NDP ping, ICMP echo, ICMP timestamp (IPv4 only), duplicate check), `l2_frame.rs` (Ethernet/VLAN/IP/ICMP/UDP build+parse), `l2_pinger.rs` (L2 target list), `windows_elevate.rs`.
- `net/dhcp*.rs` - passive DHCP sniffer (runs in the helper, captures DHCPv4 and DHCPv6), decoders (`dhcp.rs` for v4 and the shared `DhcpMessageWire`, `dhcpv6.rs` for v6 incl. relay unwrapping), state grouped by `(version, xid)`; option names/formats come from `dhcp_options.json` and `dhcpv6_options.json` (embedded).
- `net/scope.rs` - IPv6 zones for link-local ping targets (`fe80::1%eth0`): parsing/printing; the interface index travels in `PingKey::scope`, `PingRequest::scope` and into the socket address (`socket_addr` in `net/backend.rs`, `Pinger::scope_id` for ICMP).
- `net/dns.rs` (system DNS discovery, resolution), `net/dns_query.rs` (dig-like queries, hickory-resolver).
- `pcap.rs` - own minimal libpcap/Npcap binding, loaded at runtime with `libloading` (no `pcap` crate, no SDK, no link-time dependency). The Npcap driver itself must be installed for L2 and DHCP.
- `graphics.rs` - backend choice (Auto/Vulkan/OpenGL/DX12) persisted in `<config dir>/graphics-backend`, adapter selector, About-tab panel (greys out unavailable backends, names the missing library), automatic relaunch on the next backend (`STATORIUS_FALLBACK` env marker), library probes. `startup_failure.rs` - log + dialog + stderr when the window can't be created.

## Runtime-loaded libraries

wgpu/winit/pcap open their libraries at runtime, so package dependency detection (`$auto`) can't see them. The `.deb` metadata and `arch/PKGBUILD` list them by hand: X11 libs + xkbcommon-x11 are mandatory (checked by hiding them: startup fails), Vulkan or EGL one of two, Wayland/libpcap/pkexec optional. Keep these in sync when a dependency changes.

## Conventions

- Comments and docs describe the current behavior, never what changed or used to be. Changes are recorded only in `CHANGELOG.md` (one section per version).
- `Cargo.toml` `version` is authoritative; `.githooks/pre-commit` syncs `arch/PKGBUILD` (enable with `git config core.hooksPath .githooks`). The deb takes its version from `Cargo.toml`.
- Prefer std and existing dependencies over new crates.
- Windows-only code is `cfg(windows)`-gated and cannot be compiled on Linux without the Windows std; check such code by reading it against the `windows-sys` API.
- Release builds on Windows have no console (`windows_subsystem`); anything that must reach the user goes through the UI or `startup_failure`.
- Handing results back: only the changed files, or a complete archive named `*.tar.gz` (never `_tar.gz`).

## Testing notes

- Unit tests cover the ping backends (loopback sockets), pinger identity, the pcap binding (loopback capture/injection, skipped without privileges), graphics selection/fallback logic and the startup report.
- GUI behavior was checked headless: Xvfb plus Mesa software rendering, with single libraries hidden to see which are mandatory.
- Not verified on real hardware: the Windows paths (Npcap loading, `MessageBoxW`, DX12), a Wayland session, and the fallback relaunch after a late graphics failure. The development sandbox kernel has no IPv6, so IPv6 behavior (scoped link-local ping, DHCPv6 on a live link) is covered by unit tests and a loopback test that skips itself without `::1`, not by runs.
- L2 mode and DHCP capture pick the interface by its IPv4 address (`net/l2_engine.rs` `open_capture`), so an IPv6-only interface can't use them.
- Platform quirks the tests account for: on Windows a closed loopback TCP port may end as a timeout instead of "refused", and UDP port-unreachable surfaces as `ConnectionReset`.
