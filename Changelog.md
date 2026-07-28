# Changelog

All notable changes to this project are documented in this file.

***Note***: Layer 2 Pings are still broken. Do not try to use that feature.

- [todo] remove borders around DHCP messages (ugly)
- [todo] next: implement domain name resolution attempt on ips for ping
- [todo] next: implement storing/loading sets of ips to be pinged
- prettified DHCP output by removing blocks around Xiaddr entries
- added description tooltips for all Options

## [0.4.1]

### Fixed
- **No more console window on Windows.** The binary is now built as the
  "windows" GUI subsystem in release builds, so neither the main app nor
  the elevated `--l2-helper` process (the same binary, re-exec'd) pops up
  a console anymore - previously that window had to stay open for as long
  as L2 mode was active, and closing it silently killed the L2 session.
  Debug builds are unaffected, so `cargo run` still shows stdout/stderr.
- The elevated helper is launched with `SW_HIDE` instead of
  `SW_SHOWNORMAL`, and the non-elevated helper spawn now also sets
  `CREATE_NO_WINDOW` - both redundant with the subsystem fix above, but
  kept as a second layer of defense.

### Internal
- No functional/protocol changes; this is a Windows-packaging-only patch
  release on top of 0.4.0.

## [0.4.0]

### Added
- **"DHCP" tab**, gated behind L2 mode the same way "L2 Ping" is: a
  passive log of every DHCP/BOOTP exchange seen on the wire, built on the
  existing L2 capture framework. A new, independent capture handle in the
  L2 helper (alongside the ping engine's) listens for UDP ports 67/68
  continuously while L2 mode is active - no user action needed beyond
  turning L2 mode on.
  - Exchanges are grouped by transaction id (`xid`) and listed
    chronologically, oldest exchange first, each as a collapsing header
    showing the `xid` and the timestamp of that exchange's first message.
  - Every message within an exchange (DISCOVER/OFFER/REQUEST/ACK/NAK/...,
    or plain BOOTP) shows its type, capture time, client MAC, VLAN, and -
    highlighted individually with a hover explanation of what each one
    means - whichever of `ciaddr`/`yiaddr`/`siaddr`/`giaddr` are actually
    set.
  - Options are fully decoded by name (RFC 2131/2132 and later RFCs,
    IANA-registered codes) via a bundled, easily extensible lookup table
    (`net/dhcp_options.json`); list-valued options (address lists, the
    parameter request list) render one entry per line, and any single
    value still too long for the column is word-wrapped.

### Internal
- `net::dhcp`: BOOTP/DHCP parsing (including Option 52 overload and RFC
  3396 option concatenation) and option decoding, driven by the bundled,
  compile-time-embedded lookup table rather than hardcoded option tables.
- `net::dhcp_sniffer`: the L2 helper's passive capture loop, opened
  independently of the ping engine's capture handle so continuous DHCP
  sniffing never competes with Ping/CheckDuplicate jobs for the same
  socket.
- `net::dhcp_state`: GUI-side shared state grouping captured messages by
  `xid`, mirroring `l2_pinger`'s shared-state pattern.
- `net::l2_ipc`: new unsolicited `DhcpEvent` message, streamed from the
  helper to the GUI as messages are captured - the first message in this
  protocol with no request/response pairing.
- `net::l2_frame`: added UDP header parsing (`parse_udp`), the last piece
  needed between IPv4 and the DHCP payload.

## [0.3.5]

### Added
- **"Since" column** on both the "Ping" and "L2 Ping" tabs, showing a
  second-precision timer ("12s ago", "3m 45s ago", "1h 12m ago") for how
  long it's been since each target's last result was received.
- **"About" tab** with copyright and GNU AGPL-3.0 license information,
  including a link to the full license text.
- **Prettified interface speeds** on the "Interfaces" tab: TX/RX speed is
  now rendered as e.g. "1Gbps" instead of a raw bit count like
  "1000000000bps", scaling from bps up to Pbps.

### Changed
- The "L2 mode" activation checkbox has moved out of the "L2 Ping" tab body
  and into the tab row itself, right-aligned next to the tab labels.
- The "L2 Ping" tab is now only selectable once L2 mode is actually
  *active* (rather than merely possible on this system). If L2 mode is
  deactivated (or fails) while that tab is open, the app falls back to the
  "Ping" tab automatically.

### Internal
- Split the former single `src/app.rs` (~1,100 lines) into a `src/app/`
  module, organized by tab: `mod.rs` (app state, construction, tab bar),
  `ping_tab.rs`, `l2_tab.rs`, `interfaces_tab.rs`, `about_tab.rs`, and a
  shared `widgets.rs` for the result/average/since indicators used by both
  the Ping and L2 Ping tabs. No behavioral changes from this split.