# Changelog

All notable changes to this project are documented in this file.

***Note***: Layer 2 Pings are still broken. Do not try to use that feature.

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