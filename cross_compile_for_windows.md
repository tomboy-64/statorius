## Building for Windows (Cross-Compilation)

Npcap (`wpcap.dll`) is loaded at runtime (see `src/pcap.rs`), so no Npcap SDK is needed to build, and the executable starts without Npcap installed. Without it only the L2 features (L2 Ping, DHCP) are unavailable; they need Npcap installed on the machine running Statorius.

The `x86_64-pc-windows-gnu` target links with `x86_64-w64-mingw32-gcc` (set in `.cargo/config.toml`).

**Build command (Linux to Windows):**
```bash
cargo build --target x86_64-pc-windows-gnu --release
```
