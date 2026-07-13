# Statorius - a swiss-army-knife for network probing

## Current features

Right now it's simply a Pinger.

## Planned features

- Various ping variants
  - ICMP Type 13, Type 17, Traceroute 
  - ARPing
  - TCP-Connect, TCP-Syn, TCP-Ack
  - UDP Null
  - IP Protocol Ping
  - TCP Idle/Zombie Ping
- Pings in separate VLANs
- DHCP Monitoring
- Duplicate IP alerts

## Building for Windows (Cross-Compilation)

This project relies on the `pcap` crate, which requires the Npcap SDK when targeting Windows. Due to licensing, the SDK is not included in this repository.

1. Download the **Npcap SDK** from `https://npcap.com/#download`.
2. Extract the archive to a local directory.
3. Set the `LIBPCAP_LIB_DIR` environment variable to point to the `Lib/x64` directory inside the extracted SDK.

**Example build command (Linux to Windows):**
```bash
export LIBPCAP_LIB_DIR=/path/to/your/npcap-sdk/Lib/x64
cargo build --target x86_64-pc-windows-gnu --release