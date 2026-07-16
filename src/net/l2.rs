//! Layer-2 capability probing + readiness classification.
//!
//! Future features (raw Ethernet frame construction/injection) will need
//! Npcap on Windows and a raw/promiscuous-capable socket on Linux. This
//! module answers one question up front, without ever trying to acquire
//! privileges itself: *can this process already do that, as launched, and if
//! not, would elevation plausibly fix it?*

use pcap::{Capture, Device};

/// Three-state readiness - "impossible outright" and "possible but needs
/// elevation" need very different UI treatment (permanently disabled vs.
/// clickable-with-a-prompt), so a plain bool isn't enough anymore.
#[derive(Debug, Clone)]
pub enum L2Readiness {
    /// Already works with the privileges we were launched with - activating
    /// L2 mode can spawn the helper directly, no prompt needed.
    Ready { detail: String },
    /// pcap/Npcap is present and a loopback interface exists, but opening it
    /// in promiscuous mode failed - overwhelmingly likely a privilege issue,
    /// so activating L2 mode will try to launch the helper elevated.
    NeedsElevation { detail: String },
    /// pcap/Npcap itself isn't usable here at all (not installed, no
    /// loopback interface found, ...) - no amount of elevation would help,
    /// so the checkbox stays permanently disabled.
    Unavailable { detail: String },
}

/// One-time, unprivileged startup probe. Never attempts to acquire
/// privileges - it only classifies what's already true.
pub fn probe_l2_readiness() -> L2Readiness {
    match find_loopback_and_probe() {
        FindResult::NoDevices(e) => L2Readiness::Unavailable {
            detail: format!("Could not enumerate network devices: {e}"),
        },
        FindResult::NoLoopback => L2Readiness::Unavailable {
            detail: "No loopback interface found to probe against.".to_owned(),
        },
        FindResult::Probed {
            name,
            result: Ok(()),
        } => L2Readiness::Ready {
            detail: format!("Verified: opened '{name}' in promiscuous mode."),
        },
        FindResult::Probed {
            name,
            result: Err(e),
        } => L2Readiness::NeedsElevation {
            detail: format!(
                "Opening '{name}' in promiscuous mode failed: {e}. {}",
                platform_requirements()
            ),
        },
    }
}

/// Re-run just the promiscuous-open check, without the "is this fixable by
/// elevation" classification. Used by the elevated helper, which only needs
/// to know whether it can actually do the work *now*.
pub fn try_open_promiscuous_on_loopback() -> Result<String, String> {
    match find_loopback_and_probe() {
        FindResult::NoDevices(e) => Err(format!("Could not enumerate network devices: {e}")),
        FindResult::NoLoopback => Err("No loopback interface found.".to_owned()),
        FindResult::Probed {
            name,
            result: Ok(()),
        } => Ok(format!("Verified: opened '{name}' in promiscuous mode.")),
        FindResult::Probed {
            name,
            result: Err(e),
        } => Err(format!("Opening '{name}' in promiscuous mode failed: {e}")),
    }
}

enum FindResult {
    NoDevices(pcap::Error),
    NoLoopback,
    Probed {
        name: String,
        result: Result<(), pcap::Error>,
    },
}

fn find_loopback_and_probe() -> FindResult {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => return FindResult::NoDevices(e),
    };
    let Some(loopback) = devices.into_iter().find(|d| d.flags.is_loopback()) else {
        return FindResult::NoLoopback;
    };
    let name = loopback.name.clone();
    let result = try_open_promiscuous(loopback);
    FindResult::Probed { name, result }
}

/// Briefly open (and immediately close, on scope exit) a promiscuous-mode
/// capture handle on `device`. No packets are ever read - opening and
/// closing the handle is the entire test.
fn try_open_promiscuous(device: Device) -> Result<(), pcap::Error> {
    let _capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(50)
        .open()?;
    Ok(())
}

/// What this platform needs for the probe above to succeed - folded into
/// `NeedsElevation`'s detail text, and echoed in the UI tooltip.
#[cfg(target_os = "linux")]
fn platform_requirements() -> &'static str {
    "On Linux this needs CAP_NET_RAW and CAP_NET_ADMIN - clicking 'L2 mode' \
     will prompt (via pkexec) to run a small helper process elevated."
}

#[cfg(target_os = "windows")]
fn platform_requirements() -> &'static str {
    "On Windows this needs Npcap with elevated (Administrator) access - \
     clicking 'L2 mode' will prompt for UAC elevation for a small helper \
     process."
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn platform_requirements() -> &'static str {
    "This platform's raw-capture permission model isn't documented here yet."
}