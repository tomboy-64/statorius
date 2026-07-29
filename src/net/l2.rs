//! Layer-2 capability probing + readiness classification.
//!
//! Future features (raw Ethernet frame construction/injection) will need
//! Npcap on Windows and a raw/promiscuous-capable socket on Linux. This
//! module answers one question up front, without ever trying to acquire
//! privileges itself: *can this process already do that, as launched, and if
//! not, would elevation plausibly fix it?*
//!
//! The probe prefers testing against a loopback interface when one is
//! available, since briefly toggling promiscuous mode there can't affect any
//! real traffic. But a loopback interface is not guaranteed to exist:
//! Npcap only creates its loopback adapter when the installer's *optional*
//! "Support loopback traffic" checkbox was enabled - a setting completely
//! unrelated to whichever Npcap option lets Wireshark (or this app) capture
//! on real interfaces without elevation. So "no loopback interface" must
//! *not* be treated as "L2 capture is impossible here" - it just means the
//! test has to run against a real, active interface instead.

use pcap::{Capture, Device};

/// Three-state readiness - "impossible outright" and "possible but needs
/// elevation" need very different UI treatment (permanently disabled vs.
/// clickable-with-a-prompt), so a plain bool isn't enough anymore.
#[derive(Debug, Clone)]
pub enum L2Readiness {
    /// Already works with the privileges we were launched with - activating
    /// L2 mode can spawn the helper directly, no prompt needed.
    Ready { detail: String },
    /// pcap/Npcap is present and a usable interface exists (loopback, or a
    /// real interface as a fallback), but opening it in promiscuous mode
    /// failed - overwhelmingly likely a privilege issue, so activating L2
    /// mode will try to launch the helper elevated.
    NeedsElevation { detail: String },
    /// pcap/Npcap itself isn't usable here at all (not installed, or no
    /// interface at all - loopback or otherwise - could be found to probe
    /// against) - no amount of elevation would help, so the checkbox stays
    /// permanently disabled.
    Unavailable { detail: String },
}

/// One-time, unprivileged startup probe. Never attempts to acquire
/// privileges - it only classifies what's already true.
pub fn probe_l2_readiness() -> L2Readiness {
    match find_probe_target_and_test() {
        FindResult::NoDevices(e) => L2Readiness::Unavailable {
            detail: format!("Could not enumerate network devices: {e}"),
        },
        FindResult::NoUsableDevice => L2Readiness::Unavailable {
            detail: "No usable network interface found to probe against (no loopback \
                     interface, and no active non-loopback interface either)."
                .to_owned(),
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
pub fn try_open_promiscuous_probe() -> Result<String, String> {
    match find_probe_target_and_test() {
        FindResult::NoDevices(e) => Err(format!("Could not enumerate network devices: {e}")),
        FindResult::NoUsableDevice => {
            Err("No usable network interface found (no loopback interface, and no active \
                 non-loopback interface either)."
                .to_owned())
        }
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
    NoUsableDevice,
    Probed {
        name: String,
        result: Result<(), pcap::Error>,
    },
}

fn find_probe_target_and_test() -> FindResult {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => return FindResult::NoDevices(e),
    };
    let Some(target) = choose_probe_target(devices) else {
        return FindResult::NoUsableDevice;
    };
    let name = target.name.clone();
    let result = try_open_promiscuous(target);
    FindResult::Probed { name, result }
}

/// Pick the best available device to probe against: a loopback interface if
/// one exists (safest - can't disrupt real traffic), otherwise the first
/// real interface that's actually up and running. Falling back like this is
/// what keeps a missing/unconfigured loopback adapter (the normal case on a
/// fresh Npcap install - see the module docs above) from being misdiagnosed
/// as "L2 capture isn't possible on this system" when it may well be.
fn choose_probe_target(mut devices: Vec<Device>) -> Option<Device> {
    if let Some(idx) = devices.iter().position(|d| d.flags.is_loopback()) {
        return Some(devices.swap_remove(idx));
    }
    devices
        .into_iter()
        .find(|d| d.flags.is_up() && d.flags.is_running())
}

/// Briefly open (and immediately close, on scope exit) a promiscuous-mode
/// capture handle on `device`. No packets are ever read - opening and
/// closing the handle is the entire test. `device` may be a loopback
/// interface or, when none is available, a real one (see
/// `choose_probe_target`); either way this never blocks waiting for
/// traffic and never reads a single packet, so it's safe to run against a
/// live interface.
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