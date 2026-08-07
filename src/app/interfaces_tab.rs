use std::time::{Duration, Instant};
use eframe::egui;
use tokio::sync::oneshot;

use super::StatoriusApp;

impl StatoriusApp {
    /// Kicks off a background refresh of `self.interfaces`, unless one is
    /// already in flight. `default_net::get_interfaces()` is a blocking OS
    /// call - on Windows in particular, enumerating adapters can
    /// occasionally take a noticeable amount of time - so it never runs
    /// directly on the UI thread: it's offloaded to a tokio blocking-pool
    /// thread via `spawn_blocking` and the result is picked up later by
    /// `poll_interfaces_refresh`, the same non-blocking `try_recv` pattern
    /// every other background operation in this app already uses.
    fn start_interfaces_refresh(&mut self) {
        if self.interfaces_refresh_rx.is_some() {
            return; // already running - let it finish before starting another
        }
        let (tx, rx) = oneshot::channel();
        self.interfaces_refresh_rx = Some(rx);
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(default_net::get_interfaces());
        });
    }

    /// Checks whether the in-flight refresh (if any) has finished, and
    /// applies it - same shape as `ping_tab`'s `poll_dns_resolution`.
    /// Called once per frame while the Interfaces tab is shown.
    ///
    /// Deliberately does NOT touch `interfaces_open` here - sizing that to
    /// match `interfaces` used to happen only on this completion path,
    /// which left a real gap: `interfaces` is also populated synchronously
    /// once at startup (`StatoriusApp::new`), so the very first time this
    /// tab was opened - before any background refresh had a chance to
    /// finish - the render loop below would index into a still-empty
    /// `interfaces_open` and panic immediately. `interface_open_state`
    /// grows the vec on demand instead, so there's no ordering between the
    /// two lists to keep in sync at all, here or anywhere else.
    fn poll_interfaces_refresh(&mut self) {
        let Some(rx) = &mut self.interfaces_refresh_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(interfaces) => {
                self.interfaces_refresh_rx = None;
                self.interface_update = Instant::now();
                self.interfaces = interfaces;
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                // Extremely unlikely (the blocking task would have to
                // panic), but reset the timer regardless so a persistent
                // failure doesn't retry every single frame forever.
                self.interfaces_refresh_rx = None;
                self.interface_update = Instant::now();
            }
        }
    }

    pub(super) fn ui_interfaces_tab(&mut self, ui: &mut egui::Ui) {
        self.poll_interfaces_refresh();

        // Top bar for controls
        ui.horizontal(|ui| {
            ui.heading("Network Interfaces");
            if ui.button("Refresh Interfaces").clicked() {
                self.start_interfaces_refresh();
            }
        });

        ui.separator();

        // Scroll area for the interface list
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Prevent querying the OS 60 times a second - but never do the
            // querying itself right here; just kick off the background
            // refresh once a second and let `poll_interfaces_refresh`
            // (called at the top of this function, every frame) pick up
            // the result whenever it arrives.
            if self.interface_update.elapsed() >= Duration::from_secs(1) {
                self.start_interfaces_refresh();
            }

            for iface in &self.interfaces {

                // Convert the MacAddr struct into a String, or provide a fallback
                let mac_str = iface
                    .mac_addr
                    .as_ref()
                    .map(|mac| mac.to_string())
                    .unwrap_or_else(|| "No MAC".to_string());

                let has_valid_ip = (!iface.ipv4.is_empty()) && (!iface.ipv6.is_empty());

                let index = iface.index as usize;
                if has_valid_ip && !interface_open_state(&mut self.interfaces_open, index).2 {
                    let state = interface_open_state(&mut self.interfaces_open, index);
                    state.0 = true;
                    state.2 = true;
                }

                // The unique title string acts as its own ID naturally.
                let outer_open = interface_open_state(&mut self.interfaces_open, index).0;
                let outer_header_resp = egui::CollapsingHeader::new(format!("{} ({})", iface.name, mac_str))
                    .open(Some(outer_open))
                    .show(ui, |ui| {

                        // Friendly Name (Very useful on Windows)
                        if let Some(fname) = &iface.friendly_name {
                            ui.horizontal(|ui| {
                                ui.strong("Friendly Name:");
                                ui.label(fname);
                            });
                        }

                        // --- MAC Address ---
                        ui.horizontal(|ui| {
                            ui.strong("MAC Address:");
                            ui.label(mac_str);
                        });

                        // --- IPv4 Addresses ---
                        ui.horizontal(|ui| {
                            ui.strong("IPv4:");
                            if iface.ipv4.is_empty() {
                                ui.label("None");
                            } else {
                                let v4_list: Vec<String> = iface.ipv4.iter()
                                    .map(|ip| format!("{}/{}", ip.addr, ip.prefix_len))
                                    .collect();
                                ui.label(v4_list.join(", "));
                            }
                        });

                        // --- IPv6 Addresses ---
                        ui.horizontal(|ui| {
                            ui.strong("IPv6:");
                            if iface.ipv6.is_empty() {
                                ui.label("None");
                            } else {
                                let v6_list: Vec<String> = iface.ipv6.iter()
                                    .map(|ip| format!("{}/{}", ip.addr, ip.prefix_len))
                                    .collect();
                                ui.label(v6_list.join(", "));
                            }
                        });

                        // --- Bond / Teaming Status ---
                        /*
                        ui.horizontal(|ui| {
                            ui.strong("Bond Status:");
                            ui.label(self.get_bond_status(&iface.name));
                        });
                        */

                        // --- Advanced Details Toggle ---
                        // Egui automatically scopes this ID to the parent header
                        let inner_open = interface_open_state(&mut self.interfaces_open, index).1;
                        let inner_header_resp = egui::CollapsingHeader::new("Advanced")
                            .open(Some(inner_open))
                            .show(ui, |ui| {

                                // Description (Often populated on Linux/macOS)
                                if let Some(desc) = &iface.description {
                                    ui.horizontal(|ui| {
                                        ui.strong("Description:");
                                        ui.label(desc);
                                    });
                                }

                                // OS Interface Index
                                ui.horizontal(|ui| {
                                    ui.strong("OS Index:");
                                    ui.label(iface.index.to_string());
                                });

                                // Interface Type (e.g., Loopback, Ethernet, Wireless)
                                ui.horizontal(|ui| {
                                    ui.strong("Type:");
                                    ui.label(format!("{:?}", iface.if_type));
                                });

                                // Speeds
                                if let Some(tx) = iface.transmit_speed {
                                    ui.horizontal(|ui| {
                                        ui.strong("TX Speed:");
                                        ui.label(format_bps(tx));
                                    });
                                }
                                if let Some(rx) = iface.receive_speed {
                                    ui.horizontal(|ui| {
                                        ui.strong("RX Speed:");
                                        ui.label(format_bps(rx));
                                    });
                                }

                                // Raw Flags (Useful for debugging UP/BROADCAST/LOOPBACK bits)
                                ui.horizontal(|ui| {
                                    ui.strong("Raw Flags:");
                                    ui.label(format!("{:#010X}", iface.flags));
                                });
                            });
                        if inner_header_resp.header_response.clicked() {
                            interface_open_state(&mut self.interfaces_open, index).1 =
                                !interface_open_state(&mut self.interfaces_open, index).1;
                        }
                    });
                if outer_header_resp.header_response.clicked() {
                    interface_open_state(&mut self.interfaces_open, index).0 =
                        !interface_open_state(&mut self.interfaces_open, index).0;
                }
            }
        });
    }
}

/// Returns a mutable reference to `open[index]`, growing `open` first if
/// `index` is out of bounds. `default_net`'s OS-assigned interface indices
/// aren't small/contiguous, and `interfaces` can legitimately be populated
/// (at startup, or by a background refresh) before `interfaces_open` has
/// ever been sized to match - so every access goes through here rather
/// than a raw `open[index]`, which would panic (and previously did) the
/// moment those two ever got out of step.
fn interface_open_state(open: &mut Vec<(bool, bool, bool)>, index: usize) -> &mut (bool, bool, bool) {
    if index >= open.len() {
        open.resize(index + 1, (false, false, false));
    }
    &mut open[index]
}

/// Renders a bits-per-second speed as e.g. "1Gbps" instead of a raw bit
/// count - steps up by factors of 1000 (bps -> Kbps -> ... -> Pbps, matching
/// how link speeds are conventionally quoted, not binary Ki/Mi steps).
/// Whole values print with no decimals; anything else keeps up to two,
/// trimmed of trailing zeros.
fn format_bps(bps: u64) -> String {
    const UNITS: [&str; 6] = ["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps"];
    let mut value = bps as f64;
    let mut unit_idx = 0;
    while value >= 1000.0 && unit_idx < UNITS.len() - 1 {
        value /= 1000.0;
        unit_idx += 1;
    }
    if value.fract() == 0.0 {
        format!("{}{}", value as u64, UNITS[unit_idx])
    } else {
        let s = format!("{value:.2}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        format!("{s}{}", UNITS[unit_idx])
    }
}
