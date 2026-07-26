use std::time::{Duration, Instant};
use eframe::egui;

use super::StatoriusApp;

impl StatoriusApp {
    fn update_interfaces(&mut self) {
        self.interface_update = Instant::now();
        self.interfaces = default_net::get_interfaces();
        self.interface_update = Instant::now();

        self.interfaces_open.resize(
            self.interfaces
                .iter()
                .map(|iface| iface.index)
                .max()
                .unwrap_or(0) as usize + 1,
            (false,false,false)
        )
    }

    pub(super) fn ui_interfaces_tab(&mut self, ui: &mut egui::Ui) {
        // Top bar for controls
        ui.horizontal(|ui| {
            ui.heading("Network Interfaces");
            // Prevent querying the OS 60 times a second
            if ui.button("Refresh Interfaces").clicked() {
                self.interfaces = default_net::get_interfaces();
            }
        });

        ui.separator();

        // Scroll area for the interface list
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.interface_update.elapsed() >= Duration::from_secs(1) {
                self.update_interfaces();
            }

            for iface in &self.interfaces {

                // Convert the MacAddr struct into a String, or provide a fallback
                let mac_str = iface
                    .mac_addr
                    .as_ref()
                    .map(|mac| mac.to_string())
                    .unwrap_or_else(|| "No MAC".to_string());

                let has_valid_ip = (!iface.ipv4.is_empty()) && (!iface.ipv6.is_empty());

                if has_valid_ip && (!self.interfaces_open[iface.index as usize].2) {
                    self.interfaces_open[iface.index as usize].0 = true;
                    self.interfaces_open[iface.index as usize].2 = true;
                }

                // The unique title string acts as its own ID naturally.
                let outer_header_resp = egui::CollapsingHeader::new(format!("{} ({})", iface.name, mac_str))
                    .open(Some(self.interfaces_open[iface.index as usize].0))
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
                        let inner_header_resp = egui::CollapsingHeader::new("Advanced")
                            .open(Some(self.interfaces_open[iface.index as usize].1))
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
                            self.interfaces_open[iface.index as usize].1 = !self.interfaces_open[iface.index as usize].1;
                        }
                    });
                if outer_header_resp.header_response.clicked() {
                    self.interfaces_open[iface.index as usize].0 = !self.interfaces_open[iface.index as usize].0;
                }
            }
        });
    }
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