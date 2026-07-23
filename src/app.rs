use std::collections::VecDeque;
use std::net::IpAddr;
use std::time;
use std::time::{Duration, Instant};
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::l2::L2Readiness;
use crate::net::l2_ipc::L2DuplicateOutcomeWire;
use crate::net::l2_manager::{L2Command, L2JobRequest, L2Status, SharedL2Status};
use crate::net::l2_pinger::{L2PingEntry, L2Phase, L2PingerCommand, L2PingerKey, L2PingerState};
use crate::state::{PingEntry, PingMethod, PingRequest, PingResult, SharedState, WorkerCommand};

/// Which tab is currently shown. "L2 Ping" is only ever selectable when
/// `L2Readiness` isn't `Unavailable` - see `render_tab_bar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Ping,
    L2Ping,
    Interfaces,
}

/// Live validation state for the L2 pinger add-form's *source* IP field:
/// black (invalid) / yellow (checking) / red (duplicate) / green (clear).
/// Duplicate-checking is about the source address the user intends to send
/// from, not the ping target - see the module-level notes in `l2_pinger`.
#[derive(Clone, PartialEq)]
enum L2InputValidation {
    Invalid,
    Checking,
    Duplicate(Vec<String>),
    Clear,
}

pub struct StatoriusApp {
    target_input: String,
    tx: mpsc::Sender<WorkerCommand>,
    state: SharedState,
    last_error: Option<String>,

    active_tab: ActiveTab,

    /// Whether L2 is possible at all as launched, and if not, whether
    /// elevation would plausibly fix it (see `net::l2`) - checked once at
    /// startup, never re-probed, never used to request privileges itself.
    /// Also what gates whether the "L2 Ping" tab itself is selectable.
    l2_readiness: L2Readiness,
    /// Sends Activate/Deactivate to the background `l2_manager_task`, which
    /// owns spawning the (possibly elevated) helper process and its IPC
    /// connection - the GUI never touches a raw socket directly.
    l2_tx: mpsc::Sender<L2Command>,
    /// The manager's live status, read fresh every frame - ground truth for
    /// what the checkbox should show, not a bool we own ourselves.
    l2_status: SharedL2Status,

    // --- L2 Pingers: add-form state ---
    /// The address the user intends to send *from* - this is what gets
    /// live-validated and duplicate-checked, not the target.
    l2_pinger_source_input: String,
    l2_pinger_target_input: String,
    l2_pinger_vlan_input: String,
    l2_pinger_timeout_input: String,
    /// VLANs entered so far this run, offered back as quick-select buttons.
    known_vlans: Vec<u16>,
    l2_pinger_error: Option<String>,
    /// Which (source-IP field, VLAN field) combo `l2_input_validation`
    /// currently reflects - re-validating only happens when this stops
    /// matching the live input, instead of re-checking every single frame.
    l2_input_validated_for: String,
    l2_input_validation: L2InputValidation,
    l2_input_check_rx: Option<oneshot::Receiver<L2DuplicateOutcomeWire>>,

    // --- L2 Pingers: channels/state ---
    l2_pinger_tx: mpsc::Sender<L2PingerCommand>,
    l2_pinger_state: L2PingerState,
    /// Used directly by the add-form's live duplicate-check on whatever's
    /// currently typed - separate from `l2_pinger_tx`, which only ever
    /// controls already-added, tracked pingers.
    l2_job_tx: mpsc::Sender<L2JobRequest>,

    /// Snapshot of every network interface on the machine, for the
    /// "Interfaces" tab. Populated once at startup and on demand via its
    /// "Refresh" button - not re-queried every frame, since interface
    /// enumeration is a real (if cheap) system call and this data rarely
    /// changes mid-session.
    interfaces: Vec<default_net::Interface>,
    interface_update: time::Instant,
    interfaces_open: Vec::<(bool,bool,bool)>, // (outer is open, inner is open, ip is valid)
}

impl StatoriusApp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx: mpsc::Sender<WorkerCommand>,
        state: SharedState,
        l2_readiness: L2Readiness,
        l2_tx: mpsc::Sender<L2Command>,
        l2_status: SharedL2Status,
        l2_pinger_tx: mpsc::Sender<L2PingerCommand>,
        l2_pinger_state: L2PingerState,
        l2_job_tx: mpsc::Sender<L2JobRequest>,
    ) -> Self {
        Self {
            target_input: String::new(),
            tx,
            state,
            last_error: None,
            active_tab: ActiveTab::Ping,
            l2_readiness,
            l2_tx,
            l2_status,
            l2_pinger_source_input: String::new(),
            l2_pinger_target_input: String::new(),
            l2_pinger_vlan_input: String::new(),
            l2_pinger_timeout_input: "1000".to_owned(),
            known_vlans: Vec::new(),
            l2_pinger_error: None,
            l2_input_validated_for: String::new(),
            l2_input_validation: L2InputValidation::Invalid,
            l2_input_check_rx: None,
            l2_pinger_tx,
            l2_pinger_state,
            l2_job_tx,
            interfaces: default_net::get_interfaces(),
            interface_update: Instant::now(),
            interfaces_open: Vec::new(),
        }
    }

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

    /// Starts (or restarts) continuous pinging of whatever IP is currently typed
    /// into the input box.
    fn submit_ping(&mut self) {
        let trimmed = self.target_input.trim();
        match trimmed.parse::<IpAddr>() {
            Ok(target) => {
                self.last_error = None;
                let request = PingRequest {
                    target,
                    method: PingMethod::Icmp,
                    source_ip: None,
                };
                if let Err(e) = self.tx.try_send(WorkerCommand::Start(request)) {
                    self.last_error = Some(format!("Failed to queue ping: {e}"));
                }
            }
            Err(_) => {
                self.last_error = Some(format!("'{trimmed}' is not a valid IP address"));
            }
        }
    }

    /// Poll any in-flight validation check, and (re-)start one if the
    /// source-IP/VLAN fields have changed since the last check. Called once
    /// per frame, only while the L2 Ping tab's form is actually shown.
    fn update_l2_input_validation(&mut self) {
        if let Some(rx) = &mut self.l2_input_check_rx {
            match rx.try_recv() {
                Ok(outcome) => {
                    self.l2_input_check_rx = None;
                    self.l2_input_validation = match outcome {
                        L2DuplicateOutcomeWire::Clear => L2InputValidation::Clear,
                        L2DuplicateOutcomeWire::Duplicate { macs } => {
                            L2InputValidation::Duplicate(macs)
                        }
                        // Inconclusive - the field itself parses fine, but we
                        // couldn't confirm it's clear, so don't claim green.
                        L2DuplicateOutcomeWire::Error(_) => L2InputValidation::Checking,
                    };
                }
                Err(oneshot::error::TryRecvError::Empty) => return, // still checking
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.l2_input_check_rx = None;
                    self.l2_input_validation = L2InputValidation::Invalid;
                }
            }
        }

        let key = format!(
            "{}|{}",
            self.l2_pinger_source_input.trim(),
            self.l2_pinger_vlan_input.trim()
        );
        if key == self.l2_input_validated_for {
            return; // nothing changed since the last check
        }
        self.l2_input_validated_for = key;

        match parse_ip(&self.l2_pinger_source_input) {
            None => {
                self.l2_input_validation = L2InputValidation::Invalid;
            }
            Some(ip) => {
                let vlan = parse_vlan(&self.l2_pinger_vlan_input);
                self.l2_input_validation = L2InputValidation::Checking;
                let (tx, rx) = oneshot::channel();
                let job = L2JobRequest::CheckDuplicate {
                    candidate: ip,
                    vlan,
                    timeout: Duration::from_secs(1),
                    respond_to: tx,
                };
                if self.l2_job_tx.try_send(job).is_ok() {
                    self.l2_input_check_rx = Some(rx);
                } else {
                    self.l2_input_validation = L2InputValidation::Invalid;
                }
            }
        }
    }

    /// Adds (or restarts) a pairing in the L2 Pingers list from the add-form.
    fn submit_l2_pinger(&mut self) {
        let Some(source_ip) = parse_ip(&self.l2_pinger_source_input) else {
            self.l2_pinger_error = Some(
                "Enter a valid source IP address, e.g. 192.168.1.50 or 2001:db8::50".to_owned(),
            );
            return;
        };
        let Some((target, prefix)) = parse_cidr(&self.l2_pinger_target_input) else {
            self.l2_pinger_error = Some(
                "Enter a valid target IP address with a subnet mask, e.g. 192.168.1.5/24 or 2001:db8::1/64"
                    .to_owned(),
            );
            return;
        };
        if source_ip.is_ipv4() != target.is_ipv4() {
            self.l2_pinger_error = Some(
                "Source IP and target IP must be the same address family (both IPv4 or both IPv6)"
                    .to_owned(),
            );
            return;
        }

        let vlan = parse_vlan(&self.l2_pinger_vlan_input);
        if let Some(v) = vlan {
            if !self.known_vlans.contains(&v) {
                self.known_vlans.push(v);
                self.known_vlans.sort_unstable();
            }
        }
        let timeout_ms: u64 = self
            .l2_pinger_timeout_input
            .trim()
            .parse()
            .unwrap_or(1000)
            .max(1);

        self.l2_pinger_error = None;
        let command = L2PingerCommand::Start {
            source_ip,
            target,
            prefix_len: prefix,
            vlan,
            timeout: Duration::from_millis(timeout_ms),
        };
        if let Err(e) = self.l2_pinger_tx.try_send(command) {
            self.l2_pinger_error = Some(format!("Failed to queue L2 pinger: {e}"));
        }
    }

    fn ui_ping_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Target IP:");
            let response = ui.text_edit_singleline(&mut self.target_input);
            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let clicked = ui.button("Ping").clicked();
            if (clicked || enter_pressed) && !self.target_input.trim().is_empty() {
                self.submit_ping();
            }
        });

        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        ui.separator();
        ui.label("Targets:");
        ui.add_space(4.0);

        egui::ScrollArea::vertical().id_salt("ping_scroll").show(ui, |ui| {
            egui::Grid::new("ping_results_grid")
                .num_columns(4)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Target");
                    ui.strong("Last");
                    ui.strong(format!("Avg ({})", crate::state::HISTORY_LEN));
                    ui.strong("");
                    ui.end_row();

                    // Read the worker's shared state directly - this IS the
                    // update mechanism, there is no separate results channel.
                    for entry in self.state.snapshot() {
                        ui.label(entry.target.to_string());
                        render_last_indicator(ui, &entry.last_result);
                        render_average_indicator(ui, &entry.history);
                        render_controls(ui, &entry, &self.tx);
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_l2_ping_tab(&mut self, ui: &mut egui::Ui) {
        render_l2_checkbox(ui, &self.l2_readiness, &self.l2_status, &self.l2_tx);
        ui.add_space(4.0);

        let l2_active = matches!(self.l2_status.get(), L2Status::Active { .. });
        if !l2_active {
            ui.weak("Activate L2 mode above to use raw L2 pings.");
            return;
        }

        self.update_l2_input_validation();

        ui.horizontal(|ui| {
            ui.label("Source IP:");
            ui.add(
                egui::TextEdit::singleline(&mut self.l2_pinger_source_input)
                    .desired_width(140.0)
                    .hint_text("192.168.1.50 or 2001:db8::50"),
            );
            render_l2_input_indicator(ui, &self.l2_input_validation);
        });

        ui.horizontal(|ui| {
            ui.label("VLAN:");
            ui.add(
                egui::TextEdit::singleline(&mut self.l2_pinger_vlan_input)
                    .desired_width(50.0)
                    .hint_text("none"),
            );

            ui.label("Target IP/mask:");
            ui.add(
                egui::TextEdit::singleline(&mut self.l2_pinger_target_input)
                    .desired_width(150.0)
                    .hint_text("192.168.1.5/24 or 2001:db8::1/64"),
            );

            ui.label("Timeout (ms):");
            ui.add(
                egui::TextEdit::singleline(&mut self.l2_pinger_timeout_input)
                    .desired_width(60.0),
            );

            if ui.button("Add").clicked() {
                self.submit_l2_pinger();
            }
        });

        // Quick-select for VLANs used earlier this run - kept as a row of
        // buttons rather than a native dropdown widget, to avoid a combo-box
        // API this session couldn't verify.
        if !self.known_vlans.is_empty() {
            ui.horizontal(|ui| {
                ui.weak("recent VLANs:");
                for v in self.known_vlans.clone() {
                    if ui.small_button(v.to_string()).clicked() {
                        self.l2_pinger_vlan_input = v.to_string();
                    }
                }
            });
        }

        if let Some(err) = &self.l2_pinger_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        ui.add_space(4.0);

        egui::ScrollArea::vertical().id_salt("l2_pinger_scroll").show(ui, |ui| {
            egui::Grid::new("l2_pinger_grid")
                .num_columns(7)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Source");
                    ui.strong("Target");
                    ui.strong("VLAN");
                    ui.strong("Round");
                    ui.strong("Last");
                    ui.strong(format!("Avg ({})", crate::state::HISTORY_LEN));
                    ui.strong("");
                    ui.end_row();

                    for entry in self.l2_pinger_state.snapshot() {
                        ui.label(entry.source_ip.to_string());
                        ui.label(format!("{}/{}", entry.target, entry.prefix_len));
                        ui.label(
                            entry
                                .vlan
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                        render_l2_phase_indicator(ui, entry.phase, &entry.duplicate_macs);
                        render_last_indicator(ui, &entry.last_result);
                        render_average_indicator(ui, &entry.history);
                        render_l2_pinger_controls(ui, &entry, &self.l2_pinger_tx);
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_interfaces_tab(&mut self, ui: &mut egui::Ui) {
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
                                        ui.label(format!("{} bps", tx));
                                    });
                                }
                                if let Some(rx) = iface.receive_speed {
                                    ui.horizontal(|ui| {
                                        ui.strong("RX Speed:");
                                        ui.label(format!("{} bps", rx));
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



impl eframe::App for StatoriusApp {
    // eframe 0.35 split the old single `update(ctx, frame)` into an optional
    // `logic()` (no UI allowed) and this required `ui()`, which is handed the
    // root viewport's `Ui` directly instead of a `Context`. Panel builders
    // (`CentralPanel`, `Grid`, `ScrollArea`, ...) now take `&mut Ui` uniformly.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            render_tab_bar(ui, &mut self.active_tab, &self.l2_readiness);
            ui.separator();

            match self.active_tab {
                ActiveTab::Ping => self.ui_ping_tab(ui),
                ActiveTab::L2Ping => self.ui_l2_ping_tab(ui),
                ActiveTab::Interfaces => (&mut*self).ui_interfaces_tab(ui),
            }
        });

        // The workers update shared state from background tokio tasks with
        // no way to wake the UI directly, so we poll on a steady tick
        // instead of relying solely on input-driven repaints. `ui.ctx()`
        // gets us back to the `Context` now that `update`'s `ctx` parameter
        // is gone.
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
}

/// The Ping / L2 Ping tab bar. "L2 Ping" is only selectable when L2 is at
/// least theoretically possible on this system (`L2Readiness` isn't
/// `Unavailable`) - the tab itself doesn't care whether L2 mode has actually
/// been activated yet, only whether it *could* be; the tab's own content
/// handles "not activated yet" separately (see `render_l2_checkbox` and the
/// "Activate L2 mode above" message).
fn render_tab_bar(ui: &mut egui::Ui, active_tab: &mut ActiveTab, readiness: &L2Readiness) {
    ui.horizontal(|ui| {
        if ui
            .selectable_label(*active_tab == ActiveTab::Ping, "Ping")
            .clicked()
        {
            *active_tab = ActiveTab::Ping;
        }

        let l2_tab_enabled = !matches!(readiness, L2Readiness::Unavailable { .. });
        let l2_tab_hover = match readiness {
            L2Readiness::Unavailable { detail }
            | L2Readiness::Ready { detail }
            | L2Readiness::NeedsElevation { detail } => detail.clone(),
        };
        // `SelectableLabel` isn't a standalone widget struct in this egui
        // version - `selectable_label` only exists as a `Ui` convenience
        // method - so `add_enabled_ui` (which wraps a whole closure in the
        // disabled visual state) replaces the `add_enabled(widget)` pattern
        // used for the plain checkbox above.
        let l2_tab_resp = ui
            .add_enabled_ui(l2_tab_enabled, |ui| {
                ui.selectable_label(*active_tab == ActiveTab::L2Ping, "L2 Ping")
            })
            .inner
            .on_hover_text(l2_tab_hover);
        if l2_tab_resp.clicked() {
            *active_tab = ActiveTab::L2Ping;
        }

        // Pure read-only enumeration, no privileges needed either way - so
        // unlike "L2 Ping", this tab is never disabled.
        if ui
            .selectable_label(*active_tab == ActiveTab::Interfaces, "Interfaces")
            .clicked()
        {
            *active_tab = ActiveTab::Interfaces;
        }
    });
}

/// Parse "1.2.3.4/24" or "2001:db8::1/64" into (address, prefix length).
/// `None` for anything that isn't exactly one of those shapes, or a prefix
/// outside the valid range for whichever family was given (0..=32 for IPv4,
/// 0..=128 for IPv6).
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    let (ip_part, prefix_part) = s.split_once('/')?;
    let ip: IpAddr = ip_part.trim().parse().ok()?;
    let prefix: u8 = prefix_part.trim().parse().ok()?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return None;
    }
    Some((ip, prefix))
}

/// Parse a plain IP address (no subnet mask) - used for the source-IP field.
/// A candidate source address being checked/used doesn't need a prefix the
/// way a CIDR-notated target might.
fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse().ok()
}

/// Empty VLAN field means "no tag"; anything unparseable is also treated as
/// "no tag" for now rather than raising a separate validation error.
fn parse_vlan(s: &str) -> Option<u16> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        t.parse::<u16>().ok()
    }
}

/// Indicator 1: the single most recent ping - green text on success, red on
/// any kind of non-response (timeout / port closed / error). Shared by both
/// the plain ping list and the L2 pinger list.
fn render_last_indicator(ui: &mut egui::Ui, last_result: &Option<PingResult>) {
    match last_result {
        None => {
            ui.colored_label(egui::Color32::GRAY, "...");
        }
        Some(PingResult::Success(rtt)) => {
            ui.colored_label(egui::Color32::from_rgb(60, 170, 60), format!("{rtt:.1?}"));
        }
        Some(PingResult::Timeout) => {
            ui.colored_label(egui::Color32::from_rgb(210, 60, 60), "timeout");
        }
        Some(PingResult::PortClosed) => {
            ui.colored_label(egui::Color32::from_rgb(210, 60, 60), "port closed");
        }
        Some(PingResult::Error(e)) => {
            ui.colored_label(egui::Color32::from_rgb(210, 60, 60), "error")
                .on_hover_text(e.as_str());
        }
    }
}

/// Indicator 2: a colored badge for the rolling average over the last
/// `HISTORY_LEN` pings - green background normally, red background only if
/// every attempt in that window failed. Hovering shows the raw samples.
/// Shared by both the plain ping list and the L2 pinger list.
fn render_average_indicator(ui: &mut egui::Ui, history: &VecDeque<Option<Duration>>) {
    let has_history = !history.is_empty();
    let average = rolling_average(history);

    let (bg, text) = if !has_history {
        (egui::Color32::from_gray(70), "...".to_owned())
    } else if let Some(avg) = average {
        (egui::Color32::from_rgb(35, 110, 35), format!("{avg:.1?}"))
    } else {
        (egui::Color32::from_rgb(140, 30, 30), "no response".to_owned())
    };

    let badge = egui::Frame::NONE
        .fill(bg)
        .corner_radius(4.0)
        .inner_margin(6.0)
        .show(ui, |ui| {
            ui.colored_label(egui::Color32::WHITE, text);
        });

    badge.response.on_hover_ui(|ui| {
        ui.strong(format!("Last {} ping(s), newest first:", history.len()));
        if history.is_empty() {
            ui.label("No pings recorded yet.");
        }
        for sample in history.iter().rev() {
            match sample {
                Some(d) => {
                    ui.label(format!("{d:.1?}"));
                }
                None => {
                    ui.colored_label(egui::Color32::from_rgb(210, 60, 60), "no response");
                }
            }
        }
    });
}

fn rolling_average(history: &VecDeque<Option<Duration>>) -> Option<Duration> {
    let (sum, count) = history
        .iter()
        .flatten()
        .fold((Duration::ZERO, 0u32), |(sum, count), d| (sum + *d, count + 1));
    if count == 0 {
        None
    } else {
        Some(sum / count)
    }
}

/// Stop/play toggle (pauses or resumes this target's continuous loop) plus a
/// delete ("X") button that tears the target down entirely.
fn render_controls(ui: &mut egui::Ui, entry: &PingEntry, tx: &mpsc::Sender<WorkerCommand>) {
    ui.horizontal(|ui| {
        let toggle_symbol = if entry.running { "\u{23f9}" } else { "\u{25b6}" };
        let toggle_hover = if entry.running {
            "Stop pinging this target"
        } else {
            "Resume pinging this target"
        };
        if ui.small_button(toggle_symbol).on_hover_text(toggle_hover).clicked() {
            if entry.running {
                let _ = tx.try_send(WorkerCommand::Stop(entry.target));
            } else {
                let request = PingRequest {
                    target: entry.target,
                    method: entry.method.clone(),
                    source_ip: None,
                };
                let _ = tx.try_send(WorkerCommand::Start(request));
            }
        }

        if ui
            .small_button("X")
            .on_hover_text("Delete this pinger")
            .clicked()
        {
            let _ = tx.try_send(WorkerCommand::Delete(entry.target));
        }
    });
}

/// Same stop/play/delete pattern as `render_controls`, for the L2 pinger
/// list - keyed by (source_ip, target) now rather than target alone, since
/// the same target might be tracked from more than one candidate source.
fn render_l2_pinger_controls(
    ui: &mut egui::Ui,
    entry: &L2PingEntry,
    tx: &mpsc::Sender<L2PingerCommand>,
) {
    let key: L2PingerKey = (entry.source_ip, entry.target);
    ui.horizontal(|ui| {
        let toggle_symbol = if entry.running { "\u{23f9}" } else { "\u{25b6}" };
        let toggle_hover = if entry.running {
            "Stop pinging this target"
        } else {
            "Resume pinging this target"
        };
        if ui.small_button(toggle_symbol).on_hover_text(toggle_hover).clicked() {
            if entry.running {
                let _ = tx.try_send(L2PingerCommand::Stop(key));
            } else {
                let _ = tx.try_send(L2PingerCommand::Start {
                    source_ip: entry.source_ip,
                    target: entry.target,
                    prefix_len: entry.prefix_len,
                    vlan: entry.vlan,
                    timeout: entry.timeout,
                });
            }
        }

        if ui
            .small_button("X")
            .on_hover_text("Delete this pinger")
            .clicked()
        {
            let _ = tx.try_send(L2PingerCommand::Delete(key));
        }
    });
}

/// The "L2 mode" checkbox, now at the top of the L2 Ping tab (rather than
/// the window's top-right corner), with a small colored status dot: green
/// once active and confirmed working, red if activation failed, neutral
/// otherwise (inactive / still starting - neither a success nor a failure
/// yet). Checked state, label, and hover text all come straight from
/// `SharedL2Status` - there's no local bool to keep in sync, so it can never
/// show something that isn't actually true. Clicking it only ever sends a
/// command; the background manager task is what actually spawns/tears down
/// the helper and updates the status.
fn render_l2_checkbox(
    ui: &mut egui::Ui,
    readiness: &L2Readiness,
    status: &SharedL2Status,
    tx: &mpsc::Sender<L2Command>,
) {
    let current = status.get();

    // Unavailable: no prompt could ever fix this, so it's permanently
    // disabled regardless of status (this case is normally unreachable here
    // anyway, since the tab itself is disabled first - kept as a guard
    // regardless). Starting: a request is already in flight (helper
    // launching / elevation prompt pending / handshaking), so further clicks
    // are ignored until it settles.
    let clickable = !matches!(readiness, L2Readiness::Unavailable { .. })
        && !matches!(current, L2Status::Starting);

    let mut checked = matches!(current, L2Status::Active { .. });
    let label = match &current {
        L2Status::Inactive => "L2 mode".to_owned(),
        L2Status::Starting => "L2 mode (starting...)".to_owned(),
        L2Status::Active { .. } => "L2 mode".to_owned(),
        L2Status::Failed { .. } => "L2 mode (failed)".to_owned(),
    };
    let hover: String = match (&current, readiness) {
        (L2Status::Active { detail }, _) => detail.clone(),
        (L2Status::Failed { reason }, _) => reason.clone(),
        (L2Status::Starting, _) => {
            "Waiting for the elevated helper to start and connect...".to_owned()
        }
        (L2Status::Inactive, L2Readiness::Ready { detail }) => detail.clone(),
        (L2Status::Inactive, L2Readiness::NeedsElevation { detail }) => detail.clone(),
        (L2Status::Inactive, L2Readiness::Unavailable { detail }) => detail.clone(),
    };

    ui.horizontal(|ui| {
        let dot_color = match current {
            L2Status::Active { .. } => egui::Color32::from_rgb(60, 170, 60), // green: went well
            L2Status::Failed { .. } => egui::Color32::from_rgb(210, 60, 60), // red: didn't
            L2Status::Inactive | L2Status::Starting => egui::Color32::from_gray(120), // neutral
        };
        let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter().circle_filled(dot_rect.center(), 5.0, dot_color);

        let checkbox = egui::Checkbox::new(&mut checked, label);
        let resp = ui.add_enabled(clickable, checkbox).on_hover_text(hover);

        if resp.clicked() {
            let command = if matches!(current, L2Status::Active { .. }) {
                L2Command::Deactivate
            } else {
                L2Command::Activate
            };
            let _ = tx.try_send(command);
        }
    });
}

/// Live validation dot for the L2 pinger add-form's *source* IP field: black
/// (invalid) / yellow (checking) / red (duplicate) / green (clear).
fn render_l2_input_indicator(ui: &mut egui::Ui, validation: &L2InputValidation) {
    let (color, hover_text) = match validation {
        L2InputValidation::Invalid => (
            egui::Color32::BLACK,
            "Not a valid IPv4/IPv6 address (e.g. 192.168.1.50 or 2001:db8::50)".to_owned(),
        ),
        L2InputValidation::Checking => (
            egui::Color32::from_rgb(210, 180, 20),
            "Checking whether this IP is already in use...".to_owned(),
        ),
        L2InputValidation::Duplicate(macs) => (
            egui::Color32::from_rgb(210, 60, 60),
            format!(
                "Duplicate IP! More than one host answered: {}",
                macs.join(", ")
            ),
        ),
        L2InputValidation::Clear => (
            egui::Color32::from_rgb(60, 170, 60),
            "Valid, and not currently in use.".to_owned(),
        ),
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 6.0, color);
    resp.on_hover_text(hover_text);
}

/// Per-round phase dot for an L2 pinger row: yellow (checking the *source*
/// IP's duplicateness) / red (duplicate) / teal (ping in flight) / green
/// (response arrived), as requested. Grey between rounds.
fn render_l2_phase_indicator(ui: &mut egui::Ui, phase: L2Phase, duplicate_macs: &[String]) {
    let (color, hover): (egui::Color32, String) = match phase {
        L2Phase::Idle => (
            egui::Color32::from_gray(90),
            "Idle - waiting for the next round.".to_owned(),
        ),
        L2Phase::CheckingDuplicate => (
            egui::Color32::from_rgb(210, 180, 20),
            "Checking the source IP for duplicates...".to_owned(),
        ),
        L2Phase::Duplicate => (
            egui::Color32::from_rgb(210, 60, 60),
            if duplicate_macs.is_empty() {
                "Duplicate source IP detected.".to_owned()
            } else {
                format!(
                    "Duplicate source IP detected - MACs seen: {}",
                    duplicate_macs.join(", ")
                )
            },
        ),
        L2Phase::InFlight => (
            egui::Color32::from_rgb(20, 160, 170),
            "Ping in flight...".to_owned(),
        ),
        L2Phase::Success => (
            egui::Color32::from_rgb(60, 170, 60),
            "Response arrived.".to_owned(),
        ),
        L2Phase::Failed => (
            egui::Color32::from_rgb(210, 60, 60),
            "No response (or an error) this round.".to_owned(),
        ),
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 6.0, color);
    resp.on_hover_text(hover);
}