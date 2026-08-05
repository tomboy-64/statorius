use std::net::IpAddr;
use std::time::Duration;
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::l2::L2Readiness;
use crate::net::l2_ipc::L2DuplicateOutcomeWire;
use crate::net::l2_manager::{L2Command, L2JobRequest, L2Status, SharedL2Status};
use crate::net::l2_pinger::{L2PingEntry, L2Phase, L2PingerCommand, L2PingerKey};

use super::widgets::{render_average_indicator, render_last_indicator, render_since_indicator};
use super::StatoriusApp;

/// Live validation state for the L2 pinger add-form's *source* IP field:
/// black (invalid) / yellow (checking) / red (duplicate) / green (clear).
/// Duplicate-checking is about the source address the user intends to send
/// from, not the ping target - see the module-level notes in `l2_pinger`.
#[derive(Clone, PartialEq)]
pub(super) enum L2InputValidation {
    Invalid,
    Checking,
    Duplicate(Vec<String>),
    Clear,
}

impl StatoriusApp {
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

    pub(super) fn ui_l2_ping_tab(&mut self, ui: &mut egui::Ui) {
        // The "L2 mode" checkbox now lives in the tab row itself; this tab
        // is only reachable once it's actually active (see `render_tab_bar`),
        // so this is a defensive fallback rather than the normal path.
        let l2_active = matches!(self.l2_status.get(), L2Status::Active { .. });
        if !l2_active {
            ui.weak("Activate L2 mode in the tab row above to use raw L2 pings.");
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
                .num_columns(8)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Source");
                    ui.strong("Target");
                    ui.strong("VLAN");
                    ui.strong("Round");
                    ui.strong("Last");
                    ui.strong("Since");
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
                        render_since_indicator(ui, &entry.last_updated);
                        render_average_indicator(ui, &entry.history);
                        render_l2_pinger_controls(ui, &entry, &self.l2_pinger_tx);
                        ui.end_row();
                    }
                });
        });
    }
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

/// The "L2 mode" checkbox, now at the top of the L2 Ping tab (rather than
/// the window's top-right corner), with a small colored status dot: green
/// once active and confirmed working, red if activation failed, neutral
/// otherwise (inactive / still starting - neither a success nor a failure
/// yet). Checked state, label, and hover text all come straight from
/// `SharedL2Status` - there's no local bool to keep in sync, so it can never
/// show something that isn't actually true. Clicking it only ever sends a
/// command; the background manager task is what actually spawns/tears down
/// the helper and updates the status.
pub(super) fn render_l2_checkbox(
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
        let resp = ui
            .add_enabled(clickable, checkbox)
            .on_hover_text(hover.clone())
            .on_disabled_hover_text(hover);

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

/// Same stop/play/delete pattern as `render_controls` on the plain Ping tab,
/// for the L2 pinger list - keyed by (source_ip, target) now rather than
/// target alone, since the same target might be tracked from more than one
/// candidate source.
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