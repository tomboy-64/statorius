use std::net::IpAddr;
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::dns::DnsCommand;
use crate::state::{PingEntry, PingMethod, PingRequest, WorkerCommand};

use super::widgets::{render_average_indicator, render_last_indicator, render_since_indicator};
use super::StatoriusApp;

impl StatoriusApp {
    /// Starts (or restarts) continuous pinging of whatever IP is currently
    /// typed into the input box. If it's not a literal IP address, kicks off
    /// a background DNS lookup instead (see `poll_dns_resolution`) rather
    /// than pinging anything yet - the resolved address(es) replace the
    /// input, and the user submits again (now against a literal IP) to
    /// actually start the ping.
    fn submit_ping_target(&mut self) {
        let trimmed = self.target_input.trim().to_owned();
        match trimmed.parse::<IpAddr>() {
            Ok(target) => {
                self.last_error = None;
                self.dns_failed_for = None;
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
                // Not a literal IP - try it as a hostname. A lookup already
                // in flight for a previous entry gets to finish first;
                // re-pressing Enter/Ping while waiting is a no-op rather
                // than firing off a second, overlapping request.
                if self.dns_resolve_rx.is_some() {
                    return;
                }
                self.last_error = None;

                let servers: Vec<IpAddr> = self
                    .dns_shared
                    .get()
                    .into_iter()
                    .filter(|ip| *self.dns_selected.get(ip).unwrap_or(&true))
                    .collect();

                let (respond_to, rx) = oneshot::channel();
                let command = DnsCommand::Resolve {
                    name: trimmed.clone(),
                    servers,
                    respond_to,
                };
                if self.dns_tx.try_send(command).is_ok() {
                    self.dns_resolve_rx = Some(rx);
                    self.dns_resolve_target = trimmed;
                } else {
                    self.dns_failed_for = Some(trimmed);
                }
            }
        }
    }

    /// Checks whether the in-flight hostname lookup (if any) has finished,
    /// and applies its result: on success, `target_input` is replaced with
    /// every resolved A/AAAA address (comma-separated); on failure,
    /// `dns_failed_for` is set so the input renders in red until the user
    /// edits it. Called once per frame from `ui_ping_tab`, the same way the
    /// L2 tab polls its own duplicate-check oneshot.
    fn poll_dns_resolution(&mut self) {
        let Some(rx) = &mut self.dns_resolve_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(addrs)) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = None;
                self.target_input = addrs
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
            }
            Ok(Err(_reason)) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = Some(self.dns_resolve_target.clone());
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = Some(self.dns_resolve_target.clone());
            }
        }
    }

    pub(super) fn ui_ping_tab(&mut self, ui: &mut egui::Ui) {
        self.poll_dns_resolution();

        // The failed-lookup highlight only applies to the exact text that
        // failed - the moment the user types anything else, this clears on
        // its own without needing an explicit "dismiss" action.
        if self.dns_failed_for.as_deref() != Some(self.target_input.as_str()) {
            self.dns_failed_for = None;
        }

        ui.horizontal(|ui| {
            ui.label("Target IP or hostname:");

            let is_resolving = self.dns_resolve_rx.is_some();
            let is_failed = self.dns_failed_for.is_some();
            let text_edit = egui::TextEdit::singleline(&mut self.target_input)
                .text_color_opt(is_failed.then_some(egui::Color32::RED));
            let response = ui.add_enabled(!is_resolving, text_edit);

            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let clicked = ui.add_enabled(!is_resolving, egui::Button::new("Ping")).clicked();
            if (clicked || enter_pressed) && !self.target_input.trim().is_empty() {
                self.submit_ping_target();
            }

            if is_resolving {
                ui.weak("resolving\u{2026}");
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
                .num_columns(5)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Target");
                    ui.strong("Last");
                    ui.strong("Since");
                    ui.strong(format!("Avg ({})", crate::state::HISTORY_LEN));
                    ui.strong("");
                    ui.end_row();

                    // Read the worker's shared state directly - this IS the
                    // update mechanism, there is no separate results channel.
                    for entry in self.state.snapshot() {
                        ui.label(entry.target.to_string());
                        render_last_indicator(ui, &entry.last_result);
                        render_since_indicator(ui, &entry.last_updated);
                        render_average_indicator(ui, &entry.history);
                        render_controls(ui, &entry, &self.tx);
                        ui.end_row();
                    }
                });
        });
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