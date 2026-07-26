use std::net::IpAddr;
use eframe::egui;
use tokio::sync::mpsc;

use crate::state::{PingEntry, PingMethod, PingRequest, WorkerCommand};

use super::widgets::{render_average_indicator, render_last_indicator, render_since_indicator};
use super::StatoriusApp;

impl StatoriusApp {
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

    pub(super) fn ui_ping_tab(&mut self, ui: &mut egui::Ui) {
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