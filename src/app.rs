use std::net::IpAddr;
use std::time::Duration;

use eframe::egui;
use tokio::sync::mpsc;

use crate::state::{PingEntry, PingMethod, PingRequest, PingResult, SharedState};

pub struct PingApp {
    target_input: String,
    tx: mpsc::Sender<PingRequest>,
    state: SharedState,
    last_error: Option<String>,
}

impl PingApp {
    pub fn new(tx: mpsc::Sender<PingRequest>, state: SharedState) -> Self {
        Self {
            target_input: String::new(),
            tx,
            state,
            last_error: None,
        }
    }

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
                if let Err(e) = self.tx.try_send(request) {
                    self.last_error = Some(format!("Failed to queue ping: {e}"));
                }
            }
            Err(_) => {
                self.last_error = Some(format!("'{trimmed}' is not a valid IP address"));
            }
        }
    }
}

impl eframe::App for PingApp {
    // eframe 0.35 split the old single `update(ctx, frame)` into an optional
    // `logic()` (no UI allowed) and this required `ui()`, which is handed the
    // root viewport's `Ui` directly instead of a `Context`. Panel builders
    // (`CentralPanel`, `Grid`, `ScrollArea`, ...) now take `&mut Ui` uniformly.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Network Ping Tool");
            ui.separator();

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

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("ping_results_grid")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Target");
                        ui.strong("Status");
                        ui.strong("Attempts");
                        ui.strong("Success Rate");
                        ui.end_row();

                        // Read the worker's shared state directly - this IS the
                        // update mechanism, there is no separate results channel.
                        for entry in self.state.snapshot() {
                            ui.label(entry.target.to_string());
                            render_status(ui, &entry);
                            ui.label(entry.attempts.to_string());
                            let rate = if entry.attempts > 0 {
                                format!(
                                    "{:.0}%",
                                    100.0 * entry.successes as f32 / entry.attempts as f32
                                )
                            } else {
                                "-".to_owned()
                            };
                            ui.label(rate);
                            ui.end_row();
                        }
                    });
            });
        });

        // The worker updates `SharedState` from a background tokio task with no
        // way to wake the UI directly, so we poll it on a steady tick instead of
        // relying solely on input-driven repaints. `ui.ctx()` gets us back to the
        // `Context` now that `update`'s `ctx` parameter is gone.
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
}

fn render_status(ui: &mut egui::Ui, entry: &PingEntry) {
    match &entry.last_result {
        None => {
            ui.colored_label(egui::Color32::GRAY, "pending...");
        }
        Some(PingResult::Success(rtt)) => {
            ui.colored_label(egui::Color32::from_rgb(60, 160, 60), format!("{rtt:.1?}"));
        }
        Some(PingResult::Timeout) => {
            ui.colored_label(egui::Color32::from_rgb(200, 140, 20), "timeout");
        }
        Some(PingResult::PortClosed) => {
            ui.colored_label(egui::Color32::from_rgb(200, 140, 20), "port closed");
        }
        Some(PingResult::Error(e)) => {
            ui.colored_label(egui::Color32::RED, format!("error: {e}"));
        }
    }
}