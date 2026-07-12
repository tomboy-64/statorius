use std::net::IpAddr;
use std::time::Duration;

use eframe::egui;
use tokio::sync::mpsc;

use crate::state::{PingEntry, PingMethod, PingRequest, PingResult, SharedState, WorkerCommand};

pub struct PingApp {
    target_input: String,
    tx: mpsc::Sender<WorkerCommand>,
    state: SharedState,
    last_error: Option<String>,
}

impl PingApp {
    pub fn new(tx: mpsc::Sender<WorkerCommand>, state: SharedState) -> Self {
        Self {
            target_input: String::new(),
            tx,
            state,
            last_error: None,
        }
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
}

impl eframe::App for PingApp {
    // eframe 0.35 split the old single `update(ctx, frame)` into an optional
    // `logic()` (no UI allowed) and this required `ui()`, which is handed the
    // root viewport's `Ui` directly instead of a `Context`. Panel builders
    // (`CentralPanel`, `Grid`, `ScrollArea`, ...) now take `&mut Ui` uniformly.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
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
            ui.add_space(4.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
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
                            render_last_indicator(ui, &entry);
                            render_average_indicator(ui, &entry);
                            render_controls(ui, &entry, &self.tx);
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

/// Indicator 1: the single most recent ping - green text on success, red on
/// any kind of non-response (timeout / port closed / error).
fn render_last_indicator(ui: &mut egui::Ui, entry: &PingEntry) {
    match &entry.last_result {
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
fn render_average_indicator(ui: &mut egui::Ui, entry: &PingEntry) {
    let has_history = !entry.history.is_empty();
    let average = entry.rolling_average();

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
        ui.strong(format!(
            "Last {} ping(s):",
            entry.history.len()
        ));
        if entry.history.is_empty() {
            ui.label("No pings recorded yet.");
        }
        for sample in entry.history.iter().rev() {
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