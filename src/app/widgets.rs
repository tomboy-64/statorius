use std::collections::VecDeque;
use std::time::{Duration, Instant};
use eframe::egui;

use crate::state::PingResult;

/// Indicator 1: the single most recent ping - green text on success, red on
/// any kind of non-response (timeout / port closed / error). Shared by both
/// the plain ping list and the L2 pinger list.
pub(super) fn render_last_indicator(ui: &mut egui::Ui, last_result: &Option<PingResult>) {
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

/// Timer showing how long ago the last result was recorded, with second
/// precision - refreshed every frame since this reads `Instant::elapsed()`
/// directly rather than a value cached at receive-time. Shared by both the
/// plain ping list and the L2 pinger list.
pub(super) fn render_since_indicator(ui: &mut egui::Ui, last_updated: &Option<Instant>) {
    match last_updated {
        None => {
            ui.colored_label(egui::Color32::GRAY, "...");
        }
        Some(instant) => {
            ui.label(format_elapsed(instant.elapsed()));
        }
    }
}

/// Renders a `Duration` as "Ns ago" / "Nm Ns ago" / "Nh Nm ago", truncated to
/// whole seconds - matches the second-precision the "Since" column asks for.
fn format_elapsed(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m {}s ago", secs / 60, secs % 60)
    } else {
        format!("{}h {}m ago", secs / 3600, (secs % 3600) / 60)
    }
}

/// Indicator 2: a colored badge for the rolling average over the last
/// `HISTORY_LEN` pings - green background normally, red background only if
/// every attempt in that window failed. Hovering shows the raw samples.
/// Shared by both the plain ping list and the L2 pinger list.
pub(super) fn render_average_indicator(ui: &mut egui::Ui, history: &VecDeque<Option<Duration>>) {
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