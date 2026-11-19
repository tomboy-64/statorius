use std::collections::VecDeque;
use std::time::{Duration, Instant};
use eframe::egui;

use crate::state::PingResult;

const GREEN: egui::Color32 = egui::Color32::from_rgb(60, 170, 60);
const RED: egui::Color32 = egui::Color32::from_rgb(210, 60, 60);
const AMBER: egui::Color32 = egui::Color32::from_rgb(200, 160, 40);

/// Indicator 1: the single most recent ping - green text on success, red on
/// any explicit or implicit failure (timeout / explicit reject / error),
/// amber for a UDP "no reply" (open-or-filtered - not a failure). Explicit
/// rejects show *why* (RST, ICMP port/host unreachable, ...) with the full
/// detail on hover. Shared by both the plain ping list and the L2 pinger
/// list.
pub(super) fn render_last_indicator(ui: &mut egui::Ui, last_result: &Option<PingResult>) {
    match last_result {
        None => {
            ui.colored_label(egui::Color32::GRAY, "...");
        }
        Some(PingResult::Success(rtt)) => {
            ui.colored_label(GREEN, format!("{rtt:.1?}"));
        }
        Some(PingResult::Timeout) => {
            ui.colored_label(RED, "timeout")
                .on_hover_text("No reply within the timeout (probe or answer lost, or filtered)");
        }
        Some(PingResult::Silent) => {
            ui.colored_label(AMBER, "no reply")
                .on_hover_text(
                    "No reply within the timeout. For UDP that means the port is open or \
                     filtered - an empty datagram gets no answer from most services - not \
                     necessarily a failure.",
                );
        }
        Some(PingResult::Rejected { short, detail }) => {
            ui.colored_label(RED, short.as_str()).on_hover_text(detail.as_str());
        }
        Some(PingResult::Error(e)) => {
            ui.colored_label(RED, "error").on_hover_text(e.as_str());
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

/// Ping-tab variant of the "Since" timer that never goes blank: once a
/// response has been recorded it behaves exactly like
/// `render_since_indicator`; until then it counts up from `started_at` (when
/// pinging began) and appends a `*` to flag that nothing has answered yet.
/// The `*` disappears by itself the moment `last_updated` becomes `Some`.
/// Backend-agnostic - ICMP, TCP and UDP all feed the same
/// `last_updated`/`started_at` pair. (The L2 list keeps using the plain
/// version above.)
pub(super) fn render_since_indicator_pending(
    ui: &mut egui::Ui,
    last_updated: &Option<Instant>,
    started_at: Instant,
) {
    match last_updated {
        Some(instant) => {
            ui.label(format_elapsed(instant.elapsed()));
        }
        None => {
            ui.label(format!("{}*", format_elapsed(started_at.elapsed())))
                .on_hover_text("No response yet - counting since pinging started");
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

/// Ping-tab variant of the rolling-average badge, working on the full
/// outcomes instead of bare durations so it can tell the failure kinds
/// apart: green with the average while anything in the window succeeded;
/// red if nothing did - unless every attempt was a UDP "no reply", which is
/// open-or-filtered rather than a failure and gets a neutral grey badge.
/// Hovering lists the window newest first, each with its own reason.
pub(super) fn render_ping_average_indicator(ui: &mut egui::Ui, samples: &VecDeque<PingResult>) {
    let durations: VecDeque<Option<Duration>> = samples
        .iter()
        .map(|s| if let PingResult::Success(d) = s { Some(*d) } else { None })
        .collect();
    let average = rolling_average(&durations);
    let all_silent =
        !samples.is_empty() && samples.iter().all(|s| matches!(s, PingResult::Silent));
    let any_rejected = samples.iter().any(|s| matches!(s, PingResult::Rejected { .. }));

    let (bg, text) = if samples.is_empty() {
        (egui::Color32::from_gray(70), "...".to_owned())
    } else if let Some(avg) = average {
        (egui::Color32::from_rgb(35, 110, 35), format!("{avg:.1?}"))
    } else if all_silent {
        (egui::Color32::from_gray(90), "no reply".to_owned())
    } else if any_rejected {
        (egui::Color32::from_rgb(140, 30, 30), "rejected".to_owned())
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
        ui.strong(format!("Last {} ping(s), newest first:", samples.len()));
        if samples.is_empty() {
            ui.label("No pings recorded yet.");
        }
        for sample in samples.iter().rev() {
            match sample {
                PingResult::Success(d) => {
                    ui.colored_label(GREEN, format!("{d:.1?}"));
                }
                PingResult::Timeout => {
                    ui.colored_label(RED, "timeout");
                }
                PingResult::Silent => {
                    ui.colored_label(AMBER, "no reply (open or filtered)");
                }
                PingResult::Rejected { short, detail } => {
                    ui.colored_label(RED, format!("{short} \u{2013} {detail}"));
                }
                PingResult::Error(e) => {
                    ui.colored_label(RED, format!("error: {e}"));
                }
            }
        }
    });
}
