//! What happens when the window can't be created.
//!
//! In release builds on Windows the process has no console, so an error
//! returned from `eframe::run_native` would end the program with no sign of
//! why. This module is the one place that handles it:
//!
//! 1. If the failure came from wgpu *after* an adapter was selected (device
//!    or surface creation on a broken driver), the app relaunches itself
//!    restricted to the next backend (`graphics::plan_fallback`).
//! 2. Otherwise - or when every backend has failed - the error is written to
//!    `startup-error.log` in the config directory, printed to stderr and
//!    shown in a native dialog, with what to install if a library is missing.

use crate::graphics::{self, BackendChoice};

/// Which kind of component failed, for the hint in the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureKind {
    Graphics,
    WindowSystem,
    Other,
}

fn kind_of(error: &eframe::Error) -> FailureKind {
    match error {
        eframe::Error::Wgpu(_) => FailureKind::Graphics,
        eframe::Error::Winit(_) | eframe::Error::WinitEventLoop(_) => FailureKind::WindowSystem,
        _ => FailureKind::Other,
    }
}

/// The text shown to the user (dialog and log).
fn report_text(error: &str, kind: FailureKind, library_report: &str, log: Option<&str>) -> String {
    let mut text = format!("Statorius could not open its window.\n\n{error}\n");
    match kind {
        FailureKind::Graphics => {
            text.push_str("\nNo usable graphics backend was found.\n");
            if !library_report.is_empty() {
                text.push('\n');
                text.push_str(library_report);
                text.push('\n');
            }
        }
        FailureKind::WindowSystem => {
            if cfg!(target_os = "linux") {
                text.push_str(
                    "\nThe window system could not be set up. Install the X11 and keyboard \
                     libraries (Debian/Ubuntu: libx11-6 libx11-xcb1 libxcursor1 libxi6 \
                     libxkbcommon0 libxkbcommon-x11-0).\n",
                );
            }
        }
        FailureKind::Other => {}
    }
    if let Some(log) = log {
        text.push_str(&format!("\nThis message is also in {log}\n"));
    }
    text
}

/// Handles a failed `run_native`; never returns.
pub fn handle(error: &eframe::Error, choice: BackendChoice) -> ! {
    let kind = kind_of(error);

    if kind == FailureKind::Graphics {
        if let Some((next, failed)) = graphics::plan_fallback(choice) {
            match graphics::relaunch_with(next, &failed) {
                Ok(()) => std::process::exit(0),
                Err(e) => eprintln!("Could not relaunch on another graphics backend: {e}"),
            }
        }
    }

    let log_path = graphics::config_dir().map(|d| d.join("startup-error.log"));
    let library_report = if kind == FailureKind::Graphics {
        graphics::library_report()
    } else {
        String::new()
    };
    let log_text = log_path.as_ref().map(|p| p.display().to_string());
    let text = report_text(&error.to_string(), kind, &library_report, log_text.as_deref());

    if let Some(path) = &log_path {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, &text);
    }
    eprintln!("{text}");
    show_dialog("Statorius could not start", &text);
    std::process::exit(1)
}

#[cfg(windows)]
fn show_dialog(title: &str, message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (title, message) = (wide(title), wide(message));
    unsafe {
        MessageBoxW(std::ptr::null_mut(), message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

/// `zenity` or `kdialog` if installed; without either, the message is only
/// on stderr and in the log.
#[cfg(not(windows))]
fn show_dialog(title: &str, message: &str) {
    use std::process::Command;

    let attempts: [(&str, Vec<&str>); 2] = [
        ("zenity", vec!["--error", "--no-markup", "--title", title, "--text", message]),
        ("kdialog", vec!["--error", message, "--title", title]),
    ];
    for (program, args) in attempts {
        // `Ok` = the program exists and ran (whatever the user clicked).
        if Command::new(program).args(&args).status().is_ok() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphics_failure_report_names_libraries_and_log() {
        let text = report_text(
            "Wgpu(NoSuitableAdapterFound)",
            FailureKind::Graphics,
            "Vulkan: libvulkan.so.1 not found. Install the Vulkan loader.",
            Some("/home/u/.config/statorius/startup-error.log"),
        );
        assert!(text.contains("Wgpu(NoSuitableAdapterFound)"));
        assert!(text.contains("No usable graphics backend"));
        assert!(text.contains("libvulkan.so.1 not found"));
        assert!(text.contains("startup-error.log"));
    }

    #[test]
    fn other_failures_get_no_graphics_hint() {
        let text = report_text("boom", FailureKind::Other, "", None);
        assert!(text.contains("boom"));
        assert!(!text.contains("graphics backend"));
    }
}
