//! Graphics backend (wgpu) selection, verification and persistence.
//!
//! Three jobs, all feeding the "Graphics" section of the About tab:
//!
//! * **Choosing** which backend wgpu uses, from a small setting stored in a
//!   one-line file in the user's config directory (`BackendChoice`, applied
//!   to `NativeOptions` by `apply` before the window exists).
//! * **Verifying** what is actually running: `GraphicsInfo` is captured from
//!   eframe's creation context (the adapter wgpu really ended up with), so
//!   the About tab shows the truth - including when a requested backend
//!   wasn't available and wgpu fell back to another one.
//! * **Changing** the setting at runtime: wgpu's instance and adapter are
//!   created once at startup, so a change is saved immediately but only
//!   takes effect on the next start - `GraphicsPanel` says so and offers a
//!   restart button.
//!
//! The selection is always a *preference*, never a hard restriction: the
//! chosen backend is tried first, then Vulkan, then OpenGL, then everything
//! else, so a machine where the chosen backend doesn't work still gets a
//! window instead of failing at startup with "no adapter found" (with no GUI
//! to change the setting back). An explicit `WGPU_BACKEND` environment
//! variable overrides all of it, for troubleshooting.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use eframe::egui_wgpu::NativeAdapterSelectorMethod;
use eframe::wgpu::{self, Backend, DeviceType};

/// What the user asked for. `Auto` = Vulkan, then OpenGL, then the rest
/// (DX12 included); the others put that backend first and keep the `Auto`
/// order behind it as the fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendChoice {
    Auto,
    Vulkan,
    OpenGl,
    Dx12,
}

impl BackendChoice {
    /// The choices offered on this platform; empty where the selection
    /// isn't applied at all (macOS keeps wgpu's default, Metal).
    pub fn selectable() -> &'static [BackendChoice] {
        #[cfg(target_os = "windows")]
        {
            &[
                BackendChoice::Auto,
                BackendChoice::Vulkan,
                BackendChoice::OpenGl,
                BackendChoice::Dx12,
            ]
        }
        #[cfg(target_os = "linux")]
        {
            &[BackendChoice::Auto, BackendChoice::Vulkan, BackendChoice::OpenGl]
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            &[]
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Vulkan => "vulkan",
            Self::OpenGl => "opengl",
            Self::Dx12 => "dx12",
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        match key.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "vulkan" => Some(Self::Vulkan),
            "opengl" | "gl" => Some(Self::OpenGl),
            "dx12" => Some(Self::Dx12),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto (Vulkan, then OpenGL)",
            Self::Vulkan => "Vulkan",
            Self::OpenGl => "OpenGL",
            Self::Dx12 => "DirectX 12",
        }
    }

    /// The wgpu backend this choice puts first, `None` for `Auto`.
    fn wanted_backend(self) -> Option<Backend> {
        match self {
            Self::Auto => None,
            Self::Vulkan => Some(Backend::Vulkan),
            Self::OpenGl => Some(Backend::Gl),
            Self::Dx12 => Some(Backend::Dx12),
        }
    }

    /// Lower is better: the requested backend first, then Vulkan, OpenGL,
    /// and everything else.
    fn backend_rank(self, backend: Backend) -> u8 {
        if self.wanted_backend() == Some(backend) {
            return 0;
        }
        match backend {
            Backend::Vulkan => 1,
            Backend::Gl => 2,
            _ => 3,
        }
    }

    /// Reads the saved setting; anything missing, unreadable, unknown or not
    /// offered on this platform is `Auto`.
    pub fn load() -> Self {
        let choice = config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| Self::from_key(&s))
            .unwrap_or(Self::Auto);
        if Self::selectable().contains(&choice) {
            choice
        } else {
            Self::Auto
        }
    }

    fn save(self) -> Result<(), String> {
        let path = config_path().ok_or("no config directory found")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, format!("{}\n", self.key())).map_err(|e| e.to_string())
    }
}

/// `%APPDATA%\Statorius\graphics-backend` on Windows,
/// `$XDG_CONFIG_HOME/statorius/graphics-backend` (or `~/.config/...`)
/// elsewhere. Plain std - no extra crate for one line of settings.
fn config_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(|p| PathBuf::from(p).join("Statorius").join("graphics-backend"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
            })?;
        Some(base.join("statorius").join("graphics-backend"))
    }
}

/// Installs the adapter preference for `choice` into `options`. Must run
/// before `eframe::run_native`. Does nothing where the selection isn't
/// offered, or while `WGPU_BACKEND` is set (that variable wins, exactly as
/// it would without this code).
pub fn apply(options: &mut eframe::NativeOptions, choice: BackendChoice) {
    use eframe::egui_wgpu::WgpuSetup;

    if BackendChoice::selectable().is_empty() || wgpu::Backends::from_env().is_some() {
        return;
    }
    if let WgpuSetup::CreateNew(setup) = &mut options.wgpu_options.wgpu_setup {
        setup.native_adapter_selector = Some(selector(choice));
    }
}

fn selector(choice: BackendChoice) -> NativeAdapterSelectorMethod {
    Arc::new(
        move |adapters: &[wgpu::Adapter], surface: Option<&wgpu::Surface<'_>>| {
            select_adapter(choice, adapters, surface)
        },
    )
}

/// Only adapters that can present to the window are considered; the backend
/// decides first (see `BackendChoice::backend_rank`), and within a backend a
/// discrete GPU beats an integrated one, then virtual, other, and finally
/// software (CPU) adapters.
fn select_adapter(
    choice: BackendChoice,
    adapters: &[wgpu::Adapter],
    surface: Option<&wgpu::Surface<'_>>,
) -> Result<wgpu::Adapter, String> {
    adapters
        .iter()
        .filter(|a| surface.map_or(true, |s| a.is_surface_supported(s)))
        .min_by_key(|a| {
            let info = a.get_info();
            let device_rank = match info.device_type {
                DeviceType::DiscreteGpu => 0,
                DeviceType::IntegratedGpu => 1,
                DeviceType::VirtualGpu => 2,
                DeviceType::Cpu => 4,
                _ => 3,
            };
            (choice.backend_rank(info.backend), device_rank)
        })
        .cloned()
        .ok_or_else(|| "No graphics adapter can present to the window".to_owned())
}

fn backend_label(backend: Backend) -> &'static str {
    match backend {
        Backend::Vulkan => "Vulkan",
        Backend::Gl => "OpenGL",
        Backend::Dx12 => "DirectX 12",
        Backend::Metal => "Metal",
        _ => "Other",
    }
}

fn device_type_label(device_type: DeviceType) -> &'static str {
    match device_type {
        DeviceType::DiscreteGpu => "Discrete GPU",
        DeviceType::IntegratedGpu => "Integrated GPU",
        DeviceType::VirtualGpu => "Virtual GPU",
        DeviceType::Cpu => "Software (CPU)",
        _ => "Other",
    }
}

/// One adapter, reduced to what the About tab shows.
struct AdapterSummary {
    backend: Backend,
    name: String,
    device_type: DeviceType,
    driver: String,
}

impl AdapterSummary {
    fn of(adapter: &wgpu::Adapter) -> Self {
        let info = adapter.get_info();
        Self {
            backend: info.backend,
            name: info.name,
            device_type: info.device_type,
            driver: format!("{} {}", info.driver, info.driver_info).trim().to_owned(),
        }
    }
}

/// What wgpu actually ended up with, captured once at startup.
pub struct GraphicsInfo {
    active: AdapterSummary,
    all: Vec<AdapterSummary>,
}

impl GraphicsInfo {
    /// `None` if the window isn't rendered through wgpu (can't happen with
    /// the renderer this app is built for, but nothing here should panic
    /// over a display-only feature).
    pub fn from_creation_context(cc: &eframe::CreationContext<'_>) -> Option<Self> {
        let state = cc.wgpu_render_state.as_ref()?;
        Some(Self {
            active: AdapterSummary::of(&state.adapter),
            all: state.available_adapters.iter().map(AdapterSummary::of).collect(),
        })
    }
}

/// The "Graphics" section of the About tab: what's running, whether that is
/// what was asked for, and the preference toggle.
pub struct GraphicsPanel {
    info: Option<GraphicsInfo>,
    /// The saved setting - what the radio buttons show and edit.
    choice: BackendChoice,
    /// The setting this run started with, i.e. what was requested for the
    /// backend currently in use. A difference to `choice` means a restart is
    /// pending.
    choice_at_start: BackendChoice,
    /// `Some(value)` while `WGPU_BACKEND` is set - it overrides the setting.
    env_override: Option<String>,
    /// `(is_error, message)` for the last save/restart attempt.
    message: Option<(bool, String)>,
}

impl GraphicsPanel {
    pub fn new(choice: BackendChoice, info: Option<GraphicsInfo>) -> Self {
        Self {
            info,
            choice,
            choice_at_start: choice,
            env_override: wgpu::Backends::from_env()
                .map(|_| std::env::var("WGPU_BACKEND").unwrap_or_else(|_| "set".to_owned())),
            message: None,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Graphics");
        ui.add_space(4.0);

        match &self.info {
            Some(info) => {
                egui::Grid::new("graphics_info_grid")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Backend");
                        ui.strong(backend_label(info.active.backend));
                        ui.end_row();
                        ui.label("Adapter");
                        ui.label(&info.active.name);
                        ui.end_row();
                        ui.label("Type");
                        ui.label(device_type_label(info.active.device_type));
                        ui.end_row();
                        if !info.active.driver.is_empty() {
                            ui.label("Driver");
                            ui.label(&info.active.driver);
                            ui.end_row();
                        }
                    });

                // Verification: compare what was requested for this run with
                // what wgpu really picked.
                if self.env_override.is_none() {
                    if let Some(wanted) = self.choice_at_start.wanted_backend() {
                        if wanted != info.active.backend {
                            ui.colored_label(
                                egui::Color32::ORANGE,
                                format!(
                                    "{} was requested but is not available here - running on {} instead.",
                                    backend_label(wanted),
                                    backend_label(info.active.backend),
                                ),
                            );
                        }
                    }
                }
            }
            None => {
                ui.label("Graphics backend information is not available.");
            }
        }

        if let Some(value) = &self.env_override {
            ui.colored_label(
                egui::Color32::ORANGE,
                format!(
                    "WGPU_BACKEND={value} is set and overrides the setting below, \
                     which has no effect while it is set."
                ),
            );
        }

        if !BackendChoice::selectable().is_empty() {
            ui.add_space(8.0);
            ui.label("Preferred backend:");
            let mut changed = false;
            ui.add_enabled_ui(self.env_override.is_none(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    for &candidate in BackendChoice::selectable() {
                        if ui
                            .radio_value(&mut self.choice, candidate, candidate.label())
                            .changed()
                        {
                            changed = true;
                        }
                    }
                });
            });
            if changed {
                self.message = self.choice.save().err().map(|e| {
                    (true, format!("Could not save the setting: {e}"))
                });
            }
            ui.weak(
                "The preferred backend is tried first and the rest follow in the order \
                 Vulkan, OpenGL, others, so a backend that doesn't work here falls back \
                 instead of preventing startup.",
            );

            if self.choice != self.choice_at_start && self.env_override.is_none() {
                ui.horizontal(|ui| {
                    ui.label("Takes effect after a restart.");
                    if ui.button("Restart now").clicked() {
                        if let Err(e) = restart(ui.ctx()) {
                            self.message = Some((true, format!("Could not restart: {e}")));
                        }
                    }
                });
            }
        }

        if let Some((is_error, message)) = &self.message {
            if *is_error {
                ui.colored_label(egui::Color32::LIGHT_RED, message);
            } else {
                ui.label(message);
            }
        }

        if let Some(info) = &self.info {
            ui.add_space(4.0);
            ui.collapsing("Detected adapters", |ui| {
                for adapter in &info.all {
                    let in_use = adapter.backend == info.active.backend
                        && adapter.name == info.active.name;
                    ui.label(format!(
                        "{} - {} ({}){}",
                        backend_label(adapter.backend),
                        adapter.name,
                        device_type_label(adapter.device_type),
                        if in_use { "  <- in use" } else { "" },
                    ));
                }
            });
        }
    }
}

/// Starts a fresh instance of this executable and closes the current window.
fn restart(ctx: &egui::Context) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::process::Command::new(exe).spawn().map_err(|e| e.to_string())?;
    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    Ok(())
}