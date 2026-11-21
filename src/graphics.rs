//! Graphics backend (wgpu) selection, verification and persistence.
//!
//! Four jobs; the first three feed the "Graphics" section of the About tab:
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
//! * **Surviving failure** (the fourth): backends the machine can't offer are greyed out
//!   (with the missing library or driver named), and if the window can't be
//!   created on the selected backend, the app relaunches itself on the next
//!   one (`plan_fallback`, `relaunch_with`) before giving up - see
//!   `startup_failure` for the final error report.
//!
//! The selection is always a *preference*, never a hard restriction: the
//! chosen backend is tried first, then Vulkan, then OpenGL, then everything
//! else, so a machine where the chosen backend doesn't work still gets a
//! window instead of failing at startup with "no adapter found" (with no GUI
//! to change the setting back). An explicit `WGPU_BACKEND` environment
//! variable overrides all of it, for troubleshooting.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

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

/// The app's config directory: `%APPDATA%\Statorius` on Windows,
/// `$XDG_CONFIG_HOME/statorius` (or `~/.config/statorius`) elsewhere. Plain
/// std - no extra crate for a one-line setting and an error log.
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("Statorius"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
            })?;
        Some(base.join("statorius"))
    }
}

/// `graphics-backend` inside `config_dir()`.
fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("graphics-backend"))
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
    let selected = adapters
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
        .ok_or_else(|| "No graphics adapter can present to the window".to_owned())?;
    // Remembered so that a failure further down the startup (device or
    // surface creation) can be retried on the *next* backend.
    record_selected(selected.get_info().backend);
    Ok(selected)
}

// ----------------------------------------------------------- fallback

/// The backends the automatic fallback cycles through, as `WGPU_BACKEND`
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuApi {
    Vulkan,
    OpenGl,
    Dx12,
}

impl GpuApi {
    fn env_value(self) -> &'static str {
        match self {
            Self::Vulkan => "vulkan",
            Self::OpenGl => "gl",
            Self::Dx12 => "dx12",
        }
    }

    fn from_env_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "vulkan" | "vk" => Some(Self::Vulkan),
            "opengl" | "gles" | "gl" => Some(Self::OpenGl),
            "dx12" | "d3d12" => Some(Self::Dx12),
            _ => None,
        }
    }

    fn from_backend(backend: Backend) -> Option<Self> {
        match backend {
            Backend::Vulkan => Some(Self::Vulkan),
            Backend::Gl => Some(Self::OpenGl),
            Backend::Dx12 => Some(Self::Dx12),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Vulkan => 1,
            Self::OpenGl => 2,
            Self::Dx12 => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Vulkan),
            2 => Some(Self::OpenGl),
            3 => Some(Self::Dx12),
            _ => None,
        }
    }
}

/// Set (to the list of backends that already failed) on a process the
/// fallback relaunched; its presence tells that process it is part of a
/// fallback chain and that the `WGPU_BACKEND` it sees was set by the app,
/// not by the user.
pub const FALLBACK_ENV: &str = "STATORIUS_FALLBACK";

/// The backend the adapter selector returned last (0 = none yet).
static LAST_SELECTED: AtomicU8 = AtomicU8::new(0);

fn record_selected(backend: Backend) {
    if let Some(api) = GpuApi::from_backend(backend) {
        LAST_SELECTED.store(api.code(), Ordering::Relaxed);
    }
}

/// Backends in the order the fallback tries them on this platform, the
/// user's choice first (the same order `select_adapter` ranks them in).
fn fallback_order(choice: BackendChoice) -> Vec<GpuApi> {
    #[cfg(target_os = "windows")]
    let mut order = vec![GpuApi::Vulkan, GpuApi::OpenGl, GpuApi::Dx12];
    #[cfg(target_os = "linux")]
    let mut order = vec![GpuApi::Vulkan, GpuApi::OpenGl];
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let mut order: Vec<GpuApi> = Vec::new();

    let wanted = match choice {
        BackendChoice::Auto => None,
        BackendChoice::Vulkan => Some(GpuApi::Vulkan),
        BackendChoice::OpenGl => Some(GpuApi::OpenGl),
        BackendChoice::Dx12 => Some(GpuApi::Dx12),
    };
    if let Some(w) = wanted {
        if let Some(pos) = order.iter().position(|&a| a == w) {
            order.remove(pos);
            order.insert(0, w);
        }
    }
    order
}

/// The first backend in `order` that hasn't failed yet.
fn next_fallback(order: &[GpuApi], failed: &[GpuApi]) -> Option<GpuApi> {
    order.iter().copied().find(|api| !failed.contains(api))
}

fn parse_failed(list: &str) -> Vec<GpuApi> {
    list.split(',').filter_map(GpuApi::from_env_value).collect()
}

fn format_failed(failed: &[GpuApi]) -> String {
    failed.iter().map(|a| a.env_value()).collect::<Vec<_>>().join(",")
}

/// Decides whether (and on what) to retry after a failed start; pure, so it
/// can be tested without touching the environment.
///
/// * `marker`: value of `FALLBACK_ENV` (we are inside a fallback chain);
/// * `user_forced`: `WGPU_BACKEND` is set;
/// * `env_backend`: its value;
/// * `last_selected`: what the adapter selector last returned.
///
/// A user-set `WGPU_BACKEND` is never overridden. A first run in which no
/// adapter was even selected has nothing to retry - no backend could present
/// to the window at all.
fn plan(
    order: &[GpuApi],
    marker: Option<&str>,
    user_forced: bool,
    env_backend: Option<&str>,
    last_selected: Option<GpuApi>,
) -> Option<(GpuApi, Vec<GpuApi>)> {
    if user_forced && marker.is_none() {
        return None;
    }
    let mut failed = marker.map(parse_failed).unwrap_or_default();
    if marker.is_some() {
        if let Some(current) = env_backend.and_then(GpuApi::from_env_value) {
            failed.push(current);
        }
    }
    match last_selected {
        Some(selected) => failed.push(selected),
        None if marker.is_none() => return None,
        None => {}
    }
    let mut unique = Vec::new();
    for api in failed {
        if !unique.contains(&api) {
            unique.push(api);
        }
    }
    next_fallback(order, &unique).map(|next| (next, unique))
}

/// The next backend to try after a failed start, and the list of those that
/// already failed; `None` = give up.
pub fn plan_fallback(choice: BackendChoice) -> Option<(GpuApi, Vec<GpuApi>)> {
    let marker = std::env::var(FALLBACK_ENV).ok();
    let env_backend = std::env::var("WGPU_BACKEND").ok();
    plan(
        &fallback_order(choice),
        marker.as_deref(),
        wgpu::Backends::from_env().is_some(),
        env_backend.as_deref(),
        GpuApi::from_code(LAST_SELECTED.load(Ordering::Relaxed)),
    )
}

/// Starts a new instance of this executable restricted to `next`
/// (`WGPU_BACKEND`), remembering `failed` in `FALLBACK_ENV`.
pub fn relaunch_with(next: GpuApi, failed: &[GpuApi]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env("WGPU_BACKEND", next.env_value())
        .env(FALLBACK_ENV, format_failed(failed))
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------- library probing

/// Result of looking for the system library a backend needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryProbe {
    /// Nothing to check here (a system component, or not applicable).
    NotNeeded,
    Found(&'static str),
    /// None of these could be loaded.
    Missing(&'static [&'static str]),
}

/// The library a backend's loader is opened from at runtime (wgpu doesn't
/// link them, see the package dependencies in `Cargo.toml`).
fn backend_libraries(choice: BackendChoice) -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        match choice {
            BackendChoice::Vulkan => &["libvulkan.so.1"],
            BackendChoice::OpenGl => &["libEGL.so.1"],
            _ => &[],
        }
    }
    #[cfg(target_os = "windows")]
    {
        match choice {
            // Comes with the GPU driver; d3d12.dll and opengl32.dll are
            // part of Windows itself.
            BackendChoice::Vulkan => &["vulkan-1.dll"],
            _ => &[],
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = choice;
        &[]
    }
}

fn probe_libraries(names: &'static [&'static str]) -> LibraryProbe {
    if names.is_empty() {
        return LibraryProbe::NotNeeded;
    }
    for &name in names {
        // Loading runs the library's initializers; these are the loaders
        // wgpu opens itself moments later anyway.
        if unsafe { libloading::Library::new(name) }.is_ok() {
            return LibraryProbe::Found(name);
        }
    }
    LibraryProbe::Missing(names)
}

pub fn probe_backend(choice: BackendChoice) -> LibraryProbe {
    probe_libraries(backend_libraries(choice))
}

/// What to install when the backend's library is missing.
fn missing_library_hint(choice: BackendChoice) -> &'static str {
    #[cfg(target_os = "windows")]
    {
        let _ = choice;
        "Install or update the GPU driver - it provides the Vulkan loader."
    }
    #[cfg(not(target_os = "windows"))]
    {
        match choice {
            BackendChoice::Vulkan => {
                "Install the Vulkan loader (Debian/Ubuntu: libvulkan1, Arch: vulkan-icd-loader)."
            }
            BackendChoice::OpenGl => "Install EGL (Debian/Ubuntu: libegl1, Arch: libglvnd).",
            _ => "",
        }
    }
}

/// What to install when the library is there but wgpu found no adapter.
fn no_adapter_hint(choice: BackendChoice) -> &'static str {
    #[cfg(target_os = "windows")]
    {
        match choice {
            BackendChoice::Vulkan => "No Vulkan device found - install or update the GPU driver.",
            BackendChoice::OpenGl => "No OpenGL device found - install or update the GPU driver.",
            _ => "No DirectX 12 device found.",
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        match choice {
            BackendChoice::Vulkan => {
                "The loader is present but reports no device - install a Vulkan driver \
                 (Debian/Ubuntu: mesa-vulkan-drivers, or your GPU vendor's driver)."
            }
            BackendChoice::OpenGl => {
                "EGL is present but reports no device - install an OpenGL driver \
                 (Debian/Ubuntu: libgl1-mesa-dri, or your GPU vendor's driver)."
            }
            _ => "No device found.",
        }
    }
}

/// One line per selectable backend: whether its library was found, and what
/// to install if not. Used in the startup error report.
pub fn library_report() -> String {
    let mut lines = Vec::new();
    for &choice in BackendChoice::selectable() {
        if choice == BackendChoice::Auto {
            continue;
        }
        match probe_backend(choice) {
            LibraryProbe::NotNeeded => {}
            LibraryProbe::Found(name) => lines.push(format!("{}: {name} found", choice.label())),
            LibraryProbe::Missing(names) => lines.push(format!(
                "{}: {} not found. {}",
                choice.label(),
                names.join(" / "),
                missing_library_hint(choice)
            )),
        }
    }
    lines.join("\n")
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
    /// `Some(value)` while the *user's* `WGPU_BACKEND` is set - it
    /// overrides the setting.
    env_override: Option<String>,
    /// `WGPU_BACKEND` is set at all (by the user or by the fallback): the
    /// adapter list then only holds that backend, so availability of the
    /// others can't be judged from it.
    restricted: bool,
    /// The backends that failed to start before the fallback relaunched
    /// this process (`FALLBACK_ENV`), if it did.
    fallback_failed: Option<String>,
    /// What the system libraries of each backend looked like at startup.
    probes: Vec<(BackendChoice, LibraryProbe)>,
    /// `(is_error, message)` for the last save/restart attempt.
    message: Option<(bool, String)>,
}

/// Whether a backend can be used on this machine, as far as known.
enum Availability {
    Available,
    /// Can't be told (no adapter info, or `WGPU_BACKEND` restricts wgpu).
    Unknown,
    Unavailable(String),
}

impl GraphicsPanel {
    pub fn new(choice: BackendChoice, info: Option<GraphicsInfo>) -> Self {
        let fallback_failed = std::env::var(FALLBACK_ENV).ok();
        let restricted = wgpu::Backends::from_env().is_some();
        // Under the fallback, `WGPU_BACKEND` was set by the app, not by the
        // user, so it isn't presented as an override of their setting.
        let env_override = if restricted && fallback_failed.is_none() {
            Some(std::env::var("WGPU_BACKEND").unwrap_or_else(|_| "set".to_owned()))
        } else {
            None
        };
        let probes = BackendChoice::selectable()
            .iter()
            .map(|&c| (c, probe_backend(c)))
            .collect();
        Self {
            info,
            choice,
            choice_at_start: choice,
            env_override,
            restricted,
            fallback_failed,
            probes,
            message: None,
        }
    }

    /// Whether `candidate` can run here: wgpu enumerated an adapter for it.
    /// If not, the reason names the missing library or driver.
    fn availability(&self, candidate: BackendChoice) -> Availability {
        let Some(wanted) = candidate.wanted_backend() else {
            return Availability::Available;
        };
        let Some(info) = &self.info else {
            return Availability::Unknown;
        };
        if self.restricted {
            return Availability::Unknown;
        }
        if info.all.iter().any(|a| a.backend == wanted) {
            return Availability::Available;
        }
        let probe = self.probes.iter().find(|(c, _)| *c == candidate).map(|(_, p)| p);
        Availability::Unavailable(match probe {
            Some(LibraryProbe::Missing(names)) => format!(
                "{} not found. {}",
                names.join(" / "),
                missing_library_hint(candidate)
            ),
            _ => no_adapter_hint(candidate).to_owned(),
        })
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
                if let Some(failed) = &self.fallback_failed {
                    ui.colored_label(
                        egui::Color32::ORANGE,
                        format!(
                            "Starting on the preferred backend failed ({failed}) - \
                             running on {} as an automatic fallback.",
                            backend_label(info.active.backend),
                        ),
                    );
                } else if self.env_override.is_none() {
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
            let availability: Vec<(BackendChoice, Availability)> = BackendChoice::selectable()
                .iter()
                .map(|&c| (c, self.availability(c)))
                .collect();
            ui.add_enabled_ui(self.env_override.is_none(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (candidate, available) in &availability {
                        let candidate = *candidate;
                        // A backend wgpu found no adapter for can't be newly
                        // chosen; one that is already saved stays visible.
                        let unavailable = matches!(available, Availability::Unavailable(_));
                        let enabled = !unavailable || self.choice == candidate;
                        let mut response = ui.add_enabled(
                            enabled,
                            egui::RadioButton::new(self.choice == candidate, candidate.label()),
                        );
                        if let Availability::Unavailable(reason) = available {
                            response = response.on_hover_text(reason).on_disabled_hover_text(reason);
                        }
                        if response.clicked() && self.choice != candidate {
                            self.choice = candidate;
                            changed = true;
                        }
                    }
                });
            });
            for (candidate, available) in &availability {
                if let Availability::Unavailable(reason) = available {
                    ui.colored_label(
                        egui::Color32::ORANGE,
                        format!("{} is not available here: {reason}", candidate.label()),
                    );
                }
            }
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
                        if let Err(e) = restart(ui.ctx(), self.fallback_failed.is_some()) {
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
/// After an automatic fallback the new instance starts without the
/// backend restriction the fallback set, so the saved setting applies again.
fn restart(ctx: &egui::Context, after_fallback: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut command = std::process::Command::new(exe);
    if after_fallback {
        command.env_remove("WGPU_BACKEND").env_remove(FALLBACK_ENV);
    }
    command.spawn().map_err(|e| e.to_string())?;
    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [BackendChoice; 4] = [
        BackendChoice::Auto,
        BackendChoice::Vulkan,
        BackendChoice::OpenGl,
        BackendChoice::Dx12,
    ];

    #[test]
    fn keys_round_trip_and_aliases_parse() {
        for choice in ALL {
            assert_eq!(BackendChoice::from_key(choice.key()), Some(choice));
        }
        assert_eq!(BackendChoice::from_key(" GL \n"), Some(BackendChoice::OpenGl));
        assert_eq!(BackendChoice::from_key("metal"), None);
        assert_eq!(BackendChoice::from_key(""), None);
    }

    #[test]
    fn auto_ranks_vulkan_then_gl_then_the_rest() {
        let auto = BackendChoice::Auto;
        assert!(auto.backend_rank(Backend::Vulkan) < auto.backend_rank(Backend::Gl));
        assert!(auto.backend_rank(Backend::Gl) < auto.backend_rank(Backend::Dx12));
    }

    #[test]
    fn a_chosen_backend_beats_the_default_order() {
        let dx12 = BackendChoice::Dx12;
        assert_eq!(dx12.backend_rank(Backend::Dx12), 0);
        assert!(dx12.backend_rank(Backend::Dx12) < dx12.backend_rank(Backend::Vulkan));
        // The rest keeps the Auto order behind it.
        assert!(dx12.backend_rank(Backend::Vulkan) < dx12.backend_rank(Backend::Gl));
    }

    #[test]
    fn setting_is_saved_and_loaded_and_unoffered_choices_fall_back() {
        if BackendChoice::selectable().is_empty() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("statorius-cfg-test-{}", std::process::id()));
        // SAFETY: the only test that touches these variables; nothing else
        // in the test binary reads the config location.
        unsafe {
            std::env::set_var("APPDATA", &dir);
            std::env::set_var("XDG_CONFIG_HOME", &dir);
        }

        assert_eq!(BackendChoice::load(), BackendChoice::Auto, "no file yet");
        BackendChoice::OpenGl.save().unwrap();
        assert_eq!(BackendChoice::load(), BackendChoice::OpenGl);

        // Garbage and a choice this platform doesn't offer both mean Auto.
        let path = config_path().unwrap();
        std::fs::write(&path, "nonsense\n").unwrap();
        assert_eq!(BackendChoice::load(), BackendChoice::Auto);
        if !BackendChoice::selectable().contains(&BackendChoice::Dx12) {
            std::fs::write(&path, "dx12\n").unwrap();
            assert_eq!(BackendChoice::load(), BackendChoice::Auto);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    const ORDER: [GpuApi; 3] = [GpuApi::Vulkan, GpuApi::OpenGl, GpuApi::Dx12];

    #[test]
    fn next_fallback_skips_what_failed() {
        assert_eq!(next_fallback(&ORDER, &[]), Some(GpuApi::Vulkan));
        assert_eq!(next_fallback(&ORDER, &[GpuApi::Vulkan]), Some(GpuApi::OpenGl));
        assert_eq!(
            next_fallback(&ORDER, &[GpuApi::Vulkan, GpuApi::Dx12]),
            Some(GpuApi::OpenGl)
        );
        assert_eq!(next_fallback(&ORDER, &ORDER), None);
    }

    #[test]
    fn failed_list_round_trips() {
        let failed = [GpuApi::Vulkan, GpuApi::OpenGl];
        assert_eq!(format_failed(&failed), "vulkan,gl");
        assert_eq!(parse_failed("vulkan,gl"), failed);
        assert_eq!(parse_failed("vk, bogus ,d3d12"), [GpuApi::Vulkan, GpuApi::Dx12]);
        assert!(parse_failed("").is_empty());
    }

    #[test]
    fn the_users_choice_leads_the_fallback_order() {
        let order = fallback_order(BackendChoice::OpenGl);
        if !order.is_empty() {
            assert_eq!(order[0], GpuApi::OpenGl);
            assert!(order.contains(&GpuApi::Vulkan));
        }
    }

    #[test]
    fn fallback_retries_on_the_next_backend_after_a_late_failure() {
        // First run: Vulkan was selected, then the start failed.
        let plan = plan(&ORDER, None, false, None, Some(GpuApi::Vulkan));
        assert_eq!(plan, Some((GpuApi::OpenGl, vec![GpuApi::Vulkan])));
    }

    #[test]
    fn fallback_chain_continues_and_ends() {
        // Relaunched on gl after vulkan failed; gl fails too.
        let next = plan(&ORDER, Some("vulkan"), true, Some("gl"), None);
        assert_eq!(next, Some((GpuApi::Dx12, vec![GpuApi::Vulkan, GpuApi::OpenGl])));
        // Everything has failed.
        assert_eq!(plan(&ORDER, Some("vulkan,gl"), true, Some("dx12"), None), None);
    }

    #[test]
    fn fallback_leaves_a_user_set_backend_alone() {
        assert_eq!(plan(&ORDER, None, true, Some("vulkan"), None), None);
        assert_eq!(plan(&ORDER, None, true, Some("vulkan"), Some(GpuApi::Vulkan)), None);
    }

    #[test]
    fn fallback_needs_a_selected_adapter_on_the_first_run() {
        // Nothing was even selected: no backend can present to the window.
        assert_eq!(plan(&ORDER, None, false, None, None), None);
    }

    #[test]
    fn probing_finds_present_and_reports_absent_libraries() {
        assert_eq!(probe_libraries(&[]), LibraryProbe::NotNeeded);
        static MISSING: [&str; 1] = ["libstatorius-no-such-library.so.9"];
        assert_eq!(probe_libraries(&MISSING), LibraryProbe::Missing(&MISSING));
        #[cfg(target_os = "linux")]
        {
            static PRESENT: [&str; 2] = ["libstatorius-no-such-library.so.9", "libc.so.6"];
            assert_eq!(probe_libraries(&PRESENT), LibraryProbe::Found("libc.so.6"));
        }
    }
}
