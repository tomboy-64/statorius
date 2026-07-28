use std::time::{Duration, Instant};
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::dhcp_state::DhcpState;
use crate::net::l2::L2Readiness;
use crate::net::l2_ipc::L2DuplicateOutcomeWire;
use crate::net::l2_manager::{L2Command, L2JobRequest, L2Status, SharedL2Status};
use crate::net::l2_pinger::{L2PingerCommand, L2PingerState};
use crate::state::{SharedState, WorkerCommand};

mod about_tab;
mod dhcp_tab;
mod interfaces_tab;
mod l2_tab;
mod ping_tab;
mod widgets;

use l2_tab::{render_l2_checkbox, L2InputValidation};

/// Which tab is currently shown. "L2 Ping" is only ever selectable when
/// L2 mode is actually active - see `render_tab_bar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Ping,
    L2Ping,
    Dhcp,
    Interfaces,
    About,
}

pub struct StatoriusApp {
    target_input: String,
    tx: mpsc::Sender<WorkerCommand>,
    state: SharedState,
    last_error: Option<String>,

    active_tab: ActiveTab,

    /// Whether L2 is possible at all as launched, and if not, whether
    /// elevation would plausibly fix it (see `net::l2`) - checked once at
    /// startup, never re-probed, never used to request privileges itself.
    /// Also what gates whether the "L2 Ping" tab itself is selectable.
    l2_readiness: L2Readiness,
    /// Sends Activate/Deactivate to the background `l2_manager_task`, which
    /// owns spawning the (possibly elevated) helper process and its IPC
    /// connection - the GUI never touches a raw socket directly.
    l2_tx: mpsc::Sender<L2Command>,
    /// The manager's live status, read fresh every frame - ground truth for
    /// what the checkbox should show, not a bool we own ourselves.
    l2_status: SharedL2Status,

    // --- L2 Pingers: add-form state ---
    /// The address the user intends to send *from* - this is what gets
    /// live-validated and duplicate-checked, not the target.
    l2_pinger_source_input: String,
    l2_pinger_target_input: String,
    l2_pinger_vlan_input: String,
    l2_pinger_timeout_input: String,
    /// VLANs entered so far this run, offered back as quick-select buttons.
    known_vlans: Vec<u16>,
    l2_pinger_error: Option<String>,
    /// Which (source-IP field, VLAN field) combo `l2_input_validation`
    /// currently reflects - re-validating only happens when this stops
    /// matching the live input, instead of re-checking every single frame.
    l2_input_validated_for: String,
    l2_input_validation: L2InputValidation,
    l2_input_check_rx: Option<oneshot::Receiver<L2DuplicateOutcomeWire>>,

    // --- L2 Pingers: channels/state ---
    l2_pinger_tx: mpsc::Sender<L2PingerCommand>,
    l2_pinger_state: L2PingerState,
    /// Used directly by the add-form's live duplicate-check on whatever's
    /// currently typed - separate from `l2_pinger_tx`, which only ever
    /// controls already-added, tracked pingers.
    l2_job_tx: mpsc::Sender<L2JobRequest>,

    /// Snapshot of every network interface on the machine, for the
    /// "Interfaces" tab. Populated once at startup and on demand via its
    /// "Refresh" button - not re-queried every frame, since interface
    /// enumeration is a real (if cheap) system call and this data rarely
    /// changes mid-session.
    interfaces: Vec<default_net::Interface>,
    interface_update: Instant,
    interfaces_open: Vec::<(bool,bool,bool)>, // (outer is open, inner is open, ip is valid)

    /// Captured DHCP exchanges for the "DHCP" tab - written by
    /// `l2_manager` as they're captured, read via `.snapshot()` every
    /// frame this tab is shown. See `net::dhcp_state`.
    dhcp_state: DhcpState,
    /// Per-transaction collapsing-header open/closed state, keyed by
    /// `xid` - `egui::CollapsingHeader` needs this held outside itself to
    /// stay controllable (open-by-default-until-toggled) the same way
    /// `interfaces_open` does for the Interfaces tab.
    dhcp_open: std::collections::HashMap<u32, bool>,
}

impl StatoriusApp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx: mpsc::Sender<WorkerCommand>,
        state: SharedState,
        l2_readiness: L2Readiness,
        l2_tx: mpsc::Sender<L2Command>,
        l2_status: SharedL2Status,
        l2_pinger_tx: mpsc::Sender<L2PingerCommand>,
        l2_pinger_state: L2PingerState,
        l2_job_tx: mpsc::Sender<L2JobRequest>,
        dhcp_state: DhcpState,
    ) -> Self {
        Self {
            target_input: String::new(),
            tx,
            state,
            last_error: None,
            active_tab: ActiveTab::Ping,
            l2_readiness,
            l2_tx,
            l2_status,
            l2_pinger_source_input: String::new(),
            l2_pinger_target_input: String::new(),
            l2_pinger_vlan_input: String::new(),
            l2_pinger_timeout_input: "1000".to_owned(),
            known_vlans: Vec::new(),
            l2_pinger_error: None,
            l2_input_validated_for: String::new(),
            l2_input_validation: L2InputValidation::Invalid,
            l2_input_check_rx: None,
            l2_pinger_tx,
            l2_pinger_state,
            l2_job_tx,
            interfaces: default_net::get_interfaces(),
            interface_update: Instant::now(),
            interfaces_open: Vec::new(),
            dhcp_state,
            dhcp_open: std::collections::HashMap::new(),
        }
    }
}

impl eframe::App for StatoriusApp {
    // eframe 0.35 split the old single `update(ctx, frame)` into an optional
    // `logic()` (no UI allowed) and this required `ui()`, which is handed the
    // root viewport's `Ui` directly instead of a `Context`. Panel builders
    // (`CentralPanel`, `Grid`, `ScrollArea`, ...) now take `&mut Ui` uniformly.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            render_tab_bar(
                ui,
                &mut self.active_tab,
                &self.l2_readiness,
                &self.l2_status,
                &self.l2_tx,
            );
            ui.separator();

            match self.active_tab {
                ActiveTab::Ping => self.ui_ping_tab(ui),
                ActiveTab::L2Ping => self.ui_l2_ping_tab(ui),
                ActiveTab::Dhcp => self.ui_dhcp_tab(ui),
                ActiveTab::Interfaces => (&mut*self).ui_interfaces_tab(ui),
                ActiveTab::About => (&mut*self).ui_about_tab(ui),
            }
        });

        // The workers update shared state from background tokio tasks with
        // no way to wake the UI directly, so we poll on a steady tick
        // instead of relying solely on input-driven repaints. `ui.ctx()`
        // gets us back to the `Context` now that `update`'s `ctx` parameter
        // is gone.
        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
}

/// The Ping / L2 Ping tab bar, plus the "L2 mode" activation control
/// right-aligned in the same row. "L2 Ping" is only selectable once L2 mode
/// is actually `Active` - not merely theoretically possible - so there's
/// nothing to show a "not activated yet" message for on the tab itself
/// anymore (that used to live in `ui_l2_ping_tab`); flipping the checkbox
/// here is now the only way in or out of that tab being reachable at all.
fn render_tab_bar(
    ui: &mut egui::Ui,
    active_tab: &mut ActiveTab,
    readiness: &L2Readiness,
    l2_status: &SharedL2Status,
    l2_tx: &mpsc::Sender<L2Command>,
) {
    let l2_tab_enabled = matches!(l2_status.get(), L2Status::Active { .. });
    // If L2 mode gets deactivated (or fails) while the L2 Ping or DHCP tab
    // happens to be selected, fall back to the Ping tab rather than leaving
    // the user stranded on a tab that's no longer clickable. DHCP capture
    // rides on the same raw-capture helper as L2 Ping, so it's gated
    // identically.
    if !l2_tab_enabled && (*active_tab == ActiveTab::L2Ping || *active_tab == ActiveTab::Dhcp) {
        *active_tab = ActiveTab::Ping;
    }

    ui.horizontal(|ui| {
        if ui
            .selectable_label(*active_tab == ActiveTab::Ping, "Ping")
            .clicked()
        {
            *active_tab = ActiveTab::Ping;
        }

        let l2_tab_hover = match readiness {
            L2Readiness::Unavailable { detail }
            | L2Readiness::Ready { detail }
            | L2Readiness::NeedsElevation { detail } => detail.clone(),
        };
        // `SelectableLabel` isn't a standalone widget struct in this egui
        // version - `selectable_label` only exists as a `Ui` convenience
        // method - so `add_enabled_ui` (which wraps a whole closure in the
        // disabled visual state) replaces the `add_enabled(widget)` pattern
        // used for the plain checkbox above.
        let l2_tab_resp = ui
            .add_enabled_ui(l2_tab_enabled, |ui| {
                ui.selectable_label(*active_tab == ActiveTab::L2Ping, "L2 Ping")
            })
            .inner
            .on_hover_text(l2_tab_hover.clone());
        if l2_tab_resp.clicked() {
            *active_tab = ActiveTab::L2Ping;
        }

        // Same gating as "L2 Ping" above, and the same reason: reading DHCP
        // traffic needs the raw capture the elevated helper provides, so
        // there's nothing this tab could show until that's active.
        let dhcp_tab_resp = ui
            .add_enabled_ui(l2_tab_enabled, |ui| {
                ui.selectable_label(*active_tab == ActiveTab::Dhcp, "DHCP")
            })
            .inner
            .on_hover_text(l2_tab_hover.clone());
        if dhcp_tab_resp.clicked() {
            *active_tab = ActiveTab::Dhcp;
        }

        // Pure read-only enumeration, no privileges needed either way - so
        // unlike "L2 Ping", this tab is never disabled.
        if ui
            .selectable_label(*active_tab == ActiveTab::Interfaces, "Interfaces")
            .clicked()
        {
            *active_tab = ActiveTab::Interfaces;
        }

        if ui
            .selectable_label(*active_tab == ActiveTab::About, "About")
            .clicked()
        {
            *active_tab = ActiveTab::About;
        }

        // Right-aligned in the remaining space of this same row - add the
        // left-hand tabs first, then let this claim what's left from the
        // right edge inward, rather than giving it its own row.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            render_l2_checkbox(ui, readiness, l2_status, l2_tx);
        });
    });
}