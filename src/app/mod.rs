use std::time::{Duration, Instant};
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::dhcp_state::DhcpState;
use crate::net::dns::{DnsCommand, SharedDnsServers};
use crate::net::dns_query::{QueryOutcome, TraceOutcome};
use crate::net::l2::L2Readiness;
use crate::net::l2_ipc::L2DuplicateOutcomeWire;
use crate::net::l2_manager::{L2Command, L2JobRequest, L2Status, SharedL2Status};
use crate::net::l2_pinger::{L2PingerCommand, L2PingerState};
use crate::state::{SharedState, WorkerCommand};
use hickory_resolver::proto::rr::RecordType;

mod about_tab;
mod dhcp_tab;
mod dns_tab;
mod interfaces_tab;
mod l2_tab;
mod ping_tab;
mod widgets;

use l2_tab::{render_l2_checkbox, L2InputValidation};
use ping_tab::PingListLoadState;

/// Which tab is currently shown. "L2 Ping" is only ever selectable when
/// L2 mode is actually active - see `render_tab_bar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Ping,
    L2Ping,
    Dhcp,
    Interfaces,
    Dns,
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
    /// `Some` while a background `default_net::get_interfaces()` call is in
    /// flight - see `interfaces_tab::start_interfaces_refresh`. Never
    /// called directly on the UI thread.
    interfaces_refresh_rx: Option<oneshot::Receiver<Vec<default_net::Interface>>>,

    /// Captured DHCP exchanges for the "DHCP" tab - written by
    /// `l2_manager` as they're captured, read via `.snapshot()` every
    /// frame this tab is shown. See `net::dhcp_state`.
    dhcp_state: DhcpState,
    /// Per-transaction collapsing-header open/closed state, keyed by
    /// `xid` - `egui::CollapsingHeader` needs this held outside itself to
    /// stay controllable (open-by-default-until-toggled) the same way
    /// `interfaces_open` does for the Interfaces tab.
    dhcp_open: std::collections::HashMap<u32, bool>,

    /// The OS's currently-configured DNS servers, refreshed in the
    /// background every 10s - read fresh every frame for the "DNS" tab,
    /// same as `l2_status`/`dhcp_state`. See `net::dns`.
    dns_shared: SharedDnsServers,
    /// Sends one-off `DnsCommand::Resolve`/`Query`/`Trace` jobs to the
    /// background `dns_worker` task - `Resolve` is used by the Ping tab
    /// when Enter is pressed on something that isn't already a literal IP
    /// address; `Query`/`Trace` by the DNS tab's own Query panel.
    dns_tx: mpsc::Sender<DnsCommand>,
    /// Which of `dns_shared`'s servers are checked in the "DNS" tab, keyed
    /// by address so a selection survives the list being refreshed out
    /// from under it. A server not yet in this map (just discovered)
    /// defaults to checked/selected.
    dns_selected: std::collections::HashMap<std::net::IpAddr, bool>,
    /// The hostname lookup currently in flight for the Ping tab, if any -
    /// `Some` disables re-submitting until it resolves one way or the
    /// other.
    dns_resolve_rx: Option<oneshot::Receiver<Result<Vec<std::net::IpAddr>, String>>>,
    /// The exact text that was submitted for the in-flight lookup above -
    /// used to attribute the reply (success or failure) back to it.
    dns_resolve_target: String,
    /// `Some(text)` when `text` (as typed into `target_input` at the time)
    /// failed DNS resolution - the Ping tab renders `target_input` in red
    /// for exactly as long as it still equals this, and clears back to
    /// normal the moment the user types anything else.
    dns_failed_for: Option<String>,
    /// Servers added by hand on the DNS tab (the "+" field), on top of
    /// whatever `dns_shared` reports the OS has configured. Never touched
    /// by the 10s background refresh - only removed by the user's own "x"
    /// button, or implicitly by loading a `.dns` file that doesn't mention
    /// them.
    dns_manual_servers: Vec<std::net::IpAddr>,
    /// Live text of the DNS tab's "add a server" field.
    dns_add_input: String,
    /// Set when `dns_add_input` didn't parse as an IP address; rendered in
    /// red under the add field, cleared on the next successful add.
    dns_add_error: Option<String>,
    /// `Some(filename-in-progress)` while the "save as" field is open;
    /// `None` otherwise. Only one of this and `dns_load_input` is open at a
    /// time.
    dns_save_input: Option<String>,
    /// `Some(filename-in-progress)` while the "open" field is open; `None`
    /// otherwise.
    dns_load_input: Option<String>,
    /// Result of the last save/load attempt, shown under the 💾/📁 row
    /// until the next one replaces it - `(is_error, message)`.
    dns_io_message: Option<(bool, String)>,

    // --- DNS tab: Query panel ---
    /// Live text of the Query panel's "name" field.
    dns_query_input: String,
    /// Selected record type in the panel's dropdown.
    dns_query_type: RecordType,
    dns_query_use_tcp: bool,
    dns_query_recursion_desired: bool,
    dns_query_dnssec_ok: bool,
    dns_query_checking_disabled: bool,
    /// dig's `+trace` - see `dns_query::trace` for what this changes about
    /// where the query actually goes.
    dns_query_trace: bool,
    /// `Some` while a plain (non-trace) query is in flight - only one of
    /// this and `dns_trace_rx` is ever `Some` at a time, same pattern as
    /// `dns_save_input`/`dns_load_input` above.
    dns_query_rx: Option<oneshot::Receiver<Vec<QueryOutcome>>>,
    /// `Some` while a `+trace` job is in flight.
    dns_trace_rx: Option<oneshot::Receiver<TraceOutcome>>,
    /// The last completed (non-trace) query's per-server results -
    /// replaced each time a new one finishes; `None` until the first one
    /// does.
    dns_query_results: Option<Vec<QueryOutcome>>,
    /// The last completed `+trace`'s hops - same idea, for trace jobs.
    dns_trace_result: Option<TraceOutcome>,
    /// Set when the Query panel couldn't even submit a job (an empty name
    /// field, no servers checked for a non-trace query, or a full command
    /// channel) - shown in red under the option row. Per-server/per-hop
    /// failures of a job that *did* submit are shown inline with that
    /// server/hop instead, not here.
    dns_query_error: Option<String>,

    /// `Some(filename-in-progress)` while the Ping tab's "save as" field is
    /// open for the target list; `None` otherwise. Only one of this and
    /// `ping_list_load_input` is open at a time - same pattern as the DNS
    /// tab's save/load pair.
    ping_list_save_input: Option<String>,
    /// `Some(filename-in-progress)` while the Ping tab's "open" field is
    /// open for the target list; `None` otherwise.
    ping_list_load_input: Option<String>,
    /// Result of the last target-list save/load attempt, shown the same
    /// way `dns_io_message` is - `(is_error, message)`.
    ping_list_io_message: Option<(bool, String)>,
    /// `Some` while a `.ips` file load is draining its queue of hostnames
    /// still needing DNS resolution - see `ping_tab::poll_ping_list_load`.
    ping_list_load_state: Option<PingListLoadState>,
    /// Set once a `.ips` load finishes with at least one entry that was
    /// neither a valid IP nor a resolvable hostname - each already
    /// formatted as `"<entry>: <reason>"`. Drives the error window; `None`
    /// means nothing to show.
    ping_list_errors: Option<Vec<String>>,
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
        dns_shared: SharedDnsServers,
        dns_tx: mpsc::Sender<DnsCommand>,
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
            interfaces_refresh_rx: None,
            dhcp_state,
            dhcp_open: std::collections::HashMap::new(),
            dns_shared,
            dns_tx,
            dns_selected: std::collections::HashMap::new(),
            dns_resolve_rx: None,
            dns_resolve_target: String::new(),
            dns_failed_for: None,
            dns_manual_servers: Vec::new(),
            dns_add_input: String::new(),
            dns_add_error: None,
            dns_save_input: None,
            dns_load_input: None,
            dns_io_message: None,
            dns_query_input: String::new(),
            dns_query_type: RecordType::A,
            dns_query_use_tcp: false,
            dns_query_recursion_desired: true,
            dns_query_dnssec_ok: false,
            dns_query_checking_disabled: false,
            dns_query_trace: false,
            dns_query_rx: None,
            dns_trace_rx: None,
            dns_query_results: None,
            dns_trace_result: None,
            dns_query_error: None,
            ping_list_save_input: None,
            ping_list_load_input: None,
            ping_list_io_message: None,
            ping_list_load_state: None,
            ping_list_errors: None,
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
                ActiveTab::Dns => self.ui_dns_tab(ui),
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

        // Also just a local read (resolv.conf / the registry) - no
        // privileges needed, never disabled.
        if ui
            .selectable_label(*active_tab == ActiveTab::Dns, "DNS")
            .clicked()
        {
            *active_tab = ActiveTab::Dns;
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