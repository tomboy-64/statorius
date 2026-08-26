use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use eframe::egui;
use tokio::sync::{mpsc, oneshot};

use crate::net::dns::DnsCommand;
use crate::state::{PingEntry, PingMethod, PingRequest, WorkerCommand, DEFAULT_ICMP_PAYLOAD_SIZE};

use super::widgets::{render_average_indicator, render_last_indicator, render_since_indicator};
use super::{PingMethodChoice, StatoriusApp};

/// Sweeping a subnet larger than this via `a.b.c.d/n` in the target box is
/// refused outright (with a specific error) rather than silently expanding
/// into thousands of continuous pingers from a typo'd prefix length.
const MAX_SWEEP_HOSTS: u64 = 512;

/// Port a UDP ping uses when the Port field is left empty at submit time -
/// DNS, since it's the most common thing worth a quick "is this open"
/// UDP check. TCP has no equivalent default; a fixed port there would be
/// far more likely to silently probe the wrong service than to guess
/// right, so it's left as a required field instead.
const DEFAULT_UDP_PORT: u16 = 53;

/// Line ending used when *writing* a `.ips` file - matches the platform's
/// own convention (Notepad and friends still care on Windows). Reading
/// never needs the counterpart of this: `str::lines()` already treats a
/// trailing `\r` before `\n` as part of the line ending, so a file saved on
/// one platform loads back cleanly on the other without any special-casing
/// here.
#[cfg(windows)]
const NATIVE_NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
const NATIVE_NEWLINE: &str = "\n";

/// Progress of an in-flight `.ips` file load. Entries that already parse as
/// literal IPs are resolved immediately - no DNS round trip needed at all -
/// while anything else is queued here and resolved one hostname at a time
/// against the same DNS servers the Ping tab's own single-hostname lookups
/// use. There's only ever one `dns_worker` request in flight per
/// `StatoriusApp`, so a whole file of hostnames drains sequentially rather
/// than fanning out in parallel.
pub(super) struct PingListLoadState {
    /// For the final summary message and the error window's title.
    path: PathBuf,
    /// Hostnames still waiting their turn.
    queue: VecDeque<String>,
    /// The one lookup currently running, if any, plus which hostname it's
    /// for - needed to attribute the reply, and to name it on failure.
    in_flight: Option<(String, oneshot::Receiver<Result<Vec<IpAddr>, String>>)>,
    /// Every address collected so far: literal IPs read straight from the
    /// file, plus whatever the queue has resolved as it drains.
    resolved: Vec<IpAddr>,
    /// `"<entry>: <reason>"` for every line that was neither a valid IP nor
    /// a hostname that resolved. The reason is always the resolver's own
    /// error message (or the specific local failure, e.g. a full send
    /// queue) - never invented here, per the request that these be
    /// accurate rather than generic.
    errors: Vec<String>,
}

impl StatoriusApp {
    /// Builds a `PingMethod` from the Method selector and its associated
    /// port/size field, exactly as currently typed. An empty port defaults
    /// to `DEFAULT_UDP_PORT` for UDP; TCP has no such default and errors
    /// instead, same as an empty/non-numeric payload size or TCP port
    /// always has.
    fn current_ping_method(&self) -> Result<PingMethod, String> {
        match self.ping_method_choice {
            PingMethodChoice::Icmp => {
                let text = self.ping_icmp_size_input.trim();
                let payload_size: usize = if text.is_empty() {
                    DEFAULT_ICMP_PAYLOAD_SIZE
                } else {
                    text.parse()
                        .map_err(|_| format!("'{text}' isn't a valid ICMP payload size"))?
                };
                Ok(PingMethod::Icmp { payload_size })
            }
            PingMethodChoice::Tcp => {
                let text = self.ping_port_input.trim();
                let port: u16 = text
                    .parse()
                    .map_err(|_| format!("'{text}' isn't a valid port number"))?;
                Ok(PingMethod::Tcp { port })
            }
            PingMethodChoice::Udp => {
                let text = self.ping_port_input.trim();
                let port: u16 = if text.is_empty() {
                    DEFAULT_UDP_PORT
                } else {
                    text.parse().map_err(|_| format!("'{text}' isn't a valid port number"))?
                };
                Ok(PingMethod::Udp { port })
            }
        }
    }

    /// Parses the Count field - empty means unlimited (`None`), matching
    /// the only behavior that existed before this field did.
    fn current_ping_count(&self) -> Result<Option<u32>, String> {
        let text = self.ping_count_input.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let count: u32 =
            text.parse().map_err(|_| format!("'{text}' isn't a valid ping count"))?;
        if count == 0 {
            return Err("Count must be at least 1".to_owned());
        }
        Ok(Some(count))
    }

    /// Starts (or restarts) continuous pinging of whatever is currently
    /// typed into the input box, using the Method/port-or-size/Count fields
    /// alongside it. Each comma-separated part is expanded on its own: a
    /// literal IP starts immediately, a CIDR range (`a.b.c.d/n`) expands
    /// into every host address in it and starts all of them, and anything
    /// that looks like neither falls back to the whole input being tried as
    /// a single hostname - a background DNS lookup is kicked off (see
    /// `poll_dns_resolution`) rather than pinging anything yet, the
    /// resolved address(es) replace the input, and the user submits again
    /// to actually start the ping(s). (Mixing a hostname with literal
    /// IPs/CIDRs in the same submission isn't supported, same as before
    /// CIDR expansion existed - the whole input either is entirely
    /// IP/CIDR-shaped, or is tried as one hostname.)
    fn submit_ping_target(&mut self) {
        let trimmed = self.target_input.trim().to_owned();

        let parts: Vec<&str> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let expanded: Vec<Option<Result<Vec<IpAddr>, String>>> =
            parts.iter().map(|p| expand_target_part(p)).collect();

        if !expanded.is_empty() && expanded.iter().all(Option::is_some) {
            // Every part at least looks like a literal IP or a CIDR range -
            // resolve them all locally, no DNS needed.
            let mut targets = Vec::new();
            for outcome in expanded.into_iter().flatten() {
                match outcome {
                    Ok(addrs) => targets.extend(addrs),
                    Err(e) => {
                        self.last_error = Some(e);
                        return;
                    }
                }
            }

            let method = match self.current_ping_method() {
                Ok(m) => m,
                Err(e) => {
                    self.last_error = Some(e);
                    return;
                }
            };
            let count = match self.current_ping_count() {
                Ok(c) => c,
                Err(e) => {
                    self.last_error = Some(e);
                    return;
                }
            };

            self.last_error = None;
            self.dns_failed_for = None;
            let mut failures = Vec::new();
            for target in targets {
                let request =
                    PingRequest { target, method: method.clone(), count };
                if let Err(e) = self.tx.try_send(WorkerCommand::Start(request)) {
                    failures.push(format!("{target}: {e}"));
                }
            }
            if !failures.is_empty() {
                self.last_error = Some(format!("Failed to queue: {}", failures.join("; ")));
            }
            return;
        }

        // Not (all) literal IPs/CIDRs - try the whole input as a hostname.
        // A lookup already in flight for a previous entry gets to finish
        // first; re-pressing Enter/Ping while waiting is a no-op rather
        // than firing off a second, overlapping request.
        if self.dns_resolve_rx.is_some() {
            return;
        }
        self.last_error = None;

        let servers: Vec<IpAddr> = self
            .dns_shared
            .get()
            .into_iter()
            .filter(|ip| *self.dns_selected.get(ip).unwrap_or(&true))
            .collect();

        let (respond_to, rx) = oneshot::channel();
        let command = DnsCommand::Resolve { name: trimmed.clone(), servers, respond_to };
        if self.dns_tx.try_send(command).is_ok() {
            self.dns_resolve_rx = Some(rx);
            self.dns_resolve_target = trimmed;
        } else {
            self.dns_failed_for = Some(trimmed);
        }
    }

    /// Checks whether the in-flight hostname lookup (if any) has finished,
    /// and applies its result: on success, `target_input` is replaced with
    /// every resolved A/AAAA address (comma-separated); on failure,
    /// `dns_failed_for` is set so the input renders in red until the user
    /// edits it. Called once per frame from `ui_ping_tab`, the same way the
    /// L2 tab polls its own duplicate-check oneshot.
    fn poll_dns_resolution(&mut self) {
        let Some(rx) = &mut self.dns_resolve_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(addrs)) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = None;
                self.target_input = addrs
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
            }
            Ok(Err(_reason)) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = Some(self.dns_resolve_target.clone());
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                self.dns_resolve_rx = None;
                self.dns_failed_for = Some(self.dns_resolve_target.clone());
            }
        }
    }

    /// Writes every currently-known target (running or paused - everything
    /// `snapshot()` returns), one literal IP per line, to `filename`
    /// (appending `.ips` if it doesn't already end in that) in the same
    /// directory as the running executable. Always literal IPs, never
    /// hostnames - resolving is strictly a *load*-time concern, so a saved
    /// file is exactly what a fresh load of it would reproduce with zero
    /// DNS activity.
    fn save_ping_targets(&mut self, filename: &str) {
        let filename = normalize_ping_list_filename(filename.trim());
        let Some(path) = ping_list_file_path(&filename) else {
            self.ping_list_io_message = Some((
                true,
                "Could not determine the program's directory".to_owned(),
            ));
            return;
        };

        let targets: Vec<IpAddr> = self.state.snapshot().into_iter().map(|e| e.target).collect();
        let contents =
            targets.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(NATIVE_NEWLINE);

        match std::fs::write(&path, contents) {
            Ok(()) => {
                self.ping_list_io_message = Some((
                    false,
                    format!("Saved {} target(s) to {}", targets.len(), path.display()),
                ));
                self.ping_list_save_input = None;
            }
            Err(e) => {
                self.ping_list_io_message =
                    Some((true, format!("Failed to save '{}': {e}", path.display())));
            }
        }
    }

    /// Reads `filename` (appending `.ips` if needed) and kicks off loading
    /// it: every line that parses as a literal IPv4/IPv6 address is used as
    /// is, and everything else is queued to be resolved as a hostname (both
    /// A and AAAA - see `net::dns::resolve`) by `poll_ping_list_load` over
    /// the following frames. Nothing is actually started as a ping target
    /// yet - that only happens once the whole file has finished draining,
    /// so a file of several hostnames doesn't start pinging some of them
    /// noticeably before others.
    fn load_ping_targets(&mut self, filename: &str) {
        let filename = normalize_ping_list_filename(filename.trim());
        let Some(path) = ping_list_file_path(&filename) else {
            self.ping_list_io_message = Some((
                true,
                "Could not determine the program's directory".to_owned(),
            ));
            return;
        };

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.ping_list_io_message =
                    Some((true, format!("Failed to open '{}': {e}", path.display())));
                return;
            }
        };

        let mut resolved = Vec::new();
        let mut queue = VecDeque::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<IpAddr>() {
                Ok(ip) => resolved.push(ip),
                Err(_) => queue.push_back(line.to_owned()),
            }
        }

        self.ping_list_load_input = None;
        self.ping_list_io_message = None;
        self.ping_list_load_state = Some(PingListLoadState {
            path,
            queue,
            in_flight: None,
            resolved,
            errors: Vec::new(),
        });
    }

    /// Drives an in-progress `.ips` load, one step per frame: checks the
    /// current lookup (if any) for a reply, starts the next queued
    /// hostname's lookup once the previous one is done, and - once both the
    /// queue and any in-flight lookup are empty - finalizes the batch:
    /// every resolved address (literal IPs from the file plus everything
    /// the queue resolved) is started as a ping target, and if anything
    /// failed to parse or resolve, `ping_list_errors` is set so the error
    /// window renders with the specific reason for each.
    fn poll_ping_list_load(&mut self) {
        // Step 1: check the current in-flight lookup, if any, for a reply.
        if let Some(load) = &mut self.ping_list_load_state {
            if let Some((name, rx)) = &mut load.in_flight {
                match rx.try_recv() {
                    Ok(Ok(addrs)) => {
                        load.resolved.extend(addrs);
                        load.in_flight = None;
                    }
                    Ok(Err(reason)) => {
                        load.errors.push(format!("{name}: {reason}"));
                        load.in_flight = None;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => return,
                    Err(oneshot::error::TryRecvError::Closed) => {
                        load.errors
                            .push(format!("{name}: lookup channel closed unexpectedly"));
                        load.in_flight = None;
                    }
                }
            }
        }

        // Step 2: nothing in flight - start the next queued hostname, if
        // any. Kept as its own step (rather than nested in step 1's borrow)
        // since it needs `self.dns_shared`/`dns_selected`/`dns_tx` too.
        let next_name = match &mut self.ping_list_load_state {
            Some(load) if load.in_flight.is_none() => load.queue.pop_front(),
            _ => None,
        };
        if let Some(name) = next_name {
            let servers: Vec<IpAddr> = self
                .dns_shared
                .get()
                .into_iter()
                .filter(|ip| *self.dns_selected.get(ip).unwrap_or(&true))
                .collect();
            let (respond_to, rx) = oneshot::channel();
            let command = DnsCommand::Resolve {
                name: name.clone(),
                servers,
                respond_to,
            };
            let send_ok = self.dns_tx.try_send(command).is_ok();

            let load = self
                .ping_list_load_state
                .as_mut()
                .expect("just matched Some above");
            if send_ok {
                load.in_flight = Some((name, rx));
            } else {
                load.errors.push(format!("{name}: DNS worker unavailable"));
            }
            return;
        }

        // Step 3: queue drained and nothing in flight - finalize, if
        // there's actually a load in progress at all.
        let done = matches!(
            &self.ping_list_load_state,
            Some(load) if load.in_flight.is_none() && load.queue.is_empty()
        );
        if done {
            let load = self.ping_list_load_state.take().expect("checked Some above");
            let mut failures = Vec::new();
            for target in &load.resolved {
                let request = PingRequest {
                    target: *target,
                    method: PingMethod::Icmp { payload_size: DEFAULT_ICMP_PAYLOAD_SIZE },
                    count: None,
                };
                if let Err(e) = self.tx.try_send(WorkerCommand::Start(request)) {
                    failures.push(format!("{target}: {e}"));
                }
            }

            self.ping_list_io_message = Some((
                false,
                format!(
                    "Loaded {} target(s) from {}",
                    load.resolved.len(),
                    load.path.display()
                ),
            ));

            let mut errors = load.errors;
            errors.extend(failures);
            if !errors.is_empty() {
                self.ping_list_errors = Some(errors);
            }
        }
    }

    pub(super) fn ui_ping_tab(&mut self, ui: &mut egui::Ui) {
        self.poll_dns_resolution();
        self.poll_ping_list_load();

        // The failed-lookup highlight only applies to the exact text that
        // failed - the moment the user types anything else, this clears on
        // its own without needing an explicit "dismiss" action.
        if self.dns_failed_for.as_deref() != Some(self.target_input.as_str()) {
            self.dns_failed_for = None;
        }

        ui.horizontal(|ui| {
            ui.label("Target IP or hostname:");

            let is_resolving = self.dns_resolve_rx.is_some();
            let is_failed = self.dns_failed_for.is_some();
            let text_edit = egui::TextEdit::singleline(&mut self.target_input)
                .text_color_opt(is_failed.then_some(egui::Color32::RED));
            let response = ui.add_enabled(!is_resolving, text_edit);

            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let clicked = ui.add_enabled(!is_resolving, egui::Button::new("Ping")).clicked();
            if (clicked || enter_pressed) && !self.target_input.trim().is_empty() {
                self.submit_ping_target();
            }

            if is_resolving {
                ui.weak("resolving\u{2026}");
            }

            // Save/load icons for the target list, right-aligned in the
            // same row - same 💾/📁 pattern as the DNS Servers tab, just
            // against `.ips` files (one literal IP per line) instead of
            // `.dns` files.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let open_load = ui
                    .button(egui::RichText::new("\u{1F4C1}").size(26.0)) // 📁
                    .on_hover_text("Load a target list from a .ips file")
                    .clicked();
                let open_save = ui
                    .button(egui::RichText::new("\u{1F4BE}").size(26.0)) // 💾
                    .on_hover_text("Save the current target list to a .ips file")
                    .clicked();
                if open_save {
                    self.ping_list_load_input = None;
                    self.ping_list_save_input = Some(String::new());
                }
                if open_load {
                    self.ping_list_save_input = None;
                    self.ping_list_load_input = Some(String::new());
                }
            });
        });

        ui.horizontal(|ui| {
            ui.label("Method:");
            egui::ComboBox::from_id_salt("ping_method_choice")
                .selected_text(match self.ping_method_choice {
                    PingMethodChoice::Icmp => "ICMP",
                    PingMethodChoice::Tcp => "TCP",
                    PingMethodChoice::Udp => "UDP",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.ping_method_choice, PingMethodChoice::Icmp, "ICMP");
                    ui.selectable_value(&mut self.ping_method_choice, PingMethodChoice::Tcp, "TCP");
                    ui.selectable_value(&mut self.ping_method_choice, PingMethodChoice::Udp, "UDP");
                });

            match self.ping_method_choice {
                PingMethodChoice::Icmp => {
                    ui.label("Payload size:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ping_icmp_size_input)
                            .desired_width(50.0)
                            .hint_text(DEFAULT_ICMP_PAYLOAD_SIZE.to_string()),
                    )
                        .on_hover_text(
                            "Bytes of ICMP payload per echo request - the default matches classic \
                         `ping`. A larger size can help surface fragmentation/MTU issues along \
                         the path.",
                        );
                }
                PingMethodChoice::Tcp => {
                    ui.label("Port:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ping_port_input)
                            .desired_width(50.0)
                            .hint_text("e.g. 443"),
                    )
                        .on_hover_text("Required - there's no default TCP port.");
                }
                PingMethodChoice::Udp => {
                    ui.label("Port:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ping_port_input)
                            .desired_width(50.0)
                            .hint_text(DEFAULT_UDP_PORT.to_string()),
                    )
                        .on_hover_text(format!("Defaults to {DEFAULT_UDP_PORT} (DNS) if left empty."));
                }
            }

            ui.label("Count:");
            ui.add(
                egui::TextEdit::singleline(&mut self.ping_count_input)
                    .desired_width(40.0)
                    .hint_text("\u{221e}"), // ∞
            )
                .on_hover_text("Stop automatically after this many attempts. Empty = unlimited.");

            ui.label("Target box also takes a subnet, e.g. 192.168.1.0/24");
        });

        if let Some(err) = &self.last_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        let mut save_now: Option<String> = None;
        let mut cancel_save = false;
        if let Some(name) = &mut self.ping_list_save_input {
            ui.horizontal(|ui| {
                ui.label("Save as:");
                let response = ui.add(
                    egui::TextEdit::singleline(name)
                        .desired_width(200.0)
                        .hint_text("filename"),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Save").clicked() || enter_pressed {
                    save_now = Some(name.clone());
                }
                if ui.small_button("Cancel").clicked() {
                    cancel_save = true;
                }
            });
        }
        if cancel_save {
            self.ping_list_save_input = None;
        }
        if let Some(name) = save_now {
            self.save_ping_targets(&name);
        }

        let mut load_now: Option<String> = None;
        let mut cancel_load = false;
        if let Some(name) = &mut self.ping_list_load_input {
            ui.horizontal(|ui| {
                ui.label("Open:");
                let response = ui.add(
                    egui::TextEdit::singleline(name)
                        .desired_width(200.0)
                        .hint_text("filename"),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Open").clicked() || enter_pressed {
                    load_now = Some(name.clone());
                }
                if ui.small_button("Cancel").clicked() {
                    cancel_load = true;
                }
            });
        }
        if cancel_load {
            self.ping_list_load_input = None;
        }
        if let Some(name) = load_now {
            self.load_ping_targets(&name);
        }

        if let Some(load) = &self.ping_list_load_state {
            let remaining = load.queue.len() + load.in_flight.is_some() as usize;
            ui.weak(format!("loading target list\u{2026} ({remaining} left)"));
        }

        if let Some((is_error, message)) = &self.ping_list_io_message {
            let color = if *is_error {
                egui::Color32::RED
            } else {
                egui::Color32::from_rgb(60, 170, 60)
            };
            ui.colored_label(color, message);
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

        // Error window: only ever shown after a file load finishes with at
        // least one entry that was neither a valid IP nor a resolvable
        // hostname. Non-modal (doesn't block the rest of the UI) - closing
        // it (either the titlebar X or the OK button) just dismisses it,
        // the successfully-resolved targets from the same load have
        // already been started regardless.
        if let Some(errors) = self.ping_list_errors.clone() {
            let mut still_open = true;
            let mut close_via_button = false;
            egui::Window::new("Some entries could not be loaded")
                .collapsible(false)
                .resizable(true)
                .default_width(420.0)
                .open(&mut still_open)
                .show(ui.ctx(), |ui| {
                    let count = errors.len();
                    ui.label(format!(
                        "{count} entr{} could not be added:",
                        if count == 1 { "y" } else { "ies" }
                    ));
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                        for err in &errors {
                            ui.colored_label(egui::Color32::RED, err);
                        }
                    });
                    ui.add_space(8.0);
                    if ui.button("OK").clicked() {
                        close_via_button = true;
                    }
                });
            if !still_open || close_via_button {
                self.ping_list_errors = None;
            }
        }
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
                    count: entry.count,
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

/// Appends `.ips` unless `name` already ends in it.
fn normalize_ping_list_filename(name: &str) -> String {
    if name.ends_with(".ips") {
        name.to_owned()
    } else {
        format!("{name}.ips")
    }
}

/// Resolves `filename` against the directory the running executable lives
/// in - same convention `dns_tab` uses for `.dns` files.
fn ping_list_file_path(filename: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(filename))
}

/// One comma-separated part of the target box, expanded into its literal
/// address(es) - a single IP, or every host address in a CIDR range.
/// Returns `None` (not `Err`) for anything that isn't IP/CIDR shaped at
/// all, since that's `submit_ping_target`'s cue to fall back to DNS
/// resolution instead of treating this as a mistyped range - only a part
/// that clearly *looks* like a CIDR but is malformed or too large produces
/// an actual error, since silently trying to resolve "10.0.0.0/33" as a
/// hostname would be a worse experience than saying why it didn't work.
fn expand_target_part(part: &str) -> Option<Result<Vec<IpAddr>, String>> {
    if let Ok(ip) = part.parse::<IpAddr>() {
        return Some(Ok(vec![ip]));
    }
    let (base, len) = part.split_once('/')?;
    let Ok(base_ip) = base.trim().parse::<IpAddr>() else {
        return None; // doesn't look like a CIDR after all
    };
    let Ok(prefix_len) = len.trim().parse::<u8>() else {
        return Some(Err(format!("'{part}': invalid prefix length")));
    };
    Some(expand_cidr(base_ip, prefix_len))
}

fn expand_cidr(base: IpAddr, prefix_len: u8) -> Result<Vec<IpAddr>, String> {
    match base {
        IpAddr::V4(v4) => expand_cidr_v4(v4, prefix_len),
        IpAddr::V6(_) => {
            Err("IPv6 CIDR sweeps aren't supported - the ranges are far too large to \
                 enumerate. Ping the addresses individually instead."
                .to_owned())
        }
    }
}

/// Expands an IPv4 CIDR range into its individual host addresses, excluding
/// the network/broadcast addresses (except for a /31, RFC 3021, where both
/// addresses are point-to-point-usable, and a /32, which is just the one
/// address).
fn expand_cidr_v4(base: Ipv4Addr, prefix_len: u8) -> Result<Vec<IpAddr>, String> {
    if prefix_len > 32 {
        return Err(format!("'/{prefix_len}' isn't a valid IPv4 prefix length"));
    }
    let host_bits = 32 - u32::from(prefix_len);
    let total_addresses: u64 = 1u64 << host_bits;
    if total_addresses > MAX_SWEEP_HOSTS {
        return Err(format!(
            "That range has too many addresses to sweep at once (limit: {MAX_SWEEP_HOSTS} \
             hosts) - use a smaller subnet, or ping specific addresses individually"
        ));
    }

    let base_u32 = u32::from(base);
    let mask: u32 = if host_bits >= 32 { 0 } else { !0u32 << host_bits };
    let network = base_u32 & mask;
    let broadcast = network | !mask;

    let addrs: Vec<IpAddr> = match host_bits {
        0 => vec![IpAddr::V4(Ipv4Addr::from(network))],
        1 => (network..=broadcast).map(|a| IpAddr::V4(Ipv4Addr::from(a))).collect(),
        _ => ((network + 1)..broadcast).map(|a| IpAddr::V4(Ipv4Addr::from(a))).collect(),
    };
    Ok(addrs)
}