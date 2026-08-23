use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use eframe::egui;
use hickory_resolver::proto::rr::RecordType;
use tokio::sync::oneshot;

use crate::net::dns::DnsCommand;
use crate::net::dns_query::{DnsAnswer, QueryOptions, QueryOutcome, ResponseFlags, TraceHop, TraceOutcome};

use super::StatoriusApp;

/// Record types offered in the Query panel's dropdown - the common ones a
/// network engineer would actually reach for, not every one of the ~35
/// `RecordType` knows about.
const QUERY_TYPE_CHOICES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::TXT,
    RecordType::NS,
    RecordType::SOA,
    RecordType::PTR,
    RecordType::SRV,
    RecordType::CAA,
    RecordType::DNSKEY,
    RecordType::DS,
    RecordType::RRSIG,
    RecordType::NSEC,
    RecordType::NAPTR,
    RecordType::HTTPS,
    RecordType::SVCB,
    RecordType::ANY,
];

impl StatoriusApp {
    /// Two things live on this tab: the server list (which OS-configured
    /// and manually-added DNS servers are known and checked - checking one
    /// makes it eligible both for the Ping tab's hostname resolution and
    /// as a target for the Query panel below), and the Query panel itself
    /// - an actual dig-like query/`+trace` sent to those servers, with the
    /// raw response shown back. See `ui_dns_query_panel` for the latter.
    pub(super) fn ui_dns_tab(&mut self, ui: &mut egui::Ui) {
        let servers = self.combined_dns_servers();

        // Drop selections for servers that are no longer present at all -
        // neither still configured by the OS nor manually added - so this
        // doesn't grow forever on a machine that rotates DNS servers (e.g.
        // switching networks).
        let current: HashSet<IpAddr> = servers.iter().copied().collect();
        self.dns_selected.retain(|ip, _| current.contains(ip));

        ui.heading("DNS");
        ui.label(
            "Servers configured on this system are refreshed automatically every 10 seconds. \
             Checked servers are used to resolve hostnames entered on the Ping tab, and as the \
             targets for the Query panel below.",
        );
        ui.add_space(4.0);
        ui.strong("Servers");

        // Add-a-server field (left) and the save/load icons (right), one
        // row, directly above the server list itself.
        let mut add_now = false;
        let mut open_save = false;
        let mut open_load = false;
        ui.horizontal(|ui| {
            let add_clicked = ui
                .button("+")
                .on_hover_text("Add this address to the server list below")
                .clicked();
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.dns_add_input)
                    .desired_width(140.0)
                    .hint_text("Add server IP"),
            );
            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            add_now = add_clicked || enter_pressed;

            // Claims the rest of this row from the right edge inward - see
            // the identical pattern (and reasoning) on the L2 checkbox in
            // `render_tab_bar`. Icons are twice the default body text size
            // (13.0 -> 26.0) so they read as clickable controls, not stray
            // emoji in a sentence.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                open_load = ui
                    .button(egui::RichText::new("\u{1F4C1}").size(26.0)) // 📁
                    .on_hover_text("Load a previously saved .dns file")
                    .clicked();
                open_save = ui
                    .button(egui::RichText::new("\u{1F4BE}").size(26.0)) // 💾
                    .on_hover_text("Save the checked servers to a .dns file")
                    .clicked();
            });
        });
        if add_now {
            self.try_add_manual_dns_server();
        }
        if open_save {
            self.dns_load_input = None;
            self.dns_save_input = Some(String::new());
        }
        if open_load {
            self.dns_save_input = None;
            self.dns_load_input = Some(String::new());
        }
        if let Some(err) = &self.dns_add_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        let mut save_now: Option<String> = None;
        let mut cancel_save = false;
        if let Some(name) = &mut self.dns_save_input {
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
            self.dns_save_input = None;
        }
        if let Some(name) = save_now {
            self.save_dns_servers(&name);
        }

        let mut load_now: Option<String> = None;
        let mut cancel_load = false;
        if let Some(name) = &mut self.dns_load_input {
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
            self.dns_load_input = None;
        }
        if let Some(name) = load_now {
            self.load_dns_servers(&name);
        }

        if let Some((is_error, message)) = &self.dns_io_message {
            let color = if *is_error {
                egui::Color32::RED
            } else {
                egui::Color32::from_rgb(60, 170, 60)
            };
            ui.colored_label(color, message);
        }

        ui.separator();

        if servers.is_empty() {
            ui.label("No DNS servers configured or added yet.");
        } else {
            // Capped height so a long server list can't push the Query
            // panel below it off-screen - the panel has its own scroll
            // area for its (usually taller) results.
            egui::ScrollArea::vertical()
                .id_salt("dns_servers_scroll")
                .max_height(160.0)
                .show(ui, |ui| {
                    let mut remove_ip: Option<IpAddr> = None;
                    for ip in &servers {
                        // Newly-discovered/added servers default to
                        // selected, so DNS resolution works out of the box
                        // without a trip to this tab first.
                        let is_manual = self.dns_manual_servers.contains(ip);
                        let selected = self.dns_selected.entry(*ip).or_insert(true);
                        ui.horizontal(|ui| {
                            ui.checkbox(selected, ip.to_string());
                            if is_manual
                                && ui
                                .small_button("x")
                                .on_hover_text("Remove this manually-added server")
                                .clicked()
                            {
                                remove_ip = Some(*ip);
                            }
                        });
                    }
                    if let Some(ip) = remove_ip {
                        self.dns_manual_servers.retain(|s| *s != ip);
                        self.dns_selected.remove(&ip);
                    }
                });
        }

        ui.separator();
        self.ui_dns_query_panel(ui);
    }

    /// Every DNS server currently known: the OS-configured ones plus
    /// whatever's been added manually on this tab, deduplicated (manual
    /// entries that happen to match an OS-configured one don't show up
    /// twice).
    fn combined_dns_servers(&self) -> Vec<IpAddr> {
        let mut all = self.dns_shared.get();
        for ip in &self.dns_manual_servers {
            if !all.contains(ip) {
                all.push(*ip);
            }
        }
        all
    }

    /// Parses `dns_add_input` as an IP and, if valid, adds it as a manually
    /// managed server (pre-checked). Leaves `dns_add_error` set - rendered
    /// in red below the add field - if it isn't a valid address.
    fn try_add_manual_dns_server(&mut self) {
        let trimmed = self.dns_add_input.trim().to_owned();
        if trimmed.is_empty() {
            return;
        }
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => {
                if !self.dns_shared.get().contains(&ip) && !self.dns_manual_servers.contains(&ip) {
                    self.dns_manual_servers.push(ip);
                }
                self.dns_selected.insert(ip, true);
                self.dns_add_input.clear();
                self.dns_add_error = None;
            }
            Err(_) => {
                self.dns_add_error = Some(format!("'{trimmed}' is not a valid IP address"));
            }
        }
    }

    /// Writes every currently-checked server, one per line, to `filename`
    /// (appending `.dns` if it doesn't already end in that) in the same
    /// directory as the running executable.
    fn save_dns_servers(&mut self, filename: &str) {
        let filename = normalize_dns_filename(filename.trim());
        let Some(path) = dns_file_path(&filename) else {
            self.dns_io_message = Some((
                true,
                "Could not determine the program's directory".to_owned(),
            ));
            return;
        };

        let selected: Vec<IpAddr> = self
            .combined_dns_servers()
            .into_iter()
            .filter(|ip| *self.dns_selected.get(ip).unwrap_or(&true))
            .collect();
        let contents = selected.iter().map(IpAddr::to_string).collect::<Vec<_>>().join("\n");

        match std::fs::write(&path, contents) {
            Ok(()) => {
                self.dns_io_message = Some((
                    false,
                    format!("Saved {} server(s) to {}", selected.len(), path.display()),
                ));
                self.dns_save_input = None;
            }
            Err(e) => {
                self.dns_io_message = Some((true, format!("Failed to save '{}': {e}", path.display())));
            }
        }
    }

    /// Reads `filename` (appending `.dns` if needed) and restores exactly
    /// the checked set it was saved with: every currently-checked server is
    /// unchecked first, then everything the file lists is (re-)added as a
    /// manual server if needed and checked - so opening a `.dns` file
    /// reproduces the exact selection it was saved from, not a merge with
    /// whatever happened to already be checked.
    fn load_dns_servers(&mut self, filename: &str) {
        let filename = normalize_dns_filename(filename.trim());
        let Some(path) = dns_file_path(&filename) else {
            self.dns_io_message = Some((
                true,
                "Could not determine the program's directory".to_owned(),
            ));
            return;
        };

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.dns_io_message =
                    Some((true, format!("Failed to open '{}': {e}", path.display())));
                return;
            }
        };

        let mut loaded = Vec::new();
        let mut bad_lines = 0u32;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<IpAddr>() {
                Ok(ip) => loaded.push(ip),
                Err(_) => bad_lines += 1,
            }
        }

        for selected in self.dns_selected.values_mut() {
            *selected = false;
        }
        let system = self.dns_shared.get();
        for ip in &loaded {
            if !system.contains(ip) && !self.dns_manual_servers.contains(ip) {
                self.dns_manual_servers.push(*ip);
            }
            self.dns_selected.insert(*ip, true);
        }

        self.dns_io_message = Some((
            false,
            if bad_lines > 0 {
                format!(
                    "Loaded {} server(s) from {} ({bad_lines} line(s) ignored)",
                    loaded.len(),
                    path.display()
                )
            } else {
                format!("Loaded {} server(s) from {}", loaded.len(), path.display())
            },
        ));
        self.dns_load_input = None;
    }

    /// The Query panel: an actual dig-like query against the servers
    /// checked above (or, with `+trace` checked, against the root hints
    /// instead - see `dns_query::trace`), with the raw response shown
    /// back rather than just resolved addresses. Polls whichever of
    /// `dns_query_rx`/`dns_trace_rx` is in flight once per frame, the same
    /// pattern the Ping tab's hostname resolution uses.
    fn ui_dns_query_panel(&mut self, ui: &mut egui::Ui) {
        self.poll_dns_query();

        ui.strong("Query");
        ui.label(
            "Sends an actual DNS query and shows the raw response. Goes to every server \
             checked above, unless +trace is checked - that always starts at the root servers \
             and walks the delegation chain by hand, the same as plain `dig +trace`.",
        );
        ui.add_space(4.0);

        let busy = self.dns_query_rx.is_some() || self.dns_trace_rx.is_some();
        let trace = self.dns_query_trace;

        ui.horizontal(|ui| {
            ui.label("Name:");
            let hint = if self.dns_query_type == RecordType::PTR {
                "203.0.113.5 (or a name)"
            } else {
                "example.com"
            };
            let response = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut self.dns_query_input)
                    .desired_width(200.0)
                    .hint_text(hint),
            );
            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            egui::ComboBox::from_id_salt("dns_query_type")
                .selected_text(self.dns_query_type.to_string())
                .show_ui(ui, |ui| {
                    for ty in QUERY_TYPE_CHOICES {
                        ui.selectable_value(&mut self.dns_query_type, *ty, ty.to_string());
                    }
                });

            let query_clicked = ui.add_enabled(!busy, egui::Button::new("Query")).clicked();
            if !busy && (query_clicked || enter_pressed) {
                self.submit_dns_query();
            }
            if busy {
                ui.spinner();
            }
        });

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!trace, |ui| {
                ui.checkbox(&mut self.dns_query_recursion_desired, "Recursion desired")
            })
                .inner
                .on_hover_text(
                    "dig's +[no]recurse (the RD bit). Always off during +trace - each hop is asked \
                 only what it itself knows.",
                );
            ui.add_enabled_ui(!trace, |ui| ui.checkbox(&mut self.dns_query_use_tcp, "TCP"))
                .inner
                .on_hover_text(
                    "dig's +tcp - use TCP even if UDP would do. +trace always starts over UDP, \
                     retrying a hop over TCP itself if that server's reply comes back \
                     truncated.",
                );
            ui.checkbox(&mut self.dns_query_dnssec_ok, "+dnssec").on_hover_text(
                "Sets the EDNS DO bit and shows any DNSSEC records (RRSIG/DNSKEY/...) the \
                 server includes. This only requests and displays them - it doesn't validate \
                 the signatures.",
            );
            ui.add_enabled_ui(!trace, |ui| {
                ui.checkbox(&mut self.dns_query_checking_disabled, "+cdflag")
            })
                .inner
                .on_hover_text(
                    "Sets the CD bit, so an upstream validating resolver won't withhold an answer \
                 that fails its own DNSSEC check. Mainly useful together with +dnssec when \
                 inspecting a broken zone.",
                );
            ui.checkbox(&mut self.dns_query_trace, "+trace").on_hover_text(
                "Starts at the root servers and follows delegations by hand, one hop at a time \
                 - ignores the servers checked above, same as plain `dig +trace`.",
            );
        });

        if let Some(err) = &self.dns_query_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        ui.separator();

        egui::ScrollArea::vertical().id_salt("dns_query_results_scroll").show(ui, |ui| {
            if trace {
                if let Some(result) = &self.dns_trace_result {
                    render_trace_result(ui, result);
                }
            } else if let Some(results) = &self.dns_query_results {
                for outcome in results {
                    render_query_outcome(ui, outcome);
                    ui.add_space(6.0);
                }
            }
        });
    }

    /// Starts (or restarts) the Query panel's current request: either a
    /// normal fan-out to every checked server, or (with `dns_query_trace`
    /// set) a single `+trace` job that starts at the root hints instead -
    /// see `dns_query::trace` for why that ignores the checked servers
    /// entirely. A no-op while a previous job is still in flight - see
    /// `busy` in `ui_dns_query_panel`, which already disables the field
    /// and button for exactly that case, so this is a backstop more than
    /// something normally reachable.
    fn submit_dns_query(&mut self) {
        if self.dns_query_rx.is_some() || self.dns_trace_rx.is_some() {
            return;
        }

        let name = self.dns_query_input.trim().to_owned();
        if name.is_empty() {
            self.dns_query_error = Some("Enter a name to query".to_owned());
            return;
        }
        self.dns_query_error = None;

        let record_type = self.dns_query_type;
        let selected_servers: Vec<IpAddr> = self
            .combined_dns_servers()
            .into_iter()
            .filter(|ip| *self.dns_selected.get(ip).unwrap_or(&true))
            .collect();

        if self.dns_query_trace {
            let (respond_to, rx) = oneshot::channel();
            let command = DnsCommand::Trace {
                name,
                record_type,
                dnssec_ok: self.dns_query_dnssec_ok,
                // Only consulted if a referral is missing glue - see
                // `dns_query::trace`'s docs.
                fallback_servers: selected_servers,
                respond_to,
            };
            if self.dns_tx.try_send(command).is_ok() {
                self.dns_trace_rx = Some(rx);
                self.dns_trace_result = None;
            } else {
                self.dns_query_error = Some("Failed to queue the trace - try again".to_owned());
            }
            return;
        }

        if selected_servers.is_empty() {
            self.dns_query_error = Some("No DNS servers selected above".to_owned());
            return;
        }

        let options = QueryOptions {
            record_type,
            use_tcp: self.dns_query_use_tcp,
            recursion_desired: self.dns_query_recursion_desired,
            dnssec_ok: self.dns_query_dnssec_ok,
            checking_disabled: self.dns_query_checking_disabled,
        };

        let (respond_to, rx) = oneshot::channel();
        let command = DnsCommand::Query { name, servers: selected_servers, options, respond_to };
        if self.dns_tx.try_send(command).is_ok() {
            self.dns_query_rx = Some(rx);
            self.dns_query_results = None;
        } else {
            self.dns_query_error = Some("Failed to queue the query - try again".to_owned());
        }
    }

    /// Checks whether the in-flight query/trace job (if any) has finished,
    /// same polling pattern as the Ping tab's `poll_dns_resolution`.
    /// Called once per frame from `ui_dns_query_panel`.
    fn poll_dns_query(&mut self) {
        if let Some(rx) = &mut self.dns_query_rx {
            match rx.try_recv() {
                Ok(outcomes) => {
                    self.dns_query_rx = None;
                    self.dns_query_results = Some(outcomes);
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.dns_query_rx = None;
                    self.dns_query_error =
                        Some("The query worker went away before answering".to_owned());
                }
            }
        }
        if let Some(rx) = &mut self.dns_trace_rx {
            match rx.try_recv() {
                Ok(outcome) => {
                    self.dns_trace_rx = None;
                    self.dns_trace_result = Some(outcome);
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.dns_trace_rx = None;
                    self.dns_query_error =
                        Some("The trace worker went away before answering".to_owned());
                }
            }
        }
    }
}

/// One server's block in the (non-trace) Query panel results: its address,
/// how long it took, and either its answer or why it doesn't have one.
fn render_query_outcome(ui: &mut egui::Ui, outcome: &QueryOutcome) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(outcome.server.to_string()).strong());
            ui.label(format!("{:.0} ms", outcome.elapsed.as_secs_f64() * 1000.0));
        });
        match &outcome.result {
            Ok(answer) => render_dns_answer(ui, answer),
            Err(e) => {
                ui.colored_label(egui::Color32::RED, e);
            }
        }
    });
}

/// The full `+trace` panel: every hop in order, then a note at the end if
/// the trace didn't reach a final answer on its own.
fn render_trace_result(ui: &mut egui::Ui, result: &TraceOutcome) {
    for (index, hop) in result.hops.iter().enumerate() {
        render_trace_hop(ui, index + 1, hop);
        ui.add_space(6.0);
    }
    if let Some(note) = &result.note {
        ui.colored_label(egui::Color32::from_rgb(210, 150, 60), note);
    }
}

/// One hop's block: its number, which server answered (with its
/// root-server label if it has one), how long it took, and its answer.
fn render_trace_hop(ui: &mut egui::Ui, hop_number: usize, hop: &TraceHop) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            let server_text = match &hop.server_label {
                Some(label) => format!("#{hop_number}  {label} ({})", hop.server),
                None => format!("#{hop_number}  {}", hop.server),
            };
            ui.label(egui::RichText::new(server_text).strong());
            ui.label(format!("{:.0} ms", hop.elapsed.as_secs_f64() * 1000.0));
        });
        match &hop.result {
            Ok(answer) => render_dns_answer(ui, answer),
            Err(e) => {
                ui.colored_label(egui::Color32::RED, e);
            }
        }
    });
}

/// Shared by both a plain query outcome and a trace hop: the status/flags
/// line, then the answer/authority/additional sections, each record
/// already formatted dig-style by `dns_query::to_dns_answer`.
fn render_dns_answer(ui: &mut egui::Ui, answer: &DnsAnswer) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("status: {}", answer.response_code)).strong());
        ui.label(format!("{} bytes", answer.message_size));
        if answer.retried_over_tcp {
            ui.label("(retried over TCP - UDP reply was truncated)");
        }
    });
    ui.label(format!("flags: {}", format_flags(&answer.flags)));

    render_record_section(ui, "ANSWER", &answer.answers);
    render_record_section(ui, "AUTHORITY", &answer.authorities);
    render_record_section(ui, "ADDITIONAL", &answer.additionals);
}

/// One of the three record sections - omitted entirely when empty, same as
/// `dig` leaving a section out of its output rather than printing a "0
/// records" header for it.
fn render_record_section(ui: &mut egui::Ui, title: &str, records: &[String]) {
    if records.is_empty() {
        return;
    }
    ui.label(egui::RichText::new(title).italics());
    for line in records {
        ui.label(egui::RichText::new(line).monospace());
    }
}

/// dig's own "flags: qr rd ra ad ..." line - only the flags meaningful to
/// show on a response (the QR/opcode aren't worth a look-in on something
/// that's already known to be an answer).
fn format_flags(flags: &ResponseFlags) -> String {
    let mut parts = Vec::new();
    if flags.authoritative {
        parts.push("aa");
    }
    if flags.truncated {
        parts.push("tc");
    }
    if flags.recursion_available {
        parts.push("ra");
    }
    if flags.authenticated_data {
        parts.push("ad");
    }
    if flags.checking_disabled {
        parts.push("cd");
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(" ")
    }
}

/// Appends `.dns` unless `name` already ends in it.
fn normalize_dns_filename(name: &str) -> String {
    if name.ends_with(".dns") {
        name.to_owned()
    } else {
        format!("{name}.dns")
    }
}

/// Resolves `filename` against the directory the running executable lives
/// in - `None` only if the OS can't tell us where our own binary is, which
/// in practice never happens on Windows or Linux.
fn dns_file_path(filename: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(filename))
}