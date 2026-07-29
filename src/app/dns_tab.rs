use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use eframe::egui;

use super::StatoriusApp;

impl StatoriusApp {
    /// Lists every DNS server currently known - both what the OS has
    /// configured (refreshed every 10 seconds in the background by
    /// `dns_worker`, see `net::dns`) and whatever's been added manually on
    /// this tab - each with a checkbox controlling whether the Ping tab's
    /// hostname resolution is allowed to use it. Also has: a field (top
    /// right) to add another server by IP, and a save/load pair (💾 writes
    /// the currently-checked servers out as a `.dns` file next to the
    /// program's binary; 📁 reads one back in, restoring exactly the
    /// checked set it was saved with).
    pub(super) fn ui_dns_tab(&mut self, ui: &mut egui::Ui) {
        let servers = self.combined_dns_servers();

        // Drop selections for servers that are no longer present at all -
        // neither still configured by the OS nor manually added - so this
        // doesn't grow forever on a machine that rotates DNS servers (e.g.
        // switching networks).
        let current: HashSet<IpAddr> = servers.iter().copied().collect();
        self.dns_selected.retain(|ip, _| current.contains(ip));

        ui.heading("DNS Servers");
        ui.label(
            "Servers configured on this system are refreshed automatically every 10 seconds. \
             Checked servers are used to resolve hostnames entered on the Ping tab.",
        );
        ui.add_space(4.0);

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
            return;
        }

        egui::ScrollArea::vertical().id_salt("dns_servers_scroll").show(ui, |ui| {
            let mut remove_ip: Option<IpAddr> = None;
            for ip in &servers {
                // Newly-discovered/added servers default to selected, so
                // DNS resolution works out of the box without a trip to
                // this tab first.
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