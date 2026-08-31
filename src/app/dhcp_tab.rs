use eframe::egui;

use crate::net::dhcp::{self, DhcpMessageWire};
use crate::net::l2_manager::L2Status;

use super::StatoriusApp;

impl StatoriusApp {
    /// The "DHCP" tab: every DHCP/BOOTP exchange the passive sniffer (see
    /// `net::dhcp_sniffer`, running inside the L2 helper) has captured so
    /// far, grouped by transaction id and listed oldest exchange first. Each
    /// transaction is a collapsing header labelled with its `xid` and the
    /// timestamp of the *first* message seen for it; expanding it shows
    /// every message in that exchange (DISCOVER/OFFER/REQUEST/ACK/... or
    /// plain BOOTP) with its options fully decoded.
    pub(super) fn ui_dhcp_tab(&mut self, ui: &mut egui::Ui) {
        // Same reasoning as the L2 Ping tab: this is only reachable once L2
        // mode is active (see `render_tab_bar`), so this is a defensive
        // fallback rather than the normal path.
        let l2_active = matches!(self.l2_status.get(), L2Status::Active { .. });
        if !l2_active {
            ui.weak("Activate L2 mode in the tab row above to capture DHCP traffic.");
            return;
        }

        let transactions = self.dhcp_state.snapshot();

        if let Some(error) = self.dhcp_state.sniffer_error() {
            ui.colored_label(
                egui::Color32::from_rgb(220, 80, 80),
                format!("DHCP capture isn't running: {error}"),
            );
            ui.weak(
                "L2 pinging and other L2 features are unaffected - this only \
                 affects the DHCP tab specifically.",
            );
            ui.separator();
        }

        ui.horizontal(|ui| {
            ui.heading("DHCP Exchanges");
            ui.weak(format!("({} transaction(s) seen)", transactions.len()));
        });
        ui.separator();

        egui::ScrollArea::vertical().id_salt("dhcp_scroll").show(ui, |ui| {
            if transactions.is_empty() {
                ui.weak(
                    "No DHCP traffic captured yet - broadcasts (DISCOVER/REQUEST) and \
                     replies (OFFER/ACK/NAK) will appear here as they're seen.",
                );
                return;
            }

            for txn in &transactions {
                let is_open = *self.dhcp_open.entry(txn.xid).or_insert(false);
                let header_title = format!(
                    "xid 0x{:08x}  —  {}  —  {} message(s)",
                    txn.xid,
                    format_timestamp(txn.first_seen_unix_ms),
                    txn.messages.len(),
                );
                let resp = egui::CollapsingHeader::new(header_title)
                    .id_salt(txn.xid)
                    .open(Some(is_open))
                    .show(ui, |ui| {
                        for (i, msg) in txn.messages.iter().enumerate() {
                            render_dhcp_message(ui, txn.xid, i, msg);
                        }
                    });
                if resp.header_response.clicked() {
                    self.dhcp_open.insert(txn.xid, !is_open);
                }
            }
        });
    }
}

/// One message within a transaction: a summary line (type, capture time,
/// client MAC, VLAN, the fixed BOOTP addresses that are actually set), plus
/// its fully decoded options tucked into their own nested collapsing
/// header so a transaction with several messages doesn't turn into a wall
/// of option tables by default. Wrapped in `ui.scope` (not `ui.group`) so
/// each message still gets its own isolated child `Ui`/ID scope without a
/// visible frame around it.
fn render_dhcp_message(ui: &mut egui::Ui, xid: u32, index: usize, msg: &DhcpMessageWire) {
    // `ui.scope` rather than `ui.group`: it still gives this message its
    // own child `Ui` (and ID scope, keeping its widgets from colliding
    // with the next message's) but - unlike `group` - paints no visible
    // frame/border around it.
    ui.scope(|ui| {
        ui.horizontal(|ui| {
            ui.strong(&msg.message_type);
            ui.weak(format_timestamp(msg.captured_at_unix_ms));
            if let Some(mac) = &msg.client_mac {
                ui.label(format!("client {mac}"));
            }
            if let Some(vlan) = msg.vlan {
                ui.label(format!("VLAN {vlan}"));
            }
        });

        render_address_highlights(ui, msg);

        egui::CollapsingHeader::new(format!("Options ({})", msg.options.len()))
            .id_salt(("dhcp_opts", xid, index))
            .show(ui, |ui| {
                if msg.options.is_empty() {
                    ui.weak("No options.");
                    return;
                }
                egui::Grid::new(("dhcp_opts_grid", xid, index))
                    .num_columns(3)
                    .striped(true)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong("Code");
                        ui.strong("Option");
                        ui.strong("Value");
                        ui.end_row();

                        for opt in &msg.options {
                            ui.label(opt.code.to_string());

                            ui.vertical(|ui| {
                                ui.set_min_width(160.0);
                                let name_resp = ui.label(&opt.name);
                                if let Some(help) = dhcp::option_help(opt.code) {
                                    name_resp.on_hover_text(help);
                                }
                                ui.weak(format!("({})", opt.data_type));
                            });

                            // Each list entry (multiple IPs, a parameter
                            // request list, ...) already arrives as its own
                            // line from `dhcp.rs`; `wrap_text` additionally
                            // hard-wraps any single line that's still too
                            // long on its own (a hex dump, a long string
                            // option, ...) so the column can't blow out the
                            // table's width.
                            ui.label(wrap_text(&opt.value, 42));
                            ui.end_row();
                        }
                    });
            });
    });

    ui.add_space(6.0);
}

/// `ciaddr`/`yiaddr`/`siaddr`/`giaddr` mean four different, easily-confused
/// things - shown inline as before, just in a slightly brighter shade than
/// normal body text, with a hover tooltip on each spelling out what that
/// particular field means and when it's actually set.
fn render_address_highlights(ui: &mut egui::Ui, msg: &DhcpMessageWire) {
    const FIELDS: [(&str, &str); 4] = [
        (
            "ciaddr",
            "Client IP address - already held by the client (e.g. renewing an \
             existing lease). Zero during an initial DISCOVER/OFFER.",
        ),
        (
            "yiaddr",
            "\"Your\" (client's) IP address - filled in by the server in \
             OFFER/ACK to hand out the address being offered/assigned.",
        ),
        (
            "siaddr",
            "Next-server IP address - typically the TFTP/boot server for \
             PXE-style network boot, not necessarily the DHCP server itself.",
        ),
        (
            "giaddr",
            "Gateway (relay agent) IP address - set by a relay agent \
             forwarding the request across a subnet boundary.",
        ),
    ];
    let addrs = [&msg.ciaddr, &msg.yiaddr, &msg.siaddr, &msg.giaddr];

    let any_set = addrs.iter().any(|a| a.is_some());
    if !any_set {
        return;
    }

    // A touch brighter than normal text, derived from the theme's own text
    // color rather than a fixed one, so it still reads fine in both light
    // and dark mode.
    let highlight = ui.visuals().text_color().gamma_multiply(1.4);

    ui.horizontal(|ui| {
        for ((label, help), addr) in FIELDS.iter().zip(addrs.iter()) {
            let Some(addr) = addr else { continue };
            ui.label(egui::RichText::new(format!("{label} {addr}")).color(highlight))
                .on_hover_text(*help);
        }
    });
}

/// Word-wrap `text` to roughly `width` characters per visual line,
/// preferring to break right after a natural separator (space, comma,
/// colon, semicolon) near the target width over cutting mid-token - a MAC
/// address or a run of comma-separated values both read far better that
/// way than being cut at an arbitrary character. Existing newlines (from
/// list-formatted options, one entry per line already) are preserved and
/// each wrapped independently.
fn wrap_text(text: &str, width: usize) -> String {
    text.lines()
        .map(|line| wrap_line(line, width))
        .collect::<Vec<_>>()
        .join("\n")
}

fn wrap_line(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_owned();
    }
    let mut out = String::new();
    let mut current = String::new();
    for ch in line.chars() {
        current.push(ch);
        if current.chars().count() >= width {
            match current.rfind([' ', ',', ':', ';']) {
                Some(pos) => {
                    let (head, tail) = current.split_at(pos + 1);
                    out.push_str(head.trim_end());
                    out.push('\n');
                    current = tail.to_owned();
                }
                None => {
                    out.push_str(&current);
                    out.push('\n');
                    current.clear();
                }
            }
        }
    }
    out.push_str(&current);
    out
}

/// `unix_ms` -> `"YYYY-MM-DD HH:MM:SS UTC"`. No date/time crate is a
/// dependency of this project, so this is a small, self-contained
/// implementation rather than pulling one in just for this one display
/// helper - `civil_from_days` is Howard Hinnant's well-known public-domain
/// algorithm for turning a day count since the Unix epoch into a
/// proleptic-Gregorian (year, month, day), reproduced here as-is.
fn format_timestamp(unix_ms: u64) -> String {
    let total_secs = unix_ms / 1000;
    let secs_of_day = total_secs % 86400;
    let days = (total_secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}