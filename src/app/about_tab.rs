use eframe::egui;

use super::StatoriusApp;

impl StatoriusApp {
    /// Static license/copyright info - no state of its own, just text.
    pub(super) fn ui_about_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading(concat!("Statorius ", env!("CARGO_PKG_VERSION")));
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Copyright");
            ui.strong("2026 Markus Bossert");
        });
        ui.hyperlink_to("https://github.com/tomboy-64/statorius/", "https://github.com/tomboy-64/statorius/");

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(12.0);

        ui.horizontal_wrapped(|ui| {
            ui.label(
                "This program is free software: you can redistribute it and/or modify \
                 it under the terms of the",
            );
            ui.hyperlink_to(
                "GNU Affero General Public License v3.0",
                "https://www.gnu.org/licenses/agpl-3.0.html",
            );
            ui.label("as published by the Free Software Foundation.");
        });
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                "This program is distributed in the hope that it will be useful, but \
                 WITHOUT ANY WARRANTY; without even the implied warranty of \
                 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.",
            );
        });
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                "In order to accelerate Code Production, I make heave use of LLMs (notably Claude and Gemini)."
            );
        });
    }
}