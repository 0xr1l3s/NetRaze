pub mod config_panel;
pub mod console;
pub mod credential_manager;
pub mod credentials_panel;
pub mod log_panel;
pub mod network_view;
pub mod share_browser;
pub mod targets_table;
pub mod workflow_canvas;

use crate::app;
use crate::runtime::RuntimeServices;
use crate::state::AppState;

const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28); // #661b1c
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);
const SEPARATOR: egui::Color32 = egui::Color32::from_rgb(40, 46, 58);
const BAR_BG: egui::Color32 = egui::Color32::from_rgb(18, 21, 28); // #12151c

pub fn show_top_bar(ctx: &egui::Context, state: &mut AppState, runtime: &RuntimeServices) {
    egui::TopBottomPanel::top("top_bar")
        .frame(egui::Frame {
            fill: BAR_BG,
            inner_margin: egui::Margin::symmetric(12, 5),
            stroke: egui::Stroke::new(1.0, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("⚡ NetRaze")
                        .color(ACCENT)
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(16.0);

                let tabs = [
                    (crate::state::NavTab::Workspace, "Workspace"),
                    (crate::state::NavTab::Target, "Target"),
                    (crate::state::NavTab::Module, "Module"),
                    (crate::state::NavTab::Settings, "Settings"),
                ];
                for (tab, label) in tabs {
                    let selected = state.nav_tab == tab;
                    let text = if selected {
                        egui::RichText::new(label)
                            .strong()
                            .color(egui::Color32::WHITE)
                    } else {
                        egui::RichText::new(label).color(TEXT_DIM)
                    };
                    let btn = egui::Button::new(text)
                        .fill(if selected {
                            ACCENT
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .corner_radius(egui::CornerRadius::same(3))
                        .stroke(egui::Stroke::NONE);
                    if ui.add(btn).clicked() {
                        state.nav_tab = tab;
                    }
                }

                // Tools dropdown menu (styled exactly like the other tabs)
                let tools_selected = state.nav_tab == crate::state::NavTab::CredentialManager;
                let tools_text = if tools_selected {
                    egui::RichText::new("Tools")
                        .strong()
                        .color(egui::Color32::WHITE)
                } else {
                    egui::RichText::new("Tools").color(TEXT_DIM)
                };
                let tools_btn = egui::Button::new(tools_text)
                    .fill(if tools_selected {
                        ACCENT
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE);
                let tools_response = ui.add(tools_btn);
                egui::Popup::menu(&tools_response).show(|ui| {
                    if ui.button("🔐 Credential Manager").clicked() {
                        state.nav_tab = crate::state::NavTab::CredentialManager;
                        ui.close();
                    }
                });

                ui.add_space(12.0);
                ui.colored_label(SEPARATOR, "|");
                ui.add_space(4.0);

                ui.label(egui::RichText::new("Workspace:").small().color(TEXT_DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut state.workspace_path)
                        .desired_width(180.0)
                        .font(egui::TextStyle::Monospace),
                );

                if ui
                    .add(egui::Button::new(egui::RichText::new("💾 Save").small()))
                    .clicked()
                {
                    app::save_current_workspace(state, runtime);
                }
                if ui
                    .add(egui::Button::new(egui::RichText::new("📂 Load").small()))
                    .clicked()
                {
                    app::load_current_workspace(state, runtime);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (indicator, color) = if state.is_running {
                        ("● RUNNING", ACCENT)
                    } else {
                        ("○ IDLE", TEXT_DIM)
                    };
                    ui.label(egui::RichText::new(indicator).color(color).strong().small());
                });
            });
        });
}

pub fn show_right_panel(ctx: &egui::Context, state: &mut AppState, runtime: &RuntimeServices) {
    egui::SidePanel::right("right_panel")
        .default_width(230.0)
        .width_range(190.0..=320.0)
        .resizable(true)
        .frame(egui::Frame {
            fill: BAR_BG,
            inner_margin: egui::Margin::same(10),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            config_panel::show(ui, state, runtime);
        });
}

pub fn show_bottom_panel(ctx: &egui::Context, state: &mut AppState) {
    egui::TopBottomPanel::bottom("bottom_triptych")
        .resizable(true)
        .default_height(195.0)
        .height_range(100.0..=400.0)
        .frame(egui::Frame {
            fill: BAR_BG,
            inner_margin: egui::Margin::same(4),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.columns(3, |cols| {
                cols[0].group(|ui| {
                    network_view::show(ui, state);
                });
                cols[1].group(|ui| {
                    credentials_panel::show(ui, state);
                });
                cols[2].group(|ui| {
                    log_panel::show(ui, state);
                });
            });
        });
}

pub fn show_status_bar(ctx: &egui::Context, state: &mut AppState) {
    egui::TopBottomPanel::bottom("status_bar")
        .exact_height(22.0)
        .frame(egui::Frame {
            fill: egui::Color32::from_rgb(18, 21, 28),
            inner_margin: egui::Margin::symmetric(10, 2),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (indicator, color) = if state.is_running {
                    ("●", ACCENT)
                } else {
                    ("○", TEXT_DIM)
                };
                ui.colored_label(color, indicator);
                ui.label(
                    egui::RichText::new(if state.is_running { "Running" } else { "Idle" })
                        .small()
                        .color(TEXT_DIM),
                );
                ui.colored_label(SEPARATOR, "|");
                ui.label(
                    egui::RichText::new(format!("Hosts: {}", state.discovered_hosts_count()))
                        .small()
                        .color(TEXT_DIM),
                );
                ui.colored_label(SEPARATOR, "|");
                ui.label(
                    egui::RichText::new(format!("Creds: {}", state.credentials_count()))
                        .small()
                        .color(TEXT_DIM),
                );
                ui.colored_label(SEPARATOR, "|");
                ui.label(
                    egui::RichText::new(format!(
                        "Threads: {}/{}",
                        state.threads.min(16),
                        state.threads
                    ))
                    .small()
                    .color(TEXT_DIM),
                );
                ui.colored_label(SEPARATOR, "|");
                ui.label(
                    egui::RichText::new(format!(
                        "{:02}:{:02}",
                        state.elapsed_seconds() / 60,
                        state.elapsed_seconds() % 60
                    ))
                    .small()
                    .color(TEXT_DIM),
                );
            });
        });
}
