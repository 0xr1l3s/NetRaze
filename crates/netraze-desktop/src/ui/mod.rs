pub mod config_panel;
pub mod console;
pub mod credential_manager;
pub mod credentials_panel;
mod directory_panel;
pub mod log_panel;
pub mod network_view;
pub mod share_browser;
pub mod targets_table;
pub mod workflow_canvas;

use crate::app;
use crate::runtime::RuntimeServices;
use crate::state::AppState;

use crate::theme;

const ACCENT: egui::Color32 = theme::ACC; // #F97D1C orange
const TEXT_DIM: egui::Color32 = theme::MUTED; // #918C85
const SEPARATOR: egui::Color32 = theme::LINE; // #2C2B28
const BAR_BG: egui::Color32 = theme::PANEL; // #171716

pub fn show_top_bar(ctx: &egui::Context, state: &mut AppState, runtime: &RuntimeServices) {
    egui::TopBottomPanel::top("top_bar")
        .exact_height(28.0)
        .frame(egui::Frame {
            fill: theme::BG,
            inner_margin: egui::Margin::symmetric(8, 0),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Orange dot + wordmark
                let dot_rect = egui::Rect::from_min_size(
                    ui.cursor().min + egui::vec2(0.0, 10.0),
                    egui::vec2(7.0, 7.0),
                );
                ui.painter().circle_filled(dot_rect.center(), 3.5, ACCENT);
                ui.add_space(11.0);
                ui.label(
                    egui::RichText::new("NETRAZE DESK")
                        .color(theme::FG_2)
                        .size(10.5)
                        .monospace(),
                );
                ui.add_space(16.0);

                let tabs = [
                    (crate::state::NavTab::Workspace, "Workflow"),
                    (crate::state::NavTab::Target, "Cibles"),
                    (crate::state::NavTab::Module, "Moteur"),
                    (crate::state::NavTab::Settings, "Config"),
                ];
                for (tab, label) in tabs {
                    let selected = state.nav_tab == tab;
                    let text = if selected {
                        egui::RichText::new(label).size(12.0).color(theme::FG)
                    } else {
                        egui::RichText::new(label).size(12.0).color(TEXT_DIM)
                    };
                    let btn = egui::Button::new(text)
                        .fill(if selected {
                            theme::ELEV_2
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .corner_radius(egui::CornerRadius::same(theme::R_BADGE))
                        .stroke(egui::Stroke::NONE);
                    if ui.add(btn).clicked() {
                        state.nav_tab = tab;
                    }
                }

                let tools_selected = state.nav_tab == crate::state::NavTab::CredentialManager;
                let tools_text = if tools_selected {
                    egui::RichText::new("Outils").size(12.0).color(theme::FG)
                } else {
                    egui::RichText::new("Outils").size(12.0).color(TEXT_DIM)
                };
                let tools_btn = egui::Button::new(tools_text)
                    .fill(if tools_selected {
                        theme::ELEV_2
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .corner_radius(egui::CornerRadius::same(theme::R_BADGE))
                    .stroke(egui::Stroke::NONE);
                let tools_response = ui.add(tools_btn);
                egui::Popup::menu(&tools_response).show(|ui| {
                    if ui.button("🔐 Credential Manager").clicked() {
                        state.nav_tab = crate::state::NavTab::CredentialManager;
                        ui.close();
                    }
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("|").color(SEPARATOR).size(11.0));
                ui.add_space(8.0);

                ui.label(
                    egui::RichText::new("workspace")
                        .size(11.0)
                        .color(MUTED_2_COLOR),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut state.workspace_path)
                        .desired_width(160.0)
                        .font(egui::TextStyle::Monospace),
                );
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("sauver").size(11.5).color(theme::FG_2),
                        )
                        .corner_radius(egui::CornerRadius::same(theme::R_BTN)),
                    )
                    .clicked()
                {
                    app::save_current_workspace(state, runtime);
                }
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("charger").size(11.5).color(theme::FG_2),
                        )
                        .corner_radius(egui::CornerRadius::same(theme::R_BTN)),
                    )
                    .clicked()
                {
                    app::load_current_workspace(state, runtime);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (dot, label, color) = if state.is_running {
                        ("●", "actif", ACCENT)
                    } else {
                        ("○", "inactif", TEXT_DIM)
                    };
                    ui.label(
                        egui::RichText::new(format!("{dot} {label}"))
                            .size(10.5)
                            .monospace()
                            .color(color),
                    );
                });
            });
        });
}

pub fn show_right_panel(ctx: &egui::Context, state: &mut AppState, runtime: &RuntimeServices) {
    egui::SidePanel::right("right_panel")
        .default_width(300.0)
        .width_range(260.0..=440.0)
        .resizable(true)
        .frame(egui::Frame {
            fill: BAR_BG,
            inner_margin: egui::Margin::same(12),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            config_panel::show(ui, state, runtime);
        });
}

pub fn show_bottom_panel(ctx: &egui::Context, state: &mut AppState) {
    if !state.bottom_panel_open {
        return;
    }

    egui::TopBottomPanel::bottom("bottom_triptych")
        .resizable(true)
        .default_height(160.0)
        .height_range(110.0..=400.0)
        .frame(egui::Frame {
            fill: theme::CONSOLE_BG,
            inner_margin: egui::Margin::same(4),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("PANELS")
                        .small()
                        .strong()
                        .color(TEXT_DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button("×")
                        .on_hover_text("Close bottom panels")
                        .clicked()
                    {
                        state.bottom_panel_open = false;
                    }
                });
            });
            ui.separator();
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
        .exact_height(24.0)
        .frame(egui::Frame {
            fill: theme::BG,
            inner_margin: egui::Margin::symmetric(10, 2),
            stroke: egui::Stroke::new(0.5, SEPARATOR),
            ..Default::default()
        })
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (dot, label, color) = if state.is_running {
                    ("●", "actif", ACCENT)
                } else {
                    ("○", "inactif", TEXT_DIM)
                };
                ui.label(egui::RichText::new(dot).size(8.0).color(color));
                ui.label(
                    egui::RichText::new(label)
                        .size(11.0)
                        .monospace()
                        .color(TEXT_DIM),
                );
                sep(ui);
                ui.label(
                    egui::RichText::new(format!("hôtes  {}", state.discovered_hosts_count()))
                        .size(11.0)
                        .monospace()
                        .color(TEXT_DIM),
                );
                sep(ui);
                ui.label(
                    egui::RichText::new(format!("creds  {}", state.credentials_count()))
                        .size(11.0)
                        .monospace()
                        .color(TEXT_DIM),
                );
                sep(ui);
                ui.label(
                    egui::RichText::new(format!(
                        "threads  {}/{}",
                        state.threads.min(16),
                        state.threads
                    ))
                    .size(11.0)
                    .monospace()
                    .color(TEXT_DIM),
                );
                sep(ui);
                ui.label(
                    egui::RichText::new(format!(
                        "{:02}:{:02}",
                        state.elapsed_seconds() / 60,
                        state.elapsed_seconds() % 60
                    ))
                    .size(11.0)
                    .monospace()
                    .color(TEXT_DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if state.bottom_panel_open {
                        "⌄ Hide panels"
                    } else {
                        "⌃ Show panels"
                    };
                    if ui.small_button(label).clicked() {
                        state.bottom_panel_open = !state.bottom_panel_open;
                    }
                });
            });
        });
}

const MUTED_2_COLOR: egui::Color32 = theme::MUTED_2;

fn sep(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("·").size(10.0).color(SEPARATOR));
}
