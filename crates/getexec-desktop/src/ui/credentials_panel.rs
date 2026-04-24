use crate::state::{AppState, CredType};

const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("🔑 Credentials")
                .size(12.0)
                .strong()
                .color(egui::Color32::WHITE),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(format!("{}", state.credentials.len()))
                    .small()
                    .color(TEXT_DIM),
            );
        });
    });
    ui.add_space(2.0);

    // -- Credential list --
    let mut to_delete: Option<usize> = None;

    egui::ScrollArea::vertical()
        .id_salt("credentials_scroll")
        .auto_shrink([false, false])
        .max_height(ui.available_height() - 80.0)
        .show(ui, |ui| {
            for (i, cred) in state.credentials.iter().enumerate() {
                let is_selected = state.selected_cred == Some(i);
                let type_tag = match cred.cred_type {
                    CredType::Password => "PWD",
                    CredType::Hash => "HASH",
                };
                let (valid_icon, valid_color) = match cred.valid {
                    Some(true) => ("✔", egui::Color32::from_rgb(80, 200, 120)),
                    Some(false) => ("✘", egui::Color32::from_rgb(220, 80, 80)),
                    None => ("●", TEXT_DIM),
                };

                let type_color = match cred.cred_type {
                    CredType::Password => egui::Color32::from_rgb(100, 180, 255),
                    CredType::Hash => egui::Color32::from_rgb(255, 180, 80),
                };

                let bg = if is_selected {
                    egui::Color32::from_rgb(35, 40, 52)
                } else {
                    egui::Color32::TRANSPARENT
                };

                egui::Frame::NONE.fill(bg).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(valid_color, valid_icon);
                        ui.label(
                            egui::RichText::new(format!("[{}]", type_tag))
                                .monospace()
                                .size(10.5)
                                .color(type_color),
                        );
                        ui.label(
                            egui::RichText::new(format!("{}\\{}", cred.domain, cred.username))
                                .monospace()
                                .size(10.5)
                                .color(if is_selected {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(200, 205, 215)
                                }),
                        );
                    });

                    let resp = ui.interact(
                        ui.min_rect(),
                        ui.id().with(("cred_row", i)),
                        egui::Sense::click(),
                    );
                    if resp.clicked() {
                        state.selected_cred = Some(i);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("📋 Copy secret").clicked() {
                            ui.ctx().copy_text(cred.secret.clone());
                            ui.close();
                        }
                        if ui.button("📋 Copy as user:secret").clicked() {
                            ui.ctx().copy_text(format!(
                                "{}\\{}:{}",
                                cred.domain, cred.username, cred.secret
                            ));
                            ui.close();
                        }
                        if ui.button("🗑 Delete").clicked() {
                            to_delete = Some(i);
                            ui.close();
                        }
                    });
                });
            }
        });

    if let Some(idx) = to_delete {
        state.credentials.remove(idx);
        if state.selected_cred == Some(idx) {
            state.selected_cred = None;
        }
    }

    ui.separator();

    // -- Add credential form (compact) --
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.new_cred_username)
                .hint_text("user")
                .desired_width(60.0)
                .font(egui::TextStyle::Small),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.new_cred_domain)
                .hint_text("DOMAIN")
                .desired_width(60.0)
                .font(egui::TextStyle::Small),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.new_cred_secret)
                .hint_text("secret")
                .desired_width(70.0)
                .font(egui::TextStyle::Small),
        );
    });
    ui.horizontal(|ui| {
        let is_hash = state.new_cred_type == CredType::Hash;
        if ui
            .add(egui::Button::new("Pwd").selected(!is_hash))
            .clicked()
        {
            state.new_cred_type = CredType::Password;
        }
        if ui
            .add(egui::Button::new("Hash").selected(is_hash))
            .clicked()
        {
            state.new_cred_type = CredType::Hash;
        }

        let can_add = !state.new_cred_username.is_empty() && !state.new_cred_secret.is_empty();
        let btn = egui::Button::new(
            egui::RichText::new("+ Add")
                .small()
                .color(egui::Color32::WHITE),
        )
        .fill(if can_add {
            ACCENT
        } else {
            egui::Color32::from_rgb(40, 46, 58)
        });
        if ui.add(btn).clicked() && can_add {
            state.credentials.push(crate::state::CredentialRecord {
                username: state.new_cred_username.drain(..).collect(),
                domain: if state.new_cred_domain.is_empty() {
                    ".".to_owned()
                } else {
                    state.new_cred_domain.drain(..).collect()
                },
                secret: state.new_cred_secret.drain(..).collect(),
                cred_type: state.new_cred_type.clone(),
                valid: None,
            });
        }

        if state.selected_cred.is_some() && state.selected_host.is_some() {
            let test_btn = egui::Button::new(
                egui::RichText::new("⚡ Test")
                    .small()
                    .color(egui::Color32::WHITE),
            )
            .fill(egui::Color32::from_rgb(83, 21, 22));
            if ui.add(test_btn).clicked() {
                // TODO: wire to runtime test
            }
        }
    });
}
