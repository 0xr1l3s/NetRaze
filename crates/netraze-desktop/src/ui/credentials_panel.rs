use crate::state::{AppState, CredType};
use crate::theme;

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("🔑 Credentials")
                .size(12.0)
                .strong()
                .color(theme::FG),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(format!("{}", state.credentials.len()))
                    .small()
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(2.0);

    let mut to_delete: Option<usize> = None;

    egui::ScrollArea::vertical()
        .id_salt("credentials_scroll")
        .auto_shrink([false, false])
        .max_height(ui.available_height() - 80.0)
        .show(ui, |ui| {
            for (i, cred) in state.credentials.iter().enumerate() {
                let is_selected = state.selected_cred == Some(i);
                let type_tag = match &cred.cred_type {
                    CredType::Password if cred.secret.is_empty() => "GUEST",
                    CredType::Password => "PWD",
                    CredType::Hash => "HASH",
                };
                let (valid_icon, valid_color) = match cred.valid {
                    Some(true) => ("✔", theme::SUCCESS),
                    Some(false) => ("✘", theme::ERROR),
                    None => ("●", theme::MUTED),
                };
                let type_color = match &cred.cred_type {
                    CredType::Password if cred.secret.is_empty() => theme::SUCCESS,
                    CredType::Password => theme::INFO,
                    CredType::Hash => theme::WARNING,
                };

                let bg = if is_selected {
                    theme::ACC_BG
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
                                .color(if is_selected { theme::FG } else { theme::FG_2 }),
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

    // ── Compact add form ─────────────────────────────────────────────────────
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
                .hint_text(if state.new_cred_type == CredType::Password {
                    "secret (empty = guest)"
                } else {
                    "nt hash"
                })
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

        let has_secret = !state.new_cred_secret.is_empty();
        let can_add = !state.new_cred_username.is_empty()
            && (has_secret || state.new_cred_type == CredType::Password);
        let btn = egui::Button::new(egui::RichText::new("+ Add").small().color(theme::FG)).fill(
            if can_add {
                theme::ACC_DIM
            } else {
                theme::ELEV_2
            },
        );
        if ui.add(btn).clicked() && can_add {
            state.credentials.push(crate::state::CredentialRecord {
                username: std::mem::take(&mut state.new_cred_username),
                domain: if state.new_cred_domain.is_empty() {
                    ".".to_owned()
                } else {
                    std::mem::take(&mut state.new_cred_domain)
                },
                secret: std::mem::take(&mut state.new_cred_secret),
                cred_type: state.new_cred_type.clone(),
                valid: None,
                active: true,
                protocol: String::new(),
                source: String::new(),
                notes: String::new(),
                tags: Vec::new(),
                created_at: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0),
                ),
            });
        }

        if state.selected_cred.is_some() && state.selected_host.is_some() {
            let test_btn =
                egui::Button::new(egui::RichText::new("⚡ Test").small().color(theme::FG))
                    .fill(theme::ACC_DIM);
            if ui.add(test_btn).clicked() {
                // TODO: wire to runtime test
            }
        }
    });
}
