use crate::state::{AppState, CredType};
use egui::{Color32, Pos2, Rect, Ui};

const TEXT_DIM: Color32 = Color32::from_rgb(160, 165, 175);
const ROW_ALT: Color32 = Color32::from_rgba_premultiplied(14, 18, 25, 180);
const ROW_HOVER: Color32 = Color32::from_rgba_premultiplied(35, 42, 54, 200);
const SEPARATOR: Color32 = Color32::from_rgb(40, 46, 58);
const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
const BLUE: Color32 = Color32::from_rgb(80, 170, 255);
const YELLOW: Color32 = Color32::from_rgb(220, 200, 60);
const RED: Color32 = Color32::from_rgb(200, 80, 80);
const ACCENT: Color32 = Color32::from_rgb(102, 27, 28);
const DOT_COLOR: Color32 = Color32::from_rgb(40, 46, 58);
const DOT_SPACING: f32 = 20.0;
const DOT_RADIUS: f32 = 0.8;
const ROW_H: f32 = 30.0;
const PAD: f32 = 20.0;

pub fn show(ui: &mut Ui, ctx: &egui::Context, state: &mut AppState) {
    ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);

    // ── Background (same as workspace/targets) ──
    let full_rect = ui.available_rect_before_wrap();
    let painter = ui.painter();
    painter.rect_filled(full_rect, 0.0, Color32::from_rgb(18, 21, 28));
    let min_x = (full_rect.min.x / DOT_SPACING).floor() as i32;
    let max_x = (full_rect.max.x / DOT_SPACING).ceil() as i32;
    let min_y = (full_rect.min.y / DOT_SPACING).floor() as i32;
    let max_y = (full_rect.max.y / DOT_SPACING).ceil() as i32;
    for ix in min_x..=max_x {
        for iy in min_y..=max_y {
            let x = ix as f32 * DOT_SPACING;
            let y = iy as f32 * DOT_SPACING;
            painter.circle_filled(Pos2::new(x, y), DOT_RADIUS, DOT_COLOR);
        }
    }

    // ── Header ──
    let total = state.credentials.len();
    let active_count = state.credentials.iter().filter(|c| c.active).count();
    let valid_count = state
        .credentials
        .iter()
        .filter(|c| c.valid == Some(true))
        .count();
    let pwd_count = state
        .credentials
        .iter()
        .filter(|c| matches!(c.cred_type, CredType::Password))
        .count();
    let hash_count = state
        .credentials
        .iter()
        .filter(|c| matches!(c.cred_type, CredType::Hash))
        .count();

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_space(PAD);
        ui.label(
            egui::RichText::new("🔐 Credential Manager")
                .size(18.0)
                .strong()
                .color(Color32::WHITE),
        );
        ui.add_space(16.0);
        badge(ui, &total.to_string(), "total", TEXT_DIM);
        badge(ui, &active_count.to_string(), "active", GREEN);
        badge(ui, &valid_count.to_string(), "valid", BLUE);
        badge(ui, &pwd_count.to_string(), "pwd", BLUE);
        badge(ui, &hash_count.to_string(), "hash", YELLOW);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(PAD);
            let show_text = if state.cm_state.show_secrets {
                egui::RichText::new("🙈 Hide")
                    .strong()
                    .color(Color32::WHITE)
            } else {
                egui::RichText::new("👁 Show").color(TEXT_DIM)
            };
            let show_btn = egui::Button::new(show_text)
                .fill(if state.cm_state.show_secrets {
                    ACCENT
                } else {
                    egui::Color32::TRANSPARENT
                })
                .corner_radius(egui::CornerRadius::same(3))
                .stroke(egui::Stroke::NONE);
            if ui.add(show_btn).clicked() {
                state.cm_state.show_secrets = !state.cm_state.show_secrets;
            }
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut state.cm_state.search_query)
                    .desired_width(240.0)
                    .hint_text("🔍  Search user, domain, source…")
                    .font(egui::TextStyle::Monospace),
            );
        });
    });
    ui.add_space(6.0);

    // Separator
    {
        let r = ui.available_rect_before_wrap();
        ui.painter().hline(
            (r.left() + PAD)..=(r.right() - PAD),
            r.top(),
            egui::Stroke::new(1.0, SEPARATOR),
        );
        ui.add_space(12.0);
    }

    // ── Toolbar ──
    let mut toolbar_action: Option<ToolbarAction> = None;
    ui.horizontal(|ui| {
        ui.add_space(PAD);
        let add_text = egui::RichText::new("+ Add").strong().color(Color32::WHITE);
        if ui
            .add(
                egui::Button::new(add_text)
                    .fill(ACCENT)
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE),
            )
            .clicked()
        {
            toolbar_action = Some(ToolbarAction::Add);
        }
        ui.add_space(6.0);
        let can_edit = state.cm_state.selected_cred_idx.is_some();
        let edit_text = if can_edit {
            egui::RichText::new("Edit").strong().color(Color32::WHITE)
        } else {
            egui::RichText::new("Edit").color(TEXT_DIM)
        };
        if ui
            .add(
                egui::Button::new(edit_text)
                    .fill(if can_edit {
                        ACCENT
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE),
            )
            .clicked()
            && can_edit
        {
            toolbar_action = Some(ToolbarAction::Edit);
        }
        ui.add_space(6.0);
        let can_del = state.cm_state.selected_cred_idx.is_some();
        let del_text = if can_del {
            egui::RichText::new("🗑 Delete")
                .strong()
                .color(Color32::WHITE)
        } else {
            egui::RichText::new("🗑 Delete").color(TEXT_DIM)
        };
        if ui
            .add(
                egui::Button::new(del_text)
                    .fill(if can_del {
                        Color32::from_rgb(60, 30, 30)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE),
            )
            .clicked()
            && can_del
        {
            toolbar_action = Some(ToolbarAction::Delete);
        }
        ui.add_space(12.0);
        ui.colored_label(SEPARATOR, "|");
        ui.add_space(8.0);
        let import_text = egui::RichText::new("📥 Import CSV").color(TEXT_DIM);
        if ui
            .add(
                egui::Button::new(import_text)
                    .fill(egui::Color32::TRANSPARENT)
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE),
            )
            .clicked()
        {
            toolbar_action = Some(ToolbarAction::Import);
        }
        ui.add_space(6.0);
        let export_text = egui::RichText::new("📤 Export CSV").color(TEXT_DIM);
        if ui
            .add(
                egui::Button::new(export_text)
                    .fill(egui::Color32::TRANSPARENT)
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE),
            )
            .clicked()
        {
            toolbar_action = Some(ToolbarAction::Export);
        }
        ui.add_space(PAD);
    });
    ui.add_space(4.0);

    // ── Filter bar ──
    ui.horizontal(|ui| {
        ui.add_space(PAD);
        ui.label(egui::RichText::new("Filters:").small().color(TEXT_DIM));
        ui.add_space(4.0);
        // Type filter
        egui::ComboBox::from_id_salt("cm_filter_type")
            .width(90.0)
            .selected_text(match state.cm_state.filter_type {
                None => "All types",
                Some(CredType::Password) => "Password",
                Some(CredType::Hash) => "Hash",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.cm_state.filter_type, None, "All types");
                ui.selectable_value(
                    &mut state.cm_state.filter_type,
                    Some(CredType::Password),
                    "Password",
                );
                ui.selectable_value(
                    &mut state.cm_state.filter_type,
                    Some(CredType::Hash),
                    "Hash",
                );
            });
        ui.add_space(6.0);
        // Protocol filter
        ui.add(
            egui::TextEdit::singleline(&mut state.cm_state.filter_protocol)
                .desired_width(90.0)
                .hint_text("Protocol")
                .font(egui::TextStyle::Monospace),
        );
        ui.add_space(6.0);
        // Valid filter
        egui::ComboBox::from_id_salt("cm_filter_valid")
            .width(90.0)
            .selected_text(match state.cm_state.filter_valid {
                None => "All valid",
                Some(true) => "Valid ✔",
                Some(false) => "Invalid ✘",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.cm_state.filter_valid, None, "All valid");
                ui.selectable_value(&mut state.cm_state.filter_valid, Some(true), "Valid ✔");
                ui.selectable_value(&mut state.cm_state.filter_valid, Some(false), "Invalid ✘");
            });
        ui.add_space(6.0);
        ui.checkbox(
            &mut state.cm_state.filter_active_only,
            egui::RichText::new("Active only").small().color(TEXT_DIM),
        );
        ui.add_space(PAD);
    });
    ui.add_space(2.0);

    // ── Edit Window (floating) ──
    if state.cm_state.edit_mode {
        show_edit_window(ctx, state);
    }

    // ── Column widths ──
    let tw = (ui.available_width() - PAD * 2.0).max(900.0);
    let c_active = tw * 0.04;
    let c_user = tw * 0.13;
    let c_domain = tw * 0.11;
    let c_secret = tw * 0.16;
    let c_type = tw * 0.06;
    let c_proto = tw * 0.07;
    let c_valid = tw * 0.06;
    let c_source = tw * 0.10;
    let c_notes = tw * 0.16;
    let c_tags = tw * 0.11;

    let col_labels = [
        ("", c_active),
        ("USER", c_user),
        ("DOMAIN", c_domain),
        ("SECRET", c_secret),
        ("TYPE", c_type),
        ("PROTO", c_proto),
        ("VALID", c_valid),
        ("SOURCE", c_source),
        ("NOTES", c_notes),
        ("TAGS", c_tags),
    ];

    // ── Header row ──
    {
        let (hr, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 22.0), egui::Sense::hover());
        let y = hr.center().y;
        let mut x = hr.left() + PAD;
        let hfont = egui::FontId::new(10.0, egui::FontFamily::Monospace);
        for (lbl, w) in &col_labels {
            ui.painter().text(
                Pos2::new(x + 4.0, y),
                egui::Align2::LEFT_CENTER,
                *lbl,
                hfont.clone(),
                TEXT_DIM,
            );
            x += w;
        }
    }

    // Header separator
    {
        let r = ui.available_rect_before_wrap();
        ui.painter().hline(
            (r.left() + PAD)..=(r.right() - PAD),
            r.top(),
            egui::Stroke::new(1.0, SEPARATOR),
        );
        ui.add_space(1.0);
    }

    // ── Filtered rows ──
    let query = state.cm_state.search_query.to_ascii_lowercase();
    let filter_type = state.cm_state.filter_type.clone();
    let filter_protocol = state.cm_state.filter_protocol.to_ascii_lowercase();
    let filter_valid = state.cm_state.filter_valid;
    let filter_active_only = state.cm_state.filter_active_only;
    let filtered: Vec<usize> = (0..state.credentials.len())
        .filter(|&i| {
            let c = &state.credentials[i];
            // Search text
            let matches_search = query.is_empty()
                || c.username.to_ascii_lowercase().contains(&query)
                || c.domain.to_ascii_lowercase().contains(&query)
                || c.source.to_ascii_lowercase().contains(&query)
                || c.notes.to_ascii_lowercase().contains(&query)
                || c.protocol.to_ascii_lowercase().contains(&query)
                || c.tags
                    .iter()
                    .any(|t| t.to_ascii_lowercase().contains(&query));
            // Filters
            let matches_type = filter_type.as_ref().map_or(true, |t| *t == c.cred_type);
            let matches_proto = filter_protocol.is_empty()
                || c.protocol.to_ascii_lowercase().contains(&filter_protocol);
            let matches_valid = filter_valid.map_or(true, |v| c.valid == Some(v));
            let matches_active = !filter_active_only || c.active;
            matches_search && matches_type && matches_proto && matches_valid && matches_active
        })
        .collect();

    let mut to_delete: Option<usize> = None;
    let mut to_toggle_active: Option<usize> = None;
    let mut to_copy_secret: Option<String> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for (row_idx, &cred_idx) in filtered.iter().enumerate() {
                let c = &state.credentials[cred_idx];
                let is_alt = row_idx % 2 == 1;
                let is_selected = state.cm_state.selected_cred_idx == Some(cred_idx);

                let (row_rect, row_resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), ROW_H),
                    egui::Sense::click(),
                );

                // Background
                let bg = if is_selected {
                    Color32::from_rgba_premultiplied(102, 27, 28, 60)
                } else if row_resp.hovered() {
                    ROW_HOVER
                } else if is_alt {
                    ROW_ALT
                } else {
                    Color32::TRANSPARENT
                };
                ui.painter().rect_filled(row_rect, 0.0, bg);

                let y = row_rect.center().y;
                let mut x = row_rect.left() + PAD;
                let fm = egui::FontId::new(12.0, egui::FontFamily::Monospace);
                let fp = egui::FontId::new(12.0, egui::FontFamily::Proportional);
                let fs = egui::FontId::new(11.0, egui::FontFamily::Monospace);

                // ── Active toggle ──
                let active_rect =
                    Rect::from_min_size(Pos2::new(x + 2.0, y - 8.0), egui::vec2(16.0, 16.0));
                let active_color = if c.active {
                    GREEN
                } else {
                    Color32::from_rgb(60, 60, 60)
                };
                ui.painter()
                    .rect_filled(active_rect, egui::CornerRadius::same(3), active_color);
                if row_resp.clicked()
                    && active_rect
                        .contains(ui.input(|i| i.pointer.interact_pos()).unwrap_or_default())
                {
                    to_toggle_active = Some(cred_idx);
                }
                x += c_active;

                // ── User ──
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &c.username,
                    fm.clone(),
                    Color32::WHITE,
                );
                x += c_user;

                // ── Domain ──
                let dom = if c.domain == "." { "LOCAL" } else { &c.domain };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    dom,
                    fp.clone(),
                    TEXT_DIM,
                );
                x += c_domain;

                // ── Secret ──
                let secret_text = if state.cm_state.show_secrets {
                    if c.secret.len() > 28 {
                        format!("{}…", &c.secret[..27])
                    } else {
                        c.secret.clone()
                    }
                } else {
                    "••••••••".to_string()
                };
                let secret_color = match c.cred_type {
                    CredType::Hash => YELLOW,
                    CredType::Password => BLUE,
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &secret_text,
                    fm.clone(),
                    secret_color,
                );
                x += c_secret;

                // ── Type badge ──
                let (type_label, type_color, type_bg) = match c.cred_type {
                    CredType::Password => (
                        "PWD",
                        BLUE,
                        Color32::from_rgba_premultiplied(16, 34, 51, 200),
                    ),
                    CredType::Hash => (
                        "HASH",
                        YELLOW,
                        Color32::from_rgba_premultiplied(44, 40, 12, 200),
                    ),
                };
                let br = Rect::from_min_size(Pos2::new(x + 2.0, y - 9.0), egui::vec2(46.0, 18.0));
                ui.painter()
                    .rect_filled(br, egui::CornerRadius::same(3), type_bg);
                ui.painter().text(
                    br.center(),
                    egui::Align2::CENTER_CENTER,
                    type_label,
                    fs.clone(),
                    type_color,
                );
                x += c_type;

                // ── Protocol ──
                if !c.protocol.is_empty() {
                    let pr =
                        Rect::from_min_size(Pos2::new(x + 2.0, y - 9.0), egui::vec2(50.0, 18.0));
                    ui.painter().rect_filled(
                        pr,
                        egui::CornerRadius::same(3),
                        Color32::from_rgba_premultiplied(20, 40, 30, 200),
                    );
                    ui.painter().text(
                        pr.center(),
                        egui::Align2::CENTER_CENTER,
                        &c.protocol,
                        fs.clone(),
                        GREEN,
                    );
                }
                x += c_proto;

                // ── Valid ──
                let (valid_label, valid_color) = match c.valid {
                    Some(true) => ("✔", GREEN),
                    Some(false) => ("✘", RED),
                    None => ("—", TEXT_DIM),
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    valid_label,
                    fm.clone(),
                    valid_color,
                );
                x += c_valid;

                // ── Source ──
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    if c.source.is_empty() {
                        "—"
                    } else {
                        &c.source
                    },
                    fs.clone(),
                    TEXT_DIM,
                );
                x += c_source;

                // ── Notes ──
                let note_txt = if c.notes.is_empty() {
                    "—".into()
                } else if c.notes.len() > 22 {
                    format!("{}…", &c.notes[..21])
                } else {
                    c.notes.clone()
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &note_txt,
                    fs.clone(),
                    TEXT_DIM,
                );
                x += c_notes;

                // ── Tags ──
                if !c.tags.is_empty() {
                    let tag_str = c.tags.join(", ");
                    let tag_display = if tag_str.len() > 14 {
                        format!("{}…", &tag_str[..13])
                    } else {
                        tag_str
                    };
                    ui.painter().text(
                        Pos2::new(x + 4.0, y),
                        egui::Align2::LEFT_CENTER,
                        &tag_display,
                        fs.clone(),
                        BLUE,
                    );
                }

                // Selection click
                if row_resp.clicked() {
                    state.cm_state.selected_cred_idx = Some(cred_idx);
                }

                // Context menu
                row_resp.context_menu(|ui| {
                    if ui.button("📋 Copy secret").clicked() {
                        to_copy_secret = Some(c.secret.clone());
                        ui.close();
                    }
                    if ui.button("⦿ Toggle active").clicked() {
                        to_toggle_active = Some(cred_idx);
                        ui.close();
                    }
                    if ui.button("🗑 Delete").clicked() {
                        to_delete = Some(cred_idx);
                        ui.close();
                    }
                });
            }

            // Empty state
            if filtered.is_empty() {
                ui.add_space(80.0);
                ui.vertical_centered(|ui| {
                    if total == 0 {
                        ui.label(
                            egui::RichText::new("No credentials stored yet")
                                .size(16.0)
                                .color(TEXT_DIM),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(
                                "Add credentials manually or import from a CSV file",
                            )
                            .size(12.0)
                            .color(TEXT_DIM)
                            .italics(),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("No credentials match your search")
                                .size(14.0)
                                .color(TEXT_DIM),
                        );
                    }
                });
            }
        });

    // Apply deferred actions
    if let Some(idx) = to_toggle_active {
        state.credentials[idx].active = !state.credentials[idx].active;
    }
    if let Some(idx) = to_delete {
        state.credentials.remove(idx);
        if state.cm_state.selected_cred_idx == Some(idx) {
            state.cm_state.selected_cred_idx = None;
        }
    }
    if let Some(secret) = to_copy_secret {
        ui.ctx().copy_text(secret);
    }

    // Apply toolbar actions after table to avoid borrow issues
    match toolbar_action {
        Some(ToolbarAction::Add) => {
            reset_form(state);
            state.cm_state.edit_mode = true;
            state.cm_state.selected_cred_idx = None;
        }
        Some(ToolbarAction::Edit) => {
            if let Some(idx) = state.cm_state.selected_cred_idx {
                let c = &state.credentials[idx];
                state.cm_state.form_username = c.username.clone();
                state.cm_state.form_domain = c.domain.clone();
                state.cm_state.form_secret = c.secret.clone();
                state.cm_state.form_cred_type = c.cred_type.clone();
                state.cm_state.form_protocol = c.protocol.clone();
                state.cm_state.form_source = c.source.clone();
                state.cm_state.form_notes = c.notes.clone();
                state.cm_state.form_tags = c.tags.join(", ");
                state.cm_state.form_active = c.active;
                state.cm_state.edit_mode = true;
            }
        }
        Some(ToolbarAction::Delete) => {
            if let Some(idx) = state.cm_state.selected_cred_idx {
                state.credentials.remove(idx);
                state.cm_state.selected_cred_idx = None;
            }
        }
        Some(ToolbarAction::Import) => {
            if let Some(path) = native_open_file_dialog() {
                match import_csv(state, &path) {
                    Ok((imported, skipped, errors)) => {
                        state.add_log(
                            crate::runtime::LogLevel::Success,
                            format!("CSV import: {imported} imported, {skipped} skipped, {errors} errors"),
                        );
                    }
                    Err(e) => {
                        state.add_log(
                            crate::runtime::LogLevel::Error,
                            format!("CSV import failed: {e}"),
                        );
                    }
                }
            }
        }
        Some(ToolbarAction::Export) => {
            if let Some(path) = native_save_file_dialog() {
                match export_csv(state, &path) {
                    Ok(()) => {
                        state.add_log(
                            crate::runtime::LogLevel::Success,
                            format!("CSV exported to {path}"),
                        );
                    }
                    Err(e) => {
                        state.add_log(
                            crate::runtime::LogLevel::Error,
                            format!("CSV export failed: {e}"),
                        );
                    }
                }
            }
        }
        None => {}
    }
}

fn show_edit_window(ctx: &egui::Context, state: &mut AppState) {
    let is_editing = state.cm_state.selected_cred_idx.is_some();
    let title = if is_editing {
        "Edit Credential"
    } else {
        "Add Credential"
    };
    let mut open = true;
    egui::Window::new(title)
        .open(&mut open)
        .default_size([560.0, 260.0])
        .min_size([480.0, 220.0])
        .resizable(true)
        .collapsible(false)
        .show(ctx, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 6.0);

            ui.columns(2, |cols| {
                // Left column
                cols[0].vertical(|ui| {
                    ui.label(egui::RichText::new("Username").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_username)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(egui::RichText::new("Domain").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_domain)
                            .desired_width(f32::INFINITY)
                            .hint_text(". for local")
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(egui::RichText::new("Protocol").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_protocol)
                            .desired_width(f32::INFINITY)
                            .hint_text("SMB, LDAP, SSH…")
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(egui::RichText::new("Source").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_source)
                            .desired_width(f32::INFINITY)
                            .hint_text("manual, SAM, LSA…")
                            .font(egui::TextStyle::Monospace),
                    );
                });

                // Right column
                cols[1].vertical(|ui| {
                    ui.label(egui::RichText::new("Secret").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_secret)
                            .desired_width(f32::INFINITY)
                            .password(!state.cm_state.show_secrets)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(egui::RichText::new("Type").small().color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        let pwd_selected =
                            matches!(state.cm_state.form_cred_type, CredType::Password);
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("Password").small())
                                    .fill(if pwd_selected {
                                        ACCENT
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    })
                                    .corner_radius(egui::CornerRadius::same(3)),
                            )
                            .clicked()
                        {
                            state.cm_state.form_cred_type = CredType::Password;
                        }
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("Hash").small())
                                    .fill(if !pwd_selected {
                                        ACCENT
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    })
                                    .corner_radius(egui::CornerRadius::same(3)),
                            )
                            .clicked()
                        {
                            state.cm_state.form_cred_type = CredType::Hash;
                        }
                    });
                    ui.label(egui::RichText::new("Tags").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_tags)
                            .desired_width(f32::INFINITY)
                            .hint_text("tag1, tag2")
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.label(egui::RichText::new("Notes").small().color(TEXT_DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.cm_state.form_notes)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut state.cm_state.form_active,
                    egui::RichText::new("Active").color(TEXT_DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(egui::RichText::new("Cancel").small())
                                .fill(Color32::from_rgb(40, 46, 58))
                                .corner_radius(egui::CornerRadius::same(3)),
                        )
                        .clicked()
                    {
                        state.cm_state.edit_mode = false;
                    }
                    ui.add_space(6.0);
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(if is_editing {
                                    "💾 Update"
                                } else {
                                    "💾 Save"
                                })
                                .small()
                                .strong()
                                .color(Color32::WHITE),
                            )
                            .fill(ACCENT)
                            .corner_radius(egui::CornerRadius::same(3)),
                        )
                        .clicked()
                    {
                        save_form(state);
                    }
                });
            });
        });
    if !open {
        state.cm_state.edit_mode = false;
    }
}

fn save_form(state: &mut AppState) {
    let cm = &mut state.cm_state;
    let username = cm.form_username.trim().to_string();
    let domain = if cm.form_domain.trim().is_empty() {
        ".".to_owned()
    } else {
        cm.form_domain.trim().to_string()
    };
    let secret = cm.form_secret.trim().to_string();
    if username.is_empty() || secret.is_empty() {
        return;
    }

    let record = crate::state::CredentialRecord {
        username,
        domain,
        secret,
        cred_type: cm.form_cred_type.clone(),
        valid: None,
        active: cm.form_active,
        protocol: cm.form_protocol.trim().to_uppercase(),
        source: cm.form_source.trim().to_string(),
        notes: cm.form_notes.trim().to_string(),
        tags: cm
            .form_tags
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        created_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        ),
    };

    if let Some(idx) = cm.selected_cred_idx {
        // Preserve original created_at and valid if editing
        let old_created = state.credentials[idx].created_at;
        let old_valid = state.credentials[idx].valid;
        state.credentials[idx] = record;
        state.credentials[idx].created_at = old_created;
        state.credentials[idx].valid = old_valid;
    } else {
        state.credentials.push(record);
    }

    cm.edit_mode = false;
    cm.selected_cred_idx = None;
}

fn reset_form(state: &mut AppState) {
    let cm = &mut state.cm_state;
    cm.form_username.clear();
    cm.form_domain.clear();
    cm.form_secret.clear();
    cm.form_cred_type = CredType::Password;
    cm.form_protocol = "SMB".to_owned();
    cm.form_source.clear();
    cm.form_notes.clear();
    cm.form_tags.clear();
    cm.form_active = true;
}

#[derive(Debug, Clone)]
enum ToolbarAction {
    Add,
    Edit,
    Delete,
    Import,
    Export,
}

fn badge(ui: &mut Ui, value: &str, label: &str, color: Color32) {
    let text = format!("{value} {label}");
    let galley = ui.painter().layout_no_wrap(
        text.clone(),
        egui::FontId::new(10.0, egui::FontFamily::Monospace),
        color,
    );
    let w = galley.size().x + 14.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::hover());
    let bg = Color32::from_rgba_premultiplied(color.r() / 5, color.g() / 5, color.b() / 5, 200);
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(4), bg);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        &text,
        egui::FontId::new(10.0, egui::FontFamily::Monospace),
        color,
    );
}

// ── CSV Import / Export ──

fn export_csv(state: &AppState, path: &str) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record([
        "username",
        "domain",
        "secret",
        "cred_type",
        "protocol",
        "valid",
        "active",
        "source",
        "notes",
        "tags",
    ])
    .map_err(|e| e.to_string())?;
    for c in &state.credentials {
        let row: Vec<String> = vec![
            c.username.clone(),
            c.domain.clone(),
            c.secret.clone(),
            match c.cred_type {
                CredType::Password => "password".to_string(),
                CredType::Hash => "hash".to_string(),
            },
            c.protocol.clone(),
            c.valid.map_or(String::new(), |v| v.to_string()),
            c.active.to_string(),
            c.source.clone(),
            c.notes.clone(),
            c.tags.join("|"),
        ];
        wtr.write_record(&row).map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn import_csv(state: &mut AppState, path: &str) -> Result<(usize, usize, usize), String> {
    let mut rdr = csv::Reader::from_path(path).map_err(|e| e.to_string())?;
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        if record.len() < 4 {
            errors += 1;
            continue;
        }
        let username = record.get(0).unwrap_or("").trim().to_string();
        let domain = record.get(1).unwrap_or("").trim().to_string();
        let secret = record.get(2).unwrap_or("").trim().to_string();
        let cred_type_str = record.get(3).unwrap_or("password").trim().to_lowercase();
        if username.is_empty() || secret.is_empty() {
            errors += 1;
            continue;
        }
        let cred_type = if cred_type_str == "hash" {
            CredType::Hash
        } else {
            CredType::Password
        };
        // Check duplicate
        let is_dup = state
            .credentials
            .iter()
            .any(|c| c.username == username && c.domain == domain && c.secret == secret);
        if is_dup {
            skipped += 1;
            continue;
        }
        let protocol = record.get(4).unwrap_or("").trim().to_uppercase();
        let valid = record.get(5).unwrap_or("").trim().parse::<bool>().ok();
        let active = record
            .get(6)
            .unwrap_or("true")
            .trim()
            .parse::<bool>()
            .unwrap_or(true);
        let source = record.get(7).unwrap_or("").trim().to_string();
        let notes = record.get(8).unwrap_or("").trim().to_string();
        let tags = record
            .get(9)
            .unwrap_or("")
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        state.credentials.push(crate::state::CredentialRecord {
            username,
            domain: if domain.is_empty() {
                ".".to_owned()
            } else {
                domain
            },
            secret,
            cred_type,
            valid,
            active,
            protocol,
            source,
            notes,
            tags,
            created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            ),
        });
        imported += 1;
    }
    Ok((imported, skipped, errors))
}

fn native_open_file_dialog() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Title = 'Select CSV file'; $f.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'; if ($f.ShowDialog() -eq 'OK') { $f.FileName } else { '' }"#,
        ])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}

fn native_save_file_dialog() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.SaveFileDialog; $f.Title = 'Save CSV file'; $f.Filter = 'CSV files (*.csv)|*.csv'; $f.FileName = 'netraze_credentials.csv'; if ($f.ShowDialog() -eq 'OK') { $f.FileName } else { '' }"#,
        ])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}
