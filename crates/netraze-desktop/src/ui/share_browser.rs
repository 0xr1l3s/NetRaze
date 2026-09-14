use crate::theme;

/// State for the share browser window.
#[derive(Debug, Clone)]
pub struct ShareBrowserState {
    pub open: bool,
    pub host_ip: String,
    pub share_name: String,
    /// Credential used for every remote operation in this window
    /// (runtime-only — browser state is never persisted).
    pub credential: Option<crate::state::CredentialRecord>,
    pub path_stack: Vec<String>,
    pub entries: Vec<BrowserEntry>,
    pub loading: bool,
    pub error: Option<String>,
    /// Status message (e.g. "Downloaded ok", "Deleted ok")
    pub status: Option<(String, bool)>,
    /// New folder name input
    pub new_folder_name: String,
    pub show_new_folder: bool,
}

#[derive(Debug, Clone)]
pub struct BrowserEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

impl ShareBrowserState {
    pub fn new(
        host_ip: String,
        share_name: String,
        credential: Option<crate::state::CredentialRecord>,
    ) -> Self {
        Self {
            open: true,
            host_ip,
            share_name,
            credential,
            path_stack: Vec::new(),
            entries: Vec::new(),
            loading: true,
            error: None,
            status: None,
            new_folder_name: String::new(),
            show_new_folder: false,
        }
    }

    /// Display-only UNC for the current location (window title).
    pub fn current_unc(&self) -> String {
        let mut path = format!("\\\\{}\\{}", self.host_ip, self.share_name);
        for seg in &self.path_stack {
            path.push('\\');
            path.push_str(seg);
        }
        path
    }

    /// Current directory relative to the share root (`""` = root) —
    /// the `rel_path` the portable browser backend expects.
    pub fn current_rel_path(&self) -> String {
        self.path_stack.join("\\")
    }

    /// Relative path of a child entry of the current directory.
    pub fn child_rel_path(&self, name: &str) -> String {
        let cur = self.current_rel_path();
        if cur.is_empty() {
            name.to_string()
        } else {
            format!("{cur}\\{name}")
        }
    }
}

pub fn show_browser_window(ctx: &egui::Context, browser: &mut ShareBrowserState) -> BrowserAction {
    let mut action = BrowserAction::None;

    if !browser.open {
        return action;
    }

    let title = format!("📂 {}", browser.current_unc());
    let window_id = egui::Id::new(("share_browser", &browser.host_ip, &browser.share_name));

    let mut is_open = browser.open;
    egui::Window::new(title)
        .id(window_id)
        .open(&mut is_open)
        .default_size([460.0, 380.0])
        .min_size([340.0, 220.0])
        .resizable(true)
        .collapsible(true)
        .frame(egui::Frame {
            fill: theme::BG,
            inner_margin: egui::Margin::same(10),
            stroke: egui::Stroke::new(1.0_f32, theme::LINE),
            corner_radius: egui::CornerRadius::same(theme::R_MODAL),
            ..Default::default()
        })
        .show(ctx, |ui| {
            // ── Breadcrumb bar ───────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;

                let can_go_back = !browser.path_stack.is_empty();
                let back_btn = egui::Button::new(
                    egui::RichText::new("⬅").color(if can_go_back {
                        theme::FG
                    } else {
                        theme::MUTED_2
                    }),
                )
                .fill(if can_go_back { theme::ACC_DIM } else { theme::ELEV_1 })
                .corner_radius(egui::CornerRadius::same(theme::R_BADGE));
                if ui.add(back_btn).clicked() && can_go_back {
                    browser.path_stack.pop();
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate;
                }

                ui.add_space(6.0);

                let root_label = format!("\\\\{}\\{}", browser.host_ip, browser.share_name);
                if ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(&root_label)
                                .small()
                                .strong()
                                .color(theme::INFO),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    browser.path_stack.clear();
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate;
                }

                for (i, seg) in browser.path_stack.clone().iter().enumerate() {
                    ui.label(egui::RichText::new("›").small().color(theme::MUTED));
                    if ui
                        .add(
                            egui::Label::new(
                                egui::RichText::new(seg).small().strong().color(theme::FG),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .clicked()
                    {
                        browser.path_stack.truncate(i + 1);
                        browser.error = None;
                        browser.status = None;
                        action = BrowserAction::Navigate;
                    }
                }
            });

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(2.0);

            // ── Toolbar ──────────────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;

                let btn = |text: &str| {
                    egui::Button::new(egui::RichText::new(text).small().color(theme::FG))
                        .fill(theme::ELEV_2)
                        .corner_radius(egui::CornerRadius::same(theme::R_BTN))
                };

                if ui.add(btn("⬆ Upload")).clicked() {
                    action = BrowserAction::UploadDialog;
                }
                if ui.add(btn("📁+ New Folder")).clicked() {
                    browser.show_new_folder = !browser.show_new_folder;
                    browser.new_folder_name.clear();
                }
                if ui.add(btn("🔄")).clicked() {
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate;
                }
            });

            // ── New folder input ─────────────────────────────────────────────
            if browser.show_new_folder {
                ui.add_space(4.0);
                egui::Frame::NONE
                    .fill(theme::ELEV_1)
                    .inner_margin(egui::Margin::symmetric(8, 4))
                    .corner_radius(egui::CornerRadius::same(theme::R_BTN))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Name:").small().color(theme::MUTED));
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut browser.new_folder_name)
                                    .desired_width(180.0)
                                    .font(egui::FontId::proportional(11.0))
                                    .text_color(theme::FG),
                            );
                            if browser.new_folder_name.is_empty() {
                                resp.request_focus();
                            }
                            let enter = resp.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            let create_clicked = ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("✓").small().color(theme::SUCCESS),
                                    )
                                    .fill(theme::SUCCESS_BG)
                                    .corner_radius(egui::CornerRadius::same(theme::R_BADGE)),
                                )
                                .clicked();

                            if (enter || create_clicked)
                                && !browser.new_folder_name.trim().is_empty()
                            {
                                let folder_name = browser.new_folder_name.trim().to_string();
                                action = BrowserAction::CreateFolder(folder_name);
                                browser.new_folder_name.clear();
                                browser.show_new_folder = false;
                            }

                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("✕").small().color(theme::MUTED),
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .corner_radius(egui::CornerRadius::same(theme::R_BADGE)),
                                )
                                .clicked()
                            {
                                browser.show_new_folder = false;
                            }
                        });
                    });
            }

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(2.0);

            // ── Status message ───────────────────────────────────────────────
            if let Some((msg, success)) = &browser.status {
                let (color, bg) = if *success {
                    (theme::SUCCESS, theme::SUCCESS_BG)
                } else {
                    (theme::ERROR, theme::ERROR_BG)
                };
                egui::Frame::NONE
                    .fill(bg)
                    .inner_margin(egui::Margin::symmetric(8, 3))
                    .corner_radius(egui::CornerRadius::same(theme::R_BADGE))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(msg.as_str()).small().color(color));
                    });
                ui.add_space(4.0);
            }

            // ── Content ──────────────────────────────────────────────────────
            if browser.loading {
                ui.centered_and_justified(|ui| {
                    ui.spinner();
                });
            } else if let Some(err) = &browser.error {
                ui.add_space(8.0);
                egui::Frame::NONE
                    .fill(theme::ERROR_BG)
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .corner_radius(egui::CornerRadius::same(theme::R_BTN))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!("⚠ {err}"))
                                .color(theme::ERROR)
                                .small(),
                        );
                    });
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new("Use ⬅ or breadcrumbs to go back")
                        .small()
                        .italics()
                        .color(theme::MUTED),
                );
            } else if browser.entries.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Empty directory")
                            .italics()
                            .color(theme::MUTED),
                    );
                });
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let row_height = 22.0;
                        let entries_snapshot: Vec<(String, bool, u64)> = browser
                            .entries
                            .iter()
                            .map(|e| (e.name.clone(), e.is_dir, e.size))
                            .collect();

                        for (entry_name, is_dir, entry_size) in &entries_snapshot {
                            let icon = if *is_dir { "📁" } else { "📄" };

                            let (row_rect, row_response) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), row_height),
                                egui::Sense::click(),
                            );

                            if *is_dir && row_response.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }

                            if row_response.hovered() {
                                ui.painter().rect_filled(
                                    row_rect,
                                    egui::CornerRadius::same(theme::R_BADGE),
                                    theme::ELEV_1,
                                );
                            }

                            // Left accent bar for directories on hover
                            if *is_dir && row_response.hovered() {
                                let bar = egui::Rect::from_min_size(
                                    row_rect.left_top(),
                                    egui::vec2(2.0, row_height),
                                );
                                ui.painter().rect_filled(
                                    bar,
                                    egui::CornerRadius::same(1),
                                    theme::ACC,
                                );
                            }

                            let mut cursor_x = row_rect.left() + 8.0;
                            let text_y = row_rect.center().y;

                            // Icon
                            let icon_galley = ui.painter().layout_no_wrap(
                                icon.to_string(),
                                egui::FontId::proportional(13.0),
                                theme::FG,
                            );
                            ui.painter().galley(
                                egui::pos2(cursor_x, text_y - icon_galley.size().y / 2.0),
                                icon_galley.clone(),
                                theme::FG,
                            );
                            cursor_x += icon_galley.size().x + 6.0;

                            // Name
                            let name_color = if *is_dir { theme::FG } else { theme::FG_2 };
                            let name_galley = ui.painter().layout_no_wrap(
                                entry_name.clone(),
                                egui::FontId {
                                    size: 11.5,
                                    family: egui::FontFamily::Proportional,
                                },
                                name_color,
                            );
                            ui.painter().galley(
                                egui::pos2(cursor_x, text_y - name_galley.size().y / 2.0),
                                name_galley,
                                name_color,
                            );

                            // Size (files only)
                            if !is_dir {
                                let size_str = netraze_protocols::smb::format_size(*entry_size);
                                let size_galley = ui.painter().layout_no_wrap(
                                    size_str,
                                    egui::FontId::proportional(10.0),
                                    theme::MUTED,
                                );
                                let size_x = row_rect.right() - size_galley.size().x - 8.0;
                                ui.painter().galley(
                                    egui::pos2(size_x, text_y - size_galley.size().y / 2.0),
                                    size_galley,
                                    theme::MUTED,
                                );
                            }

                            // Navigate into directory on click
                            if *is_dir && row_response.clicked() {
                                browser.path_stack.push(entry_name.clone());
                                browser.error = None;
                                browser.status = None;
                                action = BrowserAction::Navigate;
                            }

                            // Right-click context menu
                            row_response.context_menu(|ui| {
                                if *is_dir {
                                    if ui.button("🗑 Delete folder").clicked() {
                                        let rel = browser.child_rel_path(entry_name);
                                        action = BrowserAction::Delete { rel_path: rel, is_dir: true };
                                        ui.close();
                                    }
                                } else {
                                    if ui.button("⬇ Download").clicked() {
                                        let rel = browser.child_rel_path(entry_name);
                                        action = BrowserAction::DownloadDialog {
                                            rel_path: rel,
                                            filename: entry_name.clone(),
                                        };
                                        ui.close();
                                    }
                                    if ui.button("🗑 Delete file").clicked() {
                                        let rel = browser.child_rel_path(entry_name);
                                        action = BrowserAction::Delete { rel_path: rel, is_dir: false };
                                        ui.close();
                                    }
                                }
                            });
                        }
                    });
            }
        });

    browser.open = is_open;
    action
}

/// Commands from the browser window. Payloads are entry names / relative
/// paths, not UNCs — app.rs composes `(host, share, rel_path, credential)`
/// from the browser state so the portable backend never has to parse a UNC.
pub enum BrowserAction {
    None,
    /// Re-list the (already updated) current directory.
    Navigate,
    DownloadDialog {
        rel_path: String,
        filename: String,
    },
    /// Upload into the current directory.
    UploadDialog,
    CreateFolder(String),
    Delete {
        rel_path: String,
        is_dir: bool,
    },
}
