use egui::Color32;

const ACCENT: Color32 = Color32::from_rgb(102, 27, 28);
const TEXT_DIM: Color32 = Color32::from_rgb(160, 165, 175);
const PANEL_BG: Color32 = Color32::from_rgb(27, 34, 44);
const SEPARATOR: Color32 = Color32::from_rgb(40, 46, 58);
const GREEN: Color32 = Color32::from_rgb(80, 200, 120);

/// State for the share browser window.
#[derive(Debug, Clone)]
pub struct ShareBrowserState {
    pub open: bool,
    pub host_ip: String,
    pub share_name: String,
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
    pub fn new(host_ip: String, share_name: String) -> Self {
        Self {
            open: true,
            host_ip,
            share_name,
            path_stack: Vec::new(),
            entries: Vec::new(),
            loading: true,
            error: None,
            status: None,
            new_folder_name: String::new(),
            show_new_folder: false,
        }
    }

    /// Full UNC path for current location.
    pub fn current_unc(&self) -> String {
        let mut path = format!("\\\\{}\\{}", self.host_ip, self.share_name);
        for seg in &self.path_stack {
            path.push('\\');
            path.push_str(seg);
        }
        path
    }

    /// UNC path for a child entry.
    pub fn child_unc(&self, name: &str) -> String {
        format!("{}\\{}", self.current_unc(), name)
    }
}

pub fn show_browser_window(ctx: &egui::Context, browser: &mut ShareBrowserState) -> BrowserAction {
    let mut action = BrowserAction::None;

    if !browser.open {
        return action;
    }

    let title = format!(
        "📂 {} — \\\\{}\\{}",
        browser.share_name, browser.host_ip, browser.share_name
    );

    let mut is_open = browser.open;
    egui::Window::new(title)
        .open(&mut is_open)
        .default_size([460.0, 380.0])
        .min_size([340.0, 220.0])
        .resizable(true)
        .collapsible(true)
        .frame(egui::Frame {
            fill: PANEL_BG,
            inner_margin: egui::Margin::same(8),
            stroke: egui::Stroke::new(1.0, SEPARATOR),
            corner_radius: egui::CornerRadius::same(6),
            ..Default::default()
        })
        .show(ctx, |ui| {
            // --- Breadcrumb bar ---
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;

                let can_go_back = !browser.path_stack.is_empty();
                let back_btn = egui::Button::new(
                    egui::RichText::new("⬅")
                        .color(if can_go_back { Color32::WHITE } else { SEPARATOR }),
                )
                .fill(if can_go_back { ACCENT } else { SEPARATOR })
                .corner_radius(egui::CornerRadius::same(3));
                if ui.add(back_btn).clicked() && can_go_back {
                    browser.path_stack.pop();
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate(browser.current_unc());
                }

                ui.add_space(4.0);

                let root_label = format!("\\\\{}\\{}", browser.host_ip, browser.share_name);
                if ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(&root_label)
                                .small()
                                .strong()
                                .color(Color32::from_rgb(80, 170, 255)),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    browser.path_stack.clear();
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate(browser.current_unc());
                }

                for (i, seg) in browser.path_stack.clone().iter().enumerate() {
                    ui.label(egui::RichText::new("›").small().color(TEXT_DIM));
                    if ui
                        .add(
                            egui::Label::new(
                                egui::RichText::new(seg)
                                    .small()
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .clicked()
                    {
                        browser.path_stack.truncate(i + 1);
                        browser.error = None;
                        browser.status = None;
                        action = BrowserAction::Navigate(browser.current_unc());
                    }
                }
            });

            ui.add_space(2.0);

            // --- Toolbar ---
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;

                let btn = |text: &str| {
                    egui::Button::new(
                        egui::RichText::new(text).small().color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(40, 46, 58))
                    .corner_radius(egui::CornerRadius::same(3))
                };

                if ui.add(btn("⬆ Upload")).clicked() {
                    action = BrowserAction::UploadDialog(browser.current_unc());
                }

                if ui.add(btn("📁+ New Folder")).clicked() {
                    browser.show_new_folder = !browser.show_new_folder;
                    browser.new_folder_name.clear();
                }

                if ui.add(btn("🔄")).clicked() {
                    browser.error = None;
                    browser.status = None;
                    action = BrowserAction::Navigate(browser.current_unc());
                }
            });

            // --- New folder input ---
            if browser.show_new_folder {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Name:").small().color(TEXT_DIM));
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut browser.new_folder_name)
                            .desired_width(180.0)
                            .font(egui::FontId::proportional(11.0)),
                    );
                    if browser.new_folder_name.is_empty() {
                        resp.request_focus();
                    }
                    let enter =
                        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let create_clicked = ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("✓").small().color(GREEN),
                            )
                            .fill(Color32::from_rgb(40, 46, 58))
                            .corner_radius(egui::CornerRadius::same(3)),
                        )
                        .clicked();

                    if (enter || create_clicked)
                        && !browser.new_folder_name.trim().is_empty()
                    {
                        let folder_name = browser.new_folder_name.trim().to_string();
                        let unc = browser.child_unc(&folder_name);
                        action = BrowserAction::CreateFolder(unc);
                        browser.new_folder_name.clear();
                        browser.show_new_folder = false;
                    }

                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("✕").small().color(TEXT_DIM),
                            )
                            .fill(Color32::TRANSPARENT)
                            .corner_radius(egui::CornerRadius::same(3)),
                        )
                        .clicked()
                    {
                        browser.show_new_folder = false;
                    }
                });
            }

            ui.add_space(2.0);
            ui.add(egui::Separator::default().spacing(4.0));

            // --- Status message ---
            if let Some((msg, success)) = &browser.status {
                let color = if *success {
                    GREEN
                } else {
                    Color32::from_rgb(220, 80, 80)
                };
                ui.label(egui::RichText::new(msg.as_str()).small().color(color));
                ui.add_space(2.0);
            }

            // --- Content ---
            if browser.loading {
                ui.centered_and_justified(|ui| {
                    ui.spinner();
                });
            } else if let Some(err) = &browser.error {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("⚠ {err}"))
                        .color(Color32::from_rgb(220, 80, 80)),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Use ⬅ or breadcrumbs to go back")
                        .small()
                        .italics()
                        .color(TEXT_DIM),
                );
            } else if browser.entries.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Empty directory")
                            .italics()
                            .color(TEXT_DIM),
                    );
                });
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let row_height = 20.0;
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
                                ui.ctx()
                                    .set_cursor_icon(egui::CursorIcon::PointingHand);
                            }

                            if row_response.hovered() {
                                ui.painter().rect_filled(
                                    row_rect,
                                    egui::CornerRadius::same(2),
                                    Color32::from_rgb(35, 42, 54),
                                );
                            }

                            // Draw content
                            let mut cursor_x = row_rect.left() + 4.0;
                            let text_y = row_rect.center().y;

                            let icon_galley = ui.painter().layout_no_wrap(
                                icon.to_string(),
                                egui::FontId::proportional(13.0),
                                Color32::WHITE,
                            );
                            ui.painter().galley(
                                egui::pos2(
                                    cursor_x,
                                    text_y - icon_galley.size().y / 2.0,
                                ),
                                icon_galley.clone(),
                                Color32::WHITE,
                            );
                            cursor_x += icon_galley.size().x + 6.0;

                            let name_color = if *is_dir {
                                Color32::WHITE
                            } else {
                                Color32::from_rgb(200, 205, 215)
                            };
                            let name_galley = ui.painter().layout_no_wrap(
                                entry_name.clone(),
                                egui::FontId {
                                    size: 11.0,
                                    family: egui::FontFamily::Proportional,
                                },
                                name_color,
                            );
                            ui.painter().galley(
                                egui::pos2(
                                    cursor_x,
                                    text_y - name_galley.size().y / 2.0,
                                ),
                                name_galley,
                                name_color,
                            );

                            if !is_dir {
                                let size_str =
                                    getexec_protocols::smb::format_size(*entry_size);
                                let size_galley = ui.painter().layout_no_wrap(
                                    size_str,
                                    egui::FontId::proportional(10.0),
                                    TEXT_DIM,
                                );
                                let size_x =
                                    row_rect.right() - size_galley.size().x - 6.0;
                                ui.painter().galley(
                                    egui::pos2(
                                        size_x,
                                        text_y - size_galley.size().y / 2.0,
                                    ),
                                    size_galley,
                                    TEXT_DIM,
                                );
                            }

                            // Left click → navigate into directory
                            if *is_dir && row_response.clicked() {
                                browser.path_stack.push(entry_name.clone());
                                browser.error = None;
                                browser.status = None;
                                action =
                                    BrowserAction::Navigate(browser.current_unc());
                            }

                            // Right-click context menu
                            row_response.context_menu(|ui| {
                                if *is_dir {
                                    if ui.button("🗑 Delete folder").clicked() {
                                        let unc = browser.child_unc(entry_name);
                                        action = BrowserAction::Delete {
                                            unc,
                                            is_dir: true,
                                        };
                                        ui.close();
                                    }
                                } else {
                                    if ui.button("⬇ Download").clicked() {
                                        let unc = browser.child_unc(entry_name);
                                        action = BrowserAction::DownloadDialog {
                                            unc,
                                            filename: entry_name.clone(),
                                        };
                                        ui.close();
                                    }
                                    if ui.button("🗑 Delete file").clicked() {
                                        let unc = browser.child_unc(entry_name);
                                        action = BrowserAction::Delete {
                                            unc,
                                            is_dir: false,
                                        };
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

pub enum BrowserAction {
    None,
    Navigate(String),
    DownloadDialog { unc: String, filename: String },
    UploadDialog(String),
    CreateFolder(String),
    Delete { unc: String, is_dir: bool },
}
