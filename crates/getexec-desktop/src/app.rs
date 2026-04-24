use eframe::CreationContext;
use egui::Color32;

use crate::runtime::{LogLevel, RuntimeServices};
use crate::state::AppState;
use crate::ui;
use crate::workspace;

pub struct GetexecDesktopApp {
    state: AppState,
    runtime: RuntimeServices,
}

impl GetexecDesktopApp {
    pub fn new(cc: &CreationContext<'_>) -> Self {
        setup_cobalt_theme(&cc.egui_ctx);

        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
        let runtime = RuntimeServices::new(log_tx);
        runtime.spawn_heartbeat();

        Self {
            state: AppState::new(log_rx),
            runtime,
        }
    }
}

fn setup_cobalt_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    let bg_dark = Color32::from_rgb(18, 21, 28); // #12151c
    let bg_panel = Color32::from_rgb(27, 34, 44); // #1b222c
    let bg_widget = Color32::from_rgb(25, 29, 38); // #191d26
    let bg_hover = Color32::from_rgb(35, 40, 52); // slightly lighter widget
    let accent = Color32::from_rgb(102, 27, 28); // #661b1c
    let accent_dark = Color32::from_rgb(83, 21, 22); // #531516
    let text_primary = Color32::WHITE;
    let text_dim = Color32::from_rgb(160, 165, 175);
    let border = Color32::from_rgb(40, 46, 58);

    visuals.panel_fill = bg_panel;
    visuals.window_fill = bg_panel;
    visuals.extreme_bg_color = bg_dark;
    visuals.faint_bg_color = bg_widget;

    visuals.widgets.noninteractive.bg_fill = bg_widget;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_dim);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, border);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.inactive.bg_fill = bg_widget;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text_primary);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, border);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.hovered.bg_fill = bg_hover;
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.active.bg_fill = accent_dark;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, accent);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(2);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(102, 27, 28, 80);
    visuals.selection.stroke = egui::Stroke::new(1.0, accent);

    visuals.window_shadow = egui::Shadow::NONE;
    visuals.popup_shadow = egui::Shadow::NONE;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::Vec2::new(6.0, 4.0);
    style.spacing.button_padding = egui::Vec2::new(8.0, 3.0);
    ctx.set_style(style);
}

impl eframe::App for GetexecDesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.poll_logs();

        // Process pending login attempts from workspace context menu
        for (ip, cred) in self.state.pending_logins.drain(..).collect::<Vec<_>>() {
            self.runtime.spawn_login_attempt(
                ip,
                cred.username,
                cred.domain,
                cred.secret,
                cred.cred_type,
            );
        }

        // Process pending share enumeration requests
        for (node_id, ip, hostname) in self.state.pending_share_enums.drain(..).collect::<Vec<_>>()
        {
            self.runtime.spawn_share_enum(node_id, ip, hostname);
        }

        // Process pending user enumeration requests
        for (node_id, ip, hostname) in self.state.pending_user_enums.drain(..).collect::<Vec<_>>() {
            self.runtime.spawn_user_enum(node_id, ip, hostname);
        }

        // Process pending dump requests
        for (node_id, ip, hostname, dump_type) in
            self.state.pending_dumps.drain(..).collect::<Vec<_>>()
        {
            match dump_type.as_str() {
                "SAM" => self.runtime.spawn_dump_sam(node_id, ip, hostname),
                "LSA" => self.runtime.spawn_dump_lsa(node_id, ip, hostname),
                _ => {}
            }
        }

        // Process pending AV enumeration requests
        for (node_id, ip, hostname, username, domain, secret) in
            self.state.pending_enumav.drain(..).collect::<Vec<_>>()
        {
            self.runtime
                .spawn_enum_av(node_id, ip, hostname, username, domain, secret);
        }

        // Process pending fingerprint requests
        for ip in self
            .state
            .pending_fingerprints
            .drain(..)
            .collect::<Vec<_>>()
        {
            self.runtime.spawn_fingerprint(ip);
        }

        // Process pending console exec commands
        for (console_id, ip, cred, command) in self
            .state
            .pending_exec_commands
            .drain(..)
            .collect::<Vec<_>>()
        {
            self.runtime.spawn_exec_command(
                console_id,
                ip,
                cred.username,
                cred.domain,
                cred.secret,
                cred.cred_type,
                command,
            );
        }

        // Process pending browse directory requests
        {
            let pending: Vec<String> = self.state.pending_browse.drain(..).collect();
            for unc_path in pending {
                // Find the browser index for this UNC path
                if let Some(idx) = self
                    .state
                    .share_browsers
                    .iter()
                    .position(|b| b.current_unc() == unc_path)
                {
                    self.state.share_browsers[idx].loading = true;
                    self.state.share_browsers[idx].error = None;
                    self.runtime.spawn_browse_directory(idx, unc_path);
                }
            }
        }

        // Order: top bar first, then status_bar (bottom-most), then bottom triptych above it,
        // then side panels, then central panel fills remaining space.
        ui::show_top_bar(ctx, &mut self.state, &self.runtime);
        ui::show_status_bar(ctx, &mut self.state);
        ui::show_bottom_panel(ctx, &mut self.state);
        ui::show_left_panel(ctx, &mut self.state, &self.runtime);
        ui::show_right_panel(ctx, &mut self.state, &self.runtime);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(ctx.style().visuals.panel_fill))
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                match self.state.nav_tab {
                    crate::state::NavTab::Targets => {
                        ui::targets_table::show(ui, &mut self.state);
                    }
                    _ => {
                        ui::workflow_canvas::show(ui, &mut self.state);
                    }
                }
            });

        // Render share browser windows
        let mut browser_actions: Vec<(usize, ui::share_browser::BrowserAction)> = Vec::new();
        for (idx, browser) in self.state.share_browsers.iter_mut().enumerate() {
            let action = ui::share_browser::show_browser_window(ctx, browser);
            match &action {
                ui::share_browser::BrowserAction::None => {}
                _ => browser_actions.push((idx, action)),
            }
        }
        // Remove closed browsers
        self.state.share_browsers.retain(|b| b.open);
        // Process actions
        for (idx, action) in browser_actions {
            match action {
                ui::share_browser::BrowserAction::Navigate(_) => {
                    if let Some(browser) = self.state.share_browsers.get(idx) {
                        let unc = browser.current_unc();
                        self.state.pending_browse.push(unc);
                    }
                }
                ui::share_browser::BrowserAction::DownloadDialog { unc, filename } => {
                    // Use native file dialog via rfd or fallback to Downloads folder
                    let downloads = dirs_fallback();
                    let local_path = format!("{}\\{}", downloads, filename);
                    self.runtime.spawn_download(idx, unc, local_path);
                }
                ui::share_browser::BrowserAction::UploadDialog(target_dir) => {
                    // Open native file picker
                    let target = target_dir.clone();
                    let rt = &self.runtime;
                    if let Some(path) = native_open_file_dialog() {
                        let filename = std::path::Path::new(&path)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "upload".to_string());
                        let remote = format!("{}\\{}", target, filename);
                        rt.spawn_upload(idx, path, remote);
                    }
                }
                ui::share_browser::BrowserAction::CreateFolder(unc) => {
                    self.runtime.spawn_create_folder(idx, unc);
                }
                ui::share_browser::BrowserAction::Delete { unc, is_dir } => {
                    self.runtime.spawn_delete(idx, unc, is_dir);
                }
                ui::share_browser::BrowserAction::None => {}
            }
        }

        // Render console windows
        let mut console_submissions: Vec<(u64, String, crate::state::CredentialRecord, String)> =
            Vec::new();
        for console in self.state.consoles.iter_mut() {
            match ui::console::show_console_window(ctx, console) {
                ui::console::ConsoleAction::Submit(cmd) => {
                    console_submissions.push((
                        console.id,
                        console.host_ip.clone(),
                        console.credential.clone(),
                        cmd,
                    ));
                }
                ui::console::ConsoleAction::None => {}
            }
        }
        self.state.consoles.retain(|c| c.open);
        for sub in console_submissions {
            self.state.pending_exec_commands.push(sub);
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

pub fn save_current_workspace(state: &mut AppState, runtime: &RuntimeServices) {
    let save = state.to_save();
    match workspace::save_workspace(std::path::Path::new(&state.workspace_path), &save) {
        Ok(()) => state.add_log(
            LogLevel::Success,
            format!("Workspace saved to {}", state.workspace_path),
        ),
        Err(error) => runtime.emit_error(format!("Save failed: {error}")),
    }
}

pub fn load_current_workspace(state: &mut AppState, runtime: &RuntimeServices) {
    match workspace::load_workspace(std::path::Path::new(&state.workspace_path)) {
        Ok(save) => {
            state.load_from(save);
            state.add_log(
                LogLevel::Success,
                format!("Workspace loaded from {}", state.workspace_path),
            );
        }
        Err(error) => runtime.emit_error(format!("Load failed: {error}")),
    }
}

/// Get a sensible download directory (USERPROFILE\Downloads or fallback to temp).
fn dirs_fallback() -> String {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let dl = format!("{}\\Downloads", profile);
        if std::path::Path::new(&dl).is_dir() {
            return dl;
        }
        return profile;
    }
    std::env::temp_dir().to_string_lossy().to_string()
}

/// Open a native file open dialog (blocking). Returns the chosen file path, or None if cancelled.
fn native_open_file_dialog() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Title = 'Select file to upload'; if ($f.ShowDialog() -eq 'OK') { $f.FileName } else { '' }"#,
        ])
        .output()
        .ok()?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}
