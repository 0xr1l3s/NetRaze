use eframe::CreationContext;
use egui::Color32;

use crate::runtime::{LogLevel, RuntimeServices};
use crate::state::AppState;
use crate::ui;
use crate::workspace;

pub struct NetRazeDesktopApp {
    state: AppState,
    runtime: RuntimeServices,
}

impl NetRazeDesktopApp {
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
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, text_dim);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5_f32, border);
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.inactive.bg_fill = bg_widget;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, text_primary);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(0.5_f32, border);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.hovered.bg_fill = bg_hover;
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, accent);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(2);

    visuals.widgets.active.bg_fill = accent_dark;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, accent);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(2);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(102, 27, 28, 80);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, accent);

    visuals.window_shadow = egui::Shadow::NONE;
    visuals.popup_shadow = egui::Shadow::NONE;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::Vec2::new(6.0, 4.0);
    style.spacing.button_padding = egui::Vec2::new(8.0, 3.0);
    ctx.set_style(style);
}

impl eframe::App for NetRazeDesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.poll_logs();

        // Process pending login attempts from workspace context menu
        for (ip, cred) in std::mem::take(&mut self.state.pending_logins) {
            self.runtime.spawn_login_attempt(
                ip,
                cred.username,
                cred.domain,
                cred.secret,
                cred.cred_type,
            );
        }

        // Process pending share enumeration requests
        for (node_id, ip, hostname, cred) in std::mem::take(&mut self.state.pending_share_enums) {
            self.runtime.spawn_share_enum(node_id, ip, hostname, cred);
        }

        // Process pending user enumeration requests
        for (node_id, ip, hostname, cred) in std::mem::take(&mut self.state.pending_user_enums) {
            self.runtime.spawn_user_enum(node_id, ip, hostname, cred);
        }

        // Process pending dump requests
        for (node_id, ip, hostname, dump_type, cred) in
            std::mem::take(&mut self.state.pending_dumps)
        {
            match dump_type.as_str() {
                "SAM" => self.runtime.spawn_dump_sam(node_id, ip, hostname, cred),
                "LSA" => self.runtime.spawn_dump_lsa(node_id, ip, hostname, cred),
                _ => {}
            }
        }

        // Process pending AV enumeration requests
        for (node_id, ip, hostname, cred) in std::mem::take(&mut self.state.pending_enumav) {
            self.runtime.spawn_enum_av(node_id, ip, hostname, cred);
        }

        // Process pending fingerprint requests
        for ip in std::mem::take(&mut self.state.pending_fingerprints) {
            self.runtime.spawn_fingerprint(ip);
        }

        // Process pending console exec commands
        for (console_id, ip, cred, command) in std::mem::take(&mut self.state.pending_exec_commands)
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

        // Process pending browse directory requests — (host, share, path,
        // credential) come off the browser state itself; the id is the index.
        for browser_id in std::mem::take(&mut self.state.pending_browse) {
            if let Some(browser) = self.state.share_browsers.get_mut(browser_id) {
                browser.loading = true;
                browser.error = None;
                let host = browser.host_ip.clone();
                let share = browser.share_name.clone();
                let rel_path = browser.current_rel_path();
                let cred = browser
                    .credential
                    .clone()
                    .map(|c| crate::runtime::cred_to_smb(&c));
                self.runtime
                    .spawn_browse_directory(browser_id, host, share, rel_path, cred);
            }
        }

        // Order: top bar first, then status_bar (bottom-most), then bottom triptych above it,
        // then side panels, then central panel fills remaining space.
        ui::show_top_bar(ctx, &mut self.state, &self.runtime);
        ui::show_status_bar(ctx, &mut self.state);
        ui::show_bottom_panel(ctx, &mut self.state);
        ui::show_right_panel(ctx, &mut self.state, &self.runtime);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(ctx.style().visuals.panel_fill))
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                match self.state.nav_tab {
                    crate::state::NavTab::Target => {
                        ui::targets_table::show(ui, &mut self.state);
                    }
                    crate::state::NavTab::CredentialManager => {
                        ui::credential_manager::show(ui, ctx, &mut self.state);
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
        // Process actions — payloads are entry names / rel paths; the
        // (host, share, credential) context comes off the browser state.
        for (idx, action) in browser_actions {
            let Some(browser) = self.state.share_browsers.get(idx) else {
                continue;
            };
            let host = browser.host_ip.clone();
            let share = browser.share_name.clone();
            let cred = browser
                .credential
                .clone()
                .map(|c| crate::runtime::cred_to_smb(&c));
            match action {
                ui::share_browser::BrowserAction::Navigate => {
                    // path_stack was already updated by the window — re-list.
                    self.state.pending_browse.push(idx);
                }
                ui::share_browser::BrowserAction::DownloadDialog { rel_path, filename } => {
                    let downloads = dirs_fallback();
                    let local_path = std::path::Path::new(&downloads)
                        .join(&filename)
                        .to_string_lossy()
                        .to_string();
                    self.runtime
                        .spawn_download(idx, host, share, rel_path, local_path, cred);
                }
                ui::share_browser::BrowserAction::UploadDialog => {
                    // Open native file picker; upload into the current dir.
                    let target_dir = browser.current_rel_path();
                    if let Some(path) = native_open_file_dialog() {
                        let filename = std::path::Path::new(&path)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "upload".to_string());
                        let rel_path = if target_dir.is_empty() {
                            filename
                        } else {
                            format!("{target_dir}\\{filename}")
                        };
                        self.runtime
                            .spawn_upload(idx, path, host, share, rel_path, cred);
                    }
                }
                ui::share_browser::BrowserAction::CreateFolder(folder_name) => {
                    let rel_path = browser.child_rel_path(&folder_name);
                    self.runtime
                        .spawn_create_folder(idx, host, share, rel_path, cred);
                }
                ui::share_browser::BrowserAction::Delete { rel_path, is_dir } => {
                    self.runtime
                        .spawn_delete(idx, host, share, rel_path, is_dir, cred);
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

/// Get a sensible download directory, per-platform:
/// Windows → `%USERPROFILE%\Downloads`, Unix → `$HOME/Downloads`,
/// with a temp-dir fallback.
fn dirs_fallback() -> String {
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let dl = std::path::Path::new(&profile).join("Downloads");
            if dl.is_dir() {
                return dl.to_string_lossy().to_string();
            }
            return profile;
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let dl = std::path::Path::new(&home).join("Downloads");
            if dl.is_dir() {
                return dl.to_string_lossy().to_string();
            }
            if std::path::Path::new(&home).is_dir() {
                return home;
            }
        }
    }
    std::env::temp_dir().to_string_lossy().to_string()
}

/// Open a native file open dialog (blocking). Returns the chosen file path,
/// or None if cancelled. Windows uses the PowerShell WinForms dialog; Unix
/// tries `zenity` then `kdialog` — no extra crate dependency either way.
fn native_open_file_dialog() -> Option<String> {
    #[cfg(windows)]
    {
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
    #[cfg(not(windows))]
    {
        // zenity: prints the chosen path to stdout, exit code 1 on cancel.
        if let Ok(output) = std::process::Command::new("zenity")
            .args(["--file-selection", "--title=Select file to upload"])
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
            // Cancelled or printed nothing — fall through only on tool
            // absence, not on user cancel.
            if output.status.code() == Some(0) || output.status.code() == Some(1) {
                return None;
            }
        }
        // kdialog: same contract (exit 1 on cancel).
        if let Ok(output) = std::process::Command::new("kdialog")
            .args([
                "--getopenfilename",
                ".",
                "All Files (*)",
                "Select file to upload",
            ])
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
        None
    }
}
