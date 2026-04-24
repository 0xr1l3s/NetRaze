use egui::Color32;

use crate::state::CredentialRecord;

const PANEL_BG: Color32 = Color32::from_rgb(27, 34, 44);
const SEPARATOR: Color32 = Color32::from_rgb(40, 46, 58);
const TEXT_DIM: Color32 = Color32::from_rgb(160, 165, 175);
const ACCENT: Color32 = Color32::from_rgb(102, 27, 28);
const PROMPT_COLOR: Color32 = Color32::from_rgb(80, 200, 120);
const ERROR_COLOR: Color32 = Color32::from_rgb(210, 60, 60);
const OUTPUT_COLOR: Color32 = Color32::from_rgb(210, 215, 225);

/// One entry in the console scrollback.
#[derive(Debug, Clone)]
pub struct ConsoleEntry {
    pub command: String,
    pub output: String,
    pub error: Option<String>,
}

/// State for a single console window bound to a pwned host.
#[derive(Debug, Clone)]
pub struct ConsoleState {
    pub id: u64,
    pub open: bool,
    pub host_ip: String,
    pub hostname: String,
    pub credential: CredentialRecord,
    pub cred_label: String,
    pub input: String,
    pub history: Vec<ConsoleEntry>,
    pub pending: bool,
    /// Set to true when a result arrives so the input regains focus on next frame.
    pub request_focus: bool,
}

impl ConsoleState {
    pub fn new(id: u64, host_ip: String, hostname: String, credential: CredentialRecord) -> Self {
        let cred_label = if credential.domain.is_empty() || credential.domain == "." {
            format!(".\\{}", credential.username)
        } else {
            format!("{}\\{}", credential.domain, credential.username)
        };
        Self {
            id,
            open: true,
            host_ip,
            hostname,
            credential,
            cred_label,
            input: String::new(),
            history: Vec::new(),
            pending: false,
            request_focus: true,
        }
    }

    pub fn push_result(&mut self, command: String, output: String, error: Option<String>) {
        self.history.push(ConsoleEntry {
            command,
            output,
            error,
        });
        self.pending = false;
        self.request_focus = true;
    }
}

pub enum ConsoleAction {
    None,
    Submit(String),
}

pub fn show_console_window(ctx: &egui::Context, console: &mut ConsoleState) -> ConsoleAction {
    let mut action = ConsoleAction::None;
    if !console.open {
        return action;
    }

    let title_host = if console.hostname.is_empty() {
        console.host_ip.clone()
    } else {
        format!("{} ({})", console.hostname, console.host_ip)
    };
    let title = format!("Console — {title_host}");
    let mut is_open = console.open;
    let window_id = egui::Id::new(("console_window", console.id));

    egui::Window::new(title)
        .id(window_id)
        .open(&mut is_open)
        .default_size([640.0, 420.0])
        .min_size([420.0, 260.0])
        .max_width(1100.0)
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
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("as").size(11.0).color(TEXT_DIM));
                ui.label(
                    egui::RichText::new(&console.cred_label)
                        .size(11.0)
                        .color(Color32::WHITE)
                        .monospace(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if console.pending {
                        ui.label(
                            egui::RichText::new("running…")
                                .size(11.0)
                                .color(ACCENT)
                                .strong(),
                        );
                    }
                });
            });
            ui.separator();

            // Scrollback
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(ui.available_height() - 38.0)
                .show(ui, |ui| {
                    ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);
                    for entry in &console.history {
                        ui.label(
                            egui::RichText::new(format!("> {}", entry.command))
                                .size(12.0)
                                .color(PROMPT_COLOR)
                                .strong()
                                .monospace(),
                        );
                        if let Some(err) = &entry.error {
                            ui.label(
                                egui::RichText::new(err)
                                    .size(12.0)
                                    .color(ERROR_COLOR)
                                    .monospace(),
                            );
                        }
                        if !entry.output.is_empty() {
                            ui.label(
                                egui::RichText::new(&entry.output)
                                    .size(12.0)
                                    .color(OUTPUT_COLOR)
                                    .monospace(),
                            );
                        }
                        ui.add_space(2.0);
                    }
                });

            ui.separator();

            // Input line — compute width explicitly so the window does not stretch.
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(">")
                        .size(13.0)
                        .color(PROMPT_COLOR)
                        .strong()
                        .monospace(),
                );
                let button_width = 54.0;
                let spacing = 12.0;
                let edit_width = (ui.available_width() - button_width - spacing).max(120.0);
                let resp = ui.add_enabled(
                    !console.pending,
                    egui::TextEdit::singleline(&mut console.input)
                        .desired_width(edit_width)
                        .font(egui::TextStyle::Monospace),
                );
                if console.request_focus && !console.pending {
                    resp.request_focus();
                    console.request_focus = false;
                }
                let submit_on_enter =
                    resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let run_clicked = ui
                    .add_enabled(
                        !console.pending && !console.input.trim().is_empty(),
                        egui::Button::new(egui::RichText::new("Run").size(12.0)),
                    )
                    .clicked();

                if (submit_on_enter || run_clicked) && !console.input.trim().is_empty() {
                    let cmd = console.input.trim().to_owned();
                    console.input.clear();
                    console.pending = true;
                    action = ConsoleAction::Submit(cmd);
                    resp.request_focus();
                }
            });
        });

    console.open = is_open;
    action
}
