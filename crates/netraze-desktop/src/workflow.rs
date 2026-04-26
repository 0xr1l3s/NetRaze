use egui::{Color32, Pos2, Rect, Stroke, Style, Ui};
use egui_snarl::ui::{BackgroundPattern, SnarlStyle, SnarlViewer};
use egui_snarl::{InPin, NodeId, OutPin, Snarl, ui::PinInfo};
use serde::{Deserialize, Serialize};

use crate::state::CredentialRecord;

const DOT_COLOR: Color32 = Color32::from_rgb(40, 46, 58);
const DOT_SPACING: f32 = 20.0;
const DOT_RADIUS: f32 = 0.8;

// HostNode card palette — hoisted to module scope so they're shared
// between `render_host_card` (used by `show_body`) and `show_on_hover_popup`.
const HOST_PRIMARY: Color32 = Color32::from_rgb(235, 240, 250);
const HOST_MUTED: Color32 = Color32::from_rgb(150, 155, 165);
const HOST_OK: Color32 = Color32::from_rgb(80, 200, 120);
const HOST_WARN: Color32 = Color32::from_rgb(220, 170, 60);
const HOST_BAD: Color32 = Color32::from_rgb(210, 60, 60);
const HOST_ADMIN_PURPLE: Color32 = Color32::from_rgb(170, 110, 210);
const HOST_CHIP_NEUTRAL: Color32 = Color32::from_rgb(120, 150, 180);

/// Fixed width for the HostNode body card. Must be narrow enough that the
/// frame never exceeds the header width on screen.
const HOST_BODY_W: f32 = 240.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowNode {
    TargetInput {
        target: String,
    },
    ProtocolModule {
        protocol: String,
    },
    CredentialNode {
        username: String,
        secret: String,
    },
    ActionNode {
        action: String,
    },
    OutputNode {
        format: String,
    },
    GenericModule {
        name: String,
    },
    HostNode {
        ip: String,
        hostname: String,
        os_info: String,
        #[serde(default)]
        domain: String,
        #[serde(default)]
        signing: Option<bool>,
        #[serde(default)]
        smbv1: Option<bool>,
        shares: Vec<String>,
        admin: bool,
        users: Vec<String>,
        #[serde(default)]
        logged_in_cred: Option<String>,
    },
    SharesNode {
        host_ip: String,
        hostname: String,
        shares: Vec<String>,
    },
    UsersNode {
        host_ip: String,
        hostname: String,
        users: Vec<UserEntry>,
    },
    DumpNode {
        host_ip: String,
        hostname: String,
        dump_type: String,
        entries: Vec<String>,
        #[serde(default)]
        error: Option<String>,
    },
    EnumAvNode {
        host_ip: String,
        hostname: String,
        /// Each entry: "ProductName|status" where status = INSTALLED, RUNNING, INSTALLED and RUNNING
        products: Vec<String>,
        #[serde(default)]
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub name: String,
    pub disabled: bool,
    pub locked: bool,
    pub privilege_level: u32,
}

/// Status colour used for the coloured border around a HostNode.
/// Returns `None` for non-host nodes (keep the default frame stroke).
fn host_status_color(node: &WorkflowNode) -> Option<Color32> {
    const UNKNOWN: Color32 = Color32::from_rgb(80, 90, 105);
    match node {
        WorkflowNode::HostNode {
            admin,
            smbv1,
            logged_in_cred,
            ..
        } => {
            if *admin {
                Some(HOST_OK)
            } else if matches!(smbv1, Some(true)) {
                Some(HOST_BAD)
            } else if logged_in_cred.is_some() {
                Some(HOST_WARN)
            } else {
                Some(UNKNOWN)
            }
        }
        _ => None,
    }
}

/// Draw a small rounded status/counter chip.
fn host_chip(ui: &mut Ui, text: &str, fg: Color32) {
    let bg = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 36);
    egui::Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0, fg.gamma_multiply(0.55)))
        .corner_radius(egui::CornerRadius::same(3))
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).small().strong().color(fg));
        });
}

/// Render the compact HostNode card body (OS line + domain line + chips
/// row + optional credential line). Called from `show_body`. Width is
/// expected to be pre-constrained by the caller to `HOST_BODY_W`.
#[allow(clippy::too_many_arguments)]
fn render_host_card(
    ui: &mut Ui,
    os_info: &str,
    domain: &str,
    signing: Option<bool>,
    smbv1: Option<bool>,
    shares: &[String],
    admin: bool,
    users: &[String],
    logged_in_cred: Option<&str>,
) {
    // Bloc 1 — OS + domain (pas de duplication de l'identité affichée dans le header).
    if !os_info.is_empty() {
        ui.label(
            egui::RichText::new(shorten_os(os_info))
                .color(HOST_PRIMARY)
                .family(egui::FontFamily::Monospace),
        );
    }
    if !domain.is_empty() {
        ui.label(
            egui::RichText::new(domain)
                .small()
                .color(HOST_MUTED)
                .family(egui::FontFamily::Monospace),
        );
    }

    // Bloc 2 — chips status + compteurs sur une seule rangée wrappée.
    let show_signing = matches!(signing, Some(true));
    let show_smbv1 = matches!(smbv1, Some(true));
    let any_chip = admin || show_signing || show_smbv1 || !shares.is_empty() || !users.is_empty();
    if any_chip {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
            if admin {
                host_chip(ui, "ADMIN", HOST_ADMIN_PURPLE);
            }
            if show_signing {
                host_chip(ui, "signing", HOST_OK);
            }
            if show_smbv1 {
                host_chip(ui, "SMBv1", HOST_BAD);
            }
            if !shares.is_empty() {
                host_chip(ui, &format!("📂 {}", shares.len()), HOST_CHIP_NEUTRAL);
            }
            if !users.is_empty() {
                host_chip(ui, &format!("👥 {}", users.len()), HOST_CHIP_NEUTRAL);
            }
        });
    }

    // Bloc 3 — credential pwné (conditionnel).
    if let Some(cred) = logged_in_cred {
        ui.add_space(4.0);
        let (text, color) = if admin {
            (format!("🔐 {cred} — Pwn3d!"), HOST_OK)
        } else {
            (cred.to_string(), HOST_WARN)
        };
        ui.label(
            egui::RichText::new(text)
                .small()
                .strong()
                .color(color)
                .family(egui::FontFamily::Monospace),
        );
    }
}

impl WorkflowNode {
    pub fn label(&self) -> String {
        match self {
            WorkflowNode::TargetInput { .. } => "Target Input".to_owned(),
            WorkflowNode::ProtocolModule { protocol } => format!("Protocol: {protocol}"),
            WorkflowNode::CredentialNode { .. } => "Credential Node".to_owned(),
            WorkflowNode::ActionNode { action } => format!("Action: {action}"),
            WorkflowNode::OutputNode { .. } => "Output Node".to_owned(),
            WorkflowNode::GenericModule { name } => format!("Module: {name}"),
            WorkflowNode::HostNode { ip, hostname, .. } => {
                if hostname.is_empty() || hostname == ip {
                    format!("🖥 {ip}")
                } else {
                    format!("🖥 {ip} ({hostname})")
                }
            }
            WorkflowNode::SharesNode {
                host_ip,
                hostname,
                shares: _,
            } => {
                let host = if hostname.is_empty() {
                    host_ip.as_str()
                } else {
                    hostname.as_str()
                };
                format!("📂 Shares — {host}")
            }
            WorkflowNode::UsersNode {
                host_ip,
                hostname,
                users,
            } => {
                let host = if hostname.is_empty() {
                    host_ip.as_str()
                } else {
                    hostname.as_str()
                };
                format!("👥 Users ({}) — {host}", users.len())
            }
            WorkflowNode::DumpNode {
                host_ip,
                hostname,
                dump_type,
                entries,
                ..
            } => {
                let host = if hostname.is_empty() {
                    host_ip.as_str()
                } else {
                    hostname.as_str()
                };
                let icon = if dump_type == "SAM" { "🔑" } else { "🔓" };
                format!("{icon} {dump_type} ({}) — {host}", entries.len())
            }
            WorkflowNode::EnumAvNode {
                host_ip,
                hostname,
                products,
                ..
            } => {
                let host = if hostname.is_empty() {
                    host_ip.as_str()
                } else {
                    hostname.as_str()
                };
                format!("🛡 AV/EDR ({}) — {host}", products.len())
            }
        }
    }

    /// Display label for the logged-in credential, if any.
    pub fn logged_in_label(&self) -> Option<&str> {
        match self {
            WorkflowNode::HostNode { logged_in_cred, .. } => logged_in_cred.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDocument {
    pub name: String,
    pub snarl: Snarl<WorkflowNode>,
}

impl WorkflowDocument {
    pub fn with_default_chain() -> Self {
        Self {
            name: "workspace".to_owned(),
            snarl: Snarl::new(),
        }
    }

    pub fn add_module_node(&mut self, name: String, pos: Pos2) {
        let node = if name == "SMB"
            || name == "LDAP"
            || name == "RDP"
            || name == "WinRM"
            || name == "MSSQL"
            || name == "SSH"
            || name == "FTP"
            || name == "Kerberos"
        {
            WorkflowNode::ProtocolModule { protocol: name }
        } else if name.starts_with("--") {
            WorkflowNode::ActionNode { action: name }
        } else {
            WorkflowNode::GenericModule { name }
        };

        self.snarl.insert_node(pos, node);
    }

    /// Add a discovered host as a node in the workspace canvas.
    /// Returns true if the node was actually added (not a duplicate).
    pub fn add_host_node(
        &mut self,
        ip: String,
        hostname: String,
        os_info: String,
        shares: Vec<String>,
        admin: bool,
        users: Vec<String>,
    ) -> bool {
        // Check if host already exists
        for node in self.snarl.nodes() {
            if let WorkflowNode::HostNode { ip: existing, .. } = node {
                if *existing == ip {
                    return false; // already in workspace
                }
            }
        }

        // Place new node, stagger based on existing node count
        let count = self.snarl.nodes().count() as f32;
        let col = count % 4.0;
        let row = (count / 4.0).floor();
        let pos = Pos2::new(40.0 + col * 280.0, 40.0 + row * 200.0);

        // Collapsed by default so the workspace stays readable when many
        // hosts land at once — users expand what they want to inspect.
        self.snarl.insert_node_collapsed(
            pos,
            WorkflowNode::HostNode {
                ip,
                hostname,
                os_info,
                domain: String::new(),
                signing: None,
                smbv1: None,
                shares,
                admin,
                users,
                logged_in_cred: None,
            },
        );
        true
    }

    /// Build our custom SnarlStyle with subtle dot-grid background.
    pub fn snarl_style() -> SnarlStyle {
        let mut style = SnarlStyle::new();
        // We'll draw our own dot pattern via draw_background override
        style.bg_pattern = Some(BackgroundPattern::NoPattern);
        style.bg_pattern_stroke = Some(Stroke::NONE);
        // Re-rasterize glyphs at the zoomed size instead of bilinear-scaling
        // the original texture — keeps node labels sharp when zooming in.
        style.crisp_magnified_text = Some(true);
        style
    }
}

pub struct WorkflowViewer {
    pub credentials: Vec<CredentialRecord>,
    pub login_requests: Vec<(String, CredentialRecord)>,
    /// (source_node_id_raw, host_ip, hostname, credential) — trigger async share enum
    pub shares_requests: Vec<(NodeId, String, String, CredentialRecord)>,
    /// (host_ip, share_name) — open browser window
    pub browse_requests: Vec<(String, String)>,
    /// (source_node_id, host_ip, hostname, credential) — trigger async user enum
    pub users_requests: Vec<(NodeId, String, String, CredentialRecord)>,
    /// (source_node_id, host_ip, hostname, dump_type, credential) — trigger async dump
    pub dump_requests: Vec<(NodeId, String, String, String, CredentialRecord)>,
    /// (source_node_id, host_ip, hostname, credential) — trigger async AV enum
    pub enumav_requests: Vec<(NodeId, String, String, CredentialRecord)>,
    /// IPs to fingerprint
    pub fingerprint_requests: Vec<String>,
    /// (host_ip, hostname, credential) — open a console window for a pwned host
    pub console_requests: Vec<(String, String, CredentialRecord)>,
}

impl WorkflowViewer {
    pub fn new(credentials: Vec<CredentialRecord>) -> Self {
        Self {
            credentials,
            login_requests: Vec::new(),
            shares_requests: Vec::new(),
            browse_requests: Vec::new(),
            users_requests: Vec::new(),
            dump_requests: Vec::new(),
            enumav_requests: Vec::new(),
            fingerprint_requests: Vec::new(),
            console_requests: Vec::new(),
        }
    }

    /// Resolve a `CredentialRecord` from its display label (e.g. `DOMAIN\user`).
    fn resolve_cred(&self, label: &Option<String>) -> Option<CredentialRecord> {
        let label = label.as_ref()?;
        for c in &self.credentials {
            let cl = if c.domain.is_empty() {
                format!(".\\{}", c.username)
            } else {
                format!("{}\\{}", c.domain, c.username)
            };
            if &cl == label {
                return Some(c.clone());
            }
        }
        None
    }
}

impl SnarlViewer<WorkflowNode> for WorkflowViewer {
    fn title(&mut self, node: &WorkflowNode) -> String {
        node.label()
    }

    fn inputs(&mut self, node: &WorkflowNode) -> usize {
        match node {
            WorkflowNode::TargetInput { .. } => 0,
            WorkflowNode::ProtocolModule { .. } => 1,
            WorkflowNode::CredentialNode { .. } => 0,
            WorkflowNode::ActionNode { .. } => 1,
            WorkflowNode::OutputNode { .. } => 1,
            WorkflowNode::GenericModule { .. } => 1,
            WorkflowNode::HostNode { .. } => 0,
            WorkflowNode::SharesNode { .. } => 1,
            WorkflowNode::UsersNode { .. } => 1,
            WorkflowNode::DumpNode { .. } => 1,
            WorkflowNode::EnumAvNode { .. } => 1,
        }
    }

    fn outputs(&mut self, node: &WorkflowNode) -> usize {
        match node {
            WorkflowNode::TargetInput { .. } => 1,
            WorkflowNode::ProtocolModule { .. } => 1,
            WorkflowNode::CredentialNode { .. } => 1,
            WorkflowNode::ActionNode { .. } => 1,
            WorkflowNode::OutputNode { .. } => 0,
            WorkflowNode::GenericModule { .. } => 1,
            WorkflowNode::HostNode { .. } => 1,
            WorkflowNode::SharesNode { .. } => 0,
            WorkflowNode::UsersNode { .. } => 0,
            WorkflowNode::DumpNode { .. } => 0,
            WorkflowNode::EnumAvNode { .. } => 0,
        }
    }

    fn show_input(
        &mut self,
        pin: &InPin,
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) -> impl egui_snarl::ui::SnarlPin + 'static {
        match &snarl[pin.id.node] {
            WorkflowNode::ProtocolModule { .. } => {
                ui.label("target");
            }
            WorkflowNode::CredentialNode { .. } => {
                ui.label("-");
            }
            WorkflowNode::ActionNode { .. } => {
                ui.label("protocol");
            }
            WorkflowNode::OutputNode { .. } => {
                ui.label("results");
            }
            WorkflowNode::GenericModule { .. } => {
                ui.label("in");
            }
            WorkflowNode::TargetInput { .. } => {
                ui.label("-");
            }
            WorkflowNode::HostNode { .. } => {
                ui.label("-");
            }
            WorkflowNode::SharesNode {
                host_ip: _,
                hostname: _,
                shares,
            } => {
                ui.set_min_width(200.0);
                ui.set_max_width(280.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    if shares.is_empty() {
                        ui.label(
                            egui::RichText::new("⚠ No shares found")
                                .small()
                                .color(Color32::from_rgb(220, 170, 60)),
                        );
                    } else {
                        for share_str in shares.iter() {
                            let (name, stype, access) = parse_share_string(share_str);

                            let access_color = match access {
                                "RW" => Color32::from_rgb(80, 200, 120),
                                "R" => Color32::from_rgb(80, 170, 255),
                                _ => Color32::from_rgb(180, 60, 60),
                            };

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.0;
                                ui.label(egui::RichText::new("📁").small());
                                ui.label(
                                    egui::RichText::new(name)
                                        .small()
                                        .strong()
                                        .color(Color32::WHITE),
                                );
                                ui.label(
                                    egui::RichText::new(format!("[{stype}]"))
                                        .small()
                                        .color(Color32::from_rgb(100, 105, 115)),
                                );
                                let badge = egui::Button::new(
                                    egui::RichText::new(access)
                                        .small()
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(access_color)
                                .corner_radius(egui::CornerRadius::same(3))
                                .stroke(egui::Stroke::NONE)
                                .sense(egui::Sense::hover());
                                ui.add(badge);
                            });
                        }
                    }
                });
            }
            WorkflowNode::UsersNode {
                host_ip: _,
                hostname: _,
                users,
            } => {
                ui.set_min_width(180.0);
                ui.set_max_width(250.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    if users.is_empty() {
                        ui.label(
                            egui::RichText::new("⚠ No users found")
                                .small()
                                .color(Color32::from_rgb(220, 170, 60)),
                        );
                    } else {
                        for user in users.iter() {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.0;
                                ui.label(egui::RichText::new("👤").small());

                                let name_color = if user.disabled {
                                    Color32::from_rgb(120, 120, 130)
                                } else {
                                    Color32::WHITE
                                };
                                ui.label(
                                    egui::RichText::new(&user.name)
                                        .small()
                                        .strong()
                                        .color(name_color),
                                );

                                // Privilege badge
                                let (priv_label, priv_color) = match user.privilege_level {
                                    2 => ("ADMIN", Color32::from_rgb(220, 60, 60)),
                                    1 => ("USER", Color32::from_rgb(80, 170, 255)),
                                    _ => ("GUEST", Color32::from_rgb(120, 120, 130)),
                                };
                                let badge = egui::Button::new(
                                    egui::RichText::new(priv_label)
                                        .small()
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(priv_color)
                                .corner_radius(egui::CornerRadius::same(3))
                                .stroke(egui::Stroke::NONE)
                                .sense(egui::Sense::hover());
                                ui.add(badge);

                                if user.disabled {
                                    ui.label(
                                        egui::RichText::new("DISABLED")
                                            .small()
                                            .color(Color32::from_rgb(160, 100, 60)),
                                    );
                                }
                                if user.locked {
                                    ui.label(egui::RichText::new("🔒").small());
                                }
                            });
                        }
                    }
                });
            }
            WorkflowNode::DumpNode {
                host_ip: _,
                hostname: _,
                dump_type,
                entries,
                error,
            } => {
                ui.set_min_width(280.0);
                ui.set_max_width(400.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 3.0;
                    if let Some(err) = error {
                        ui.label(
                            egui::RichText::new(format!("⚠ {err}"))
                                .small()
                                .color(Color32::from_rgb(220, 170, 60)),
                        );
                    }
                    if entries.is_empty() && error.is_none() {
                        ui.label(
                            egui::RichText::new("⏳ Dumping...")
                                .small()
                                .color(Color32::from_rgb(160, 165, 175)),
                        );
                    }
                    let is_sam = dump_type == "SAM";
                    for entry in entries.iter() {
                        if is_sam {
                            // SAM format: username:rid:lm:nt:::
                            let parts: Vec<&str> = entry.splitn(7, ':').collect();
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 2.0;
                                if parts.len() >= 4 {
                                    ui.label(
                                        egui::RichText::new(parts[0])
                                            .small()
                                            .strong()
                                            .color(Color32::WHITE)
                                            .family(egui::FontFamily::Monospace),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!(":{}", parts[1]))
                                            .small()
                                            .color(Color32::from_rgb(160, 165, 175))
                                            .family(egui::FontFamily::Monospace),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!(
                                            ":{}:{}:::",
                                            parts[2], parts[3]
                                        ))
                                        .small()
                                        .color(Color32::from_rgb(80, 200, 120))
                                        .family(egui::FontFamily::Monospace),
                                    );
                                } else {
                                    ui.label(
                                        egui::RichText::new(entry)
                                            .small()
                                            .color(Color32::WHITE)
                                            .family(egui::FontFamily::Monospace),
                                    );
                                }
                            });
                        } else {
                            // LSA format: key: value or just name
                            ui.label(
                                egui::RichText::new(entry)
                                    .small()
                                    .color(Color32::from_rgb(200, 160, 255))
                                    .family(egui::FontFamily::Monospace),
                            );
                        }
                    }
                });
            }
            WorkflowNode::EnumAvNode {
                products, error, ..
            } => {
                ui.set_min_width(260.0);
                ui.set_max_width(380.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 3.0;
                    if let Some(err) = error {
                        ui.label(
                            egui::RichText::new(format!("⚠ {err}"))
                                .small()
                                .color(Color32::from_rgb(220, 170, 60)),
                        );
                    }
                    if products.is_empty() && error.is_none() {
                        ui.label(
                            egui::RichText::new("⏳ Scanning...")
                                .small()
                                .color(Color32::from_rgb(160, 165, 175)),
                        );
                    }
                    for product_line in products.iter() {
                        // Format: "ProductName|status"
                        let (name, status) =
                            product_line.split_once('|').unwrap_or((product_line, ""));
                        let (icon, color) = match status {
                            "INSTALLED and RUNNING" => ("🟢", Color32::from_rgb(80, 200, 120)),
                            "RUNNING" => ("🔵", Color32::from_rgb(80, 170, 255)),
                            "INSTALLED" => ("🟡", Color32::from_rgb(220, 200, 60)),
                            _ => ("⚪", Color32::from_rgb(160, 165, 175)),
                        };
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            ui.label(egui::RichText::new(icon).small());
                            ui.label(
                                egui::RichText::new(name)
                                    .small()
                                    .strong()
                                    .color(Color32::WHITE),
                            );
                            ui.label(egui::RichText::new(status).small().color(color));
                        });
                    }
                    if products.is_empty() && error.is_some() {
                        ui.label(
                            egui::RichText::new("No AV/EDR detected")
                                .small()
                                .italics()
                                .color(Color32::from_rgb(160, 165, 175)),
                        );
                    }
                });
            }
        };
        let is_output_node = matches!(
            &snarl[pin.id.node],
            WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        );
        if is_output_node {
            PinInfo::circle()
                .with_fill(Color32::TRANSPARENT)
                .with_stroke(egui::Stroke::NONE)
        } else {
            PinInfo::circle().with_fill(Color32::from_rgb(80, 170, 255))
        }
    }

    fn show_output(
        &mut self,
        pin: &OutPin,
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) -> impl egui_snarl::ui::SnarlPin + 'static {
        match &snarl[pin.id.node] {
            WorkflowNode::TargetInput { target } => {
                ui.label(format!("{target}"));
                PinInfo::triangle().with_fill(Color32::from_rgb(80, 220, 120))
            }
            WorkflowNode::ProtocolModule { protocol } => {
                ui.label(protocol.clone());
                PinInfo::triangle().with_fill(Color32::from_rgb(235, 180, 80))
            }
            WorkflowNode::CredentialNode { username, .. } => {
                ui.label(username.clone());
                PinInfo::triangle().with_fill(Color32::from_rgb(120, 210, 255))
            }
            WorkflowNode::ActionNode { action } => {
                ui.label(action.clone());
                PinInfo::triangle().with_fill(Color32::from_rgb(255, 170, 60))
            }
            WorkflowNode::OutputNode { format } => {
                ui.label(format.clone());
                PinInfo::triangle().with_fill(Color32::from_rgb(180, 220, 110))
            }
            WorkflowNode::GenericModule { name } => {
                ui.label(name.clone());
                PinInfo::triangle().with_fill(Color32::from_rgb(200, 120, 220))
            }
            WorkflowNode::HostNode { .. } => {
                // All visual content is rendered in `show_body` via
                // `render_host_card` (hostname/IP already shown by the
                // snarl header, so the body stays focused on status).
                // The coloured status border is painted by snarl on the
                // real frame/header stroke — see `node_frame` /
                // `header_frame` overrides.
                PinInfo::triangle().with_fill(Color32::from_rgb(80, 220, 120))
            }
            WorkflowNode::SharesNode { .. } => {
                ui.label("-");
                PinInfo::circle().with_fill(Color32::from_rgb(80, 170, 255))
            }
            WorkflowNode::UsersNode { .. } => {
                ui.label("-");
                PinInfo::circle().with_fill(Color32::from_rgb(80, 170, 255))
            }
            WorkflowNode::DumpNode { .. } => {
                ui.label("-");
                PinInfo::circle().with_fill(Color32::from_rgb(80, 170, 255))
            }
            WorkflowNode::EnumAvNode { .. } => {
                ui.label("-");
                PinInfo::circle().with_fill(Color32::from_rgb(80, 170, 255))
            }
        }
    }

    fn connect(&mut self, from: &OutPin, to: &InPin, snarl: &mut Snarl<WorkflowNode>) {
        for &remote in &to.remotes {
            snarl.disconnect(remote, to.id);
        }
        snarl.connect(from.id, to.id);
    }

    // ------------------------------------------------------------------
    // HostNode body + hover popup — proper snarl architecture.
    // The body lives between the input and output pin columns (snarl's
    // `left_to_right(Align::Min)` body_ui), which places the card
    // naturally in the middle of the frame regardless of header width.
    // The hover popup reveals the details that don't fit in the compact
    // card (OS complet, signing/SMBv1 status explicites, listes
    // shares/users).
    // ------------------------------------------------------------------

    fn has_body(&mut self, node: &WorkflowNode) -> bool {
        matches!(node, WorkflowNode::HostNode { .. })
    }

    fn show_body(
        &mut self,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) {
        if let WorkflowNode::HostNode {
            os_info,
            domain,
            signing,
            smbv1,
            shares,
            admin,
            users,
            logged_in_cred,
            ..
        } = &snarl[node]
        {
            ui.vertical(|ui| {
                ui.set_min_width(HOST_BODY_W);
                ui.set_max_width(HOST_BODY_W);
                ui.spacing_mut().item_spacing.y = 2.0;
                render_host_card(
                    ui,
                    os_info,
                    domain,
                    *signing,
                    *smbv1,
                    shares,
                    *admin,
                    users,
                    logged_in_cred.as_deref(),
                );
            });
        }
    }

    fn has_on_hover_popup(&mut self, node: &WorkflowNode) -> bool {
        matches!(node, WorkflowNode::HostNode { .. })
    }

    fn show_on_hover_popup(
        &mut self,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) {
        if let WorkflowNode::HostNode {
            ip,
            hostname,
            os_info,
            domain,
            signing,
            smbv1,
            shares,
            admin,
            users,
            logged_in_cred,
        } = &snarl[node]
        {
            ui.set_max_width(340.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;

                // Full identity — le popup est autonome, doublon légitime.
                let title = if hostname.is_empty() || hostname == ip {
                    ip.clone()
                } else {
                    format!("{hostname} — {ip}")
                };
                ui.label(egui::RichText::new(title).strong().color(HOST_PRIMARY));
                ui.separator();

                if !os_info.is_empty() {
                    ui.label(format!("OS: {os_info}"));
                }
                if !domain.is_empty() {
                    ui.label(format!("Domain: {domain}"));
                }

                let signing_label = match signing {
                    Some(true) => "Enabled",
                    Some(false) => "Disabled",
                    None => "Unknown",
                };
                ui.label(format!("Signing: {signing_label}"));

                let smbv1_label = match smbv1 {
                    Some(true) => "Supported (vulnerable)",
                    Some(false) => "Disabled",
                    None => "Unknown",
                };
                ui.label(format!("SMBv1: {smbv1_label}"));

                if *admin {
                    ui.label(
                        egui::RichText::new("ADMIN")
                            .strong()
                            .color(HOST_ADMIN_PURPLE),
                    );
                }
                if let Some(cred) = logged_in_cred.as_deref() {
                    let (text, color) = if *admin {
                        (format!("🔐 {cred} — Pwn3d!"), HOST_OK)
                    } else {
                        (cred.to_string(), HOST_WARN)
                    };
                    ui.label(egui::RichText::new(text).strong().color(color));
                }

                if !shares.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("Shares ({})", shares.len()))
                            .strong()
                            .color(HOST_PRIMARY),
                    );
                    for s in shares {
                        ui.label(format!("  {s}"));
                    }
                }

                if !users.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("Users ({})", users.len()))
                            .strong()
                            .color(HOST_PRIMARY),
                    );
                    for u in users.iter().take(20) {
                        ui.label(format!("  {u}"));
                    }
                    if users.len() > 20 {
                        ui.label(format!("  … +{} more", users.len() - 20));
                    }
                }
            });
        }
    }

    /// Customize the node's frame stroke with its status colour so the
    /// *real* cadre (painted by snarl itself) is coloured — no overlay.
    ///
    /// For HostNodes we replace the default stroke with a thicker,
    /// status-coloured one. All other node kinds keep the default.
    fn node_frame(
        &mut self,
        default: egui::Frame,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        snarl: &Snarl<WorkflowNode>,
    ) -> egui::Frame {
        if let Some(color) = host_status_color(&snarl[node]) {
            // Keep the default stroke *width* (matches the plain gray cadre
            // of non-host nodes) — only swap the colour.
            default.stroke(Stroke::new(default.stroke.width, color))
        } else {
            default
        }
    }

    /// Mirror the same treatment on the header frame so the top half of the
    /// cadre matches (otherwise only the body strip gets the colour).
    fn header_frame(
        &mut self,
        default: egui::Frame,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        snarl: &Snarl<WorkflowNode>,
    ) -> egui::Frame {
        if let Some(color) = host_status_color(&snarl[node]) {
            default.stroke(Stroke::new(default.stroke.width, color))
        } else {
            default
        }
    }

    fn has_graph_menu(&mut self, _pos: Pos2, _snarl: &mut Snarl<WorkflowNode>) -> bool {
        true
    }

    fn show_graph_menu(&mut self, pos: Pos2, ui: &mut Ui, snarl: &mut Snarl<WorkflowNode>) {
        ui.label(
            egui::RichText::new("Ajouter un noeud")
                .small()
                .strong()
                .color(Color32::from_rgb(160, 165, 175)),
        );
        ui.separator();
        if ui.button("Target Input").clicked() {
            snarl.insert_node(
                pos,
                WorkflowNode::TargetInput {
                    target: "10.0.0.0/24".to_owned(),
                },
            );
            ui.close();
        }
        if ui.button("Protocol Module").clicked() {
            snarl.insert_node(
                pos,
                WorkflowNode::ProtocolModule {
                    protocol: "SMB".to_owned(),
                },
            );
            ui.close();
        }
        if ui.button("Credential Node").clicked() {
            snarl.insert_node(
                pos,
                WorkflowNode::CredentialNode {
                    username: "administrator".to_owned(),
                    secret: "******".to_owned(),
                },
            );
            ui.close();
        }
        if ui.button("Action Node").clicked() {
            snarl.insert_node(
                pos,
                WorkflowNode::ActionNode {
                    action: "--shares".to_owned(),
                },
            );
            ui.close();
        }
        if ui.button("Output Node").clicked() {
            snarl.insert_node(
                pos,
                WorkflowNode::OutputNode {
                    format: "JSON".to_owned(),
                },
            );
            ui.close();
        }
    }

    fn has_node_menu(&mut self, _node: &WorkflowNode) -> bool {
        true
    }

    fn show_node_menu(
        &mut self,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) {
        let is_shares = matches!(&snarl[node], WorkflowNode::SharesNode { .. });
        let is_host = matches!(&snarl[node], WorkflowNode::HostNode { .. });

        if is_shares {
            if let WorkflowNode::SharesNode {
                host_ip, shares, ..
            } = &snarl[node]
            {
                for s in shares {
                    let (name, _stype, access) = parse_share_string(s);
                    if access == "NO ACCESS" {
                        continue;
                    }
                    let label = format!("🔍 Browse {name}");
                    if ui.button(&label).clicked() {
                        self.browse_requests
                            .push((host_ip.clone(), name.to_string()));
                        ui.close();
                    }
                }
                ui.separator();
            }
        }

        if is_host {
            // "Fingerprint" — re-run SMB fingerprint (no auth needed)
            if ui.button("🔍 Fingerprint").clicked() {
                if let WorkflowNode::HostNode { ip, .. } = &snarl[node] {
                    self.fingerprint_requests.push(ip.clone());
                }
                ui.close();
            }

            // "List Shares" — spawn a SharesNode
            if ui.button("📂 List Shares").clicked() {
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    if let Some(cred) = self.resolve_cred(logged_in_cred) {
                        self.shares_requests
                            .push((node, ip.clone(), hostname.clone(), cred));
                    }
                }
                ui.close();
            }

            // "List Users" — spawn a UsersNode
            if ui.button("👥 List Users").clicked() {
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    if let Some(cred) = self.resolve_cred(logged_in_cred) {
                        self.users_requests
                            .push((node, ip.clone(), hostname.clone(), cred));
                    }
                }
                ui.close();
            }

            // "Dump" submenu — SAM / LSA
            ui.menu_button("🔑 Dump", |ui| {
                ui.set_min_width(140.0);
                if ui.button("🔑 SAM Hashes").clicked() {
                    if let WorkflowNode::HostNode {
                        ip,
                        hostname,
                        logged_in_cred,
                        ..
                    } = &snarl[node]
                    {
                        if let Some(cred) = self.resolve_cred(logged_in_cred) {
                            self.dump_requests.push((
                                node,
                                ip.clone(),
                                hostname.clone(),
                                "SAM".to_string(),
                                cred,
                            ));
                        }
                    }
                    ui.close();
                }
                if ui.button("🔓 LSA Secrets").clicked() {
                    if let WorkflowNode::HostNode {
                        ip,
                        hostname,
                        logged_in_cred,
                        ..
                    } = &snarl[node]
                    {
                        if let Some(cred) = self.resolve_cred(logged_in_cred) {
                            self.dump_requests.push((
                                node,
                                ip.clone(),
                                hostname.clone(),
                                "LSA".to_string(),
                                cred,
                            ));
                        }
                    }
                    ui.close();
                }
            });

            // "Get Console" — only offered on pwned hosts (admin == true)
            let (is_pwned, pwned_ip, pwned_hostname, pwned_cred_label) =
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    admin,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    (
                        *admin && logged_in_cred.is_some(),
                        ip.clone(),
                        hostname.clone(),
                        logged_in_cred.clone(),
                    )
                } else {
                    (false, String::new(), String::new(), None)
                };
            if is_pwned {
                if ui.button("🖥 Get Console").clicked() {
                    if let Some(label) = pwned_cred_label.as_deref() {
                        let cred_opt = self
                            .credentials
                            .iter()
                            .find(|c| {
                                let cl = if c.domain.is_empty() {
                                    format!(".\\{}", c.username)
                                } else {
                                    format!("{}\\{}", c.domain, c.username)
                                };
                                cl == label
                            })
                            .cloned();
                        if let Some(cred) = cred_opt {
                            self.console_requests.push((pwned_ip, pwned_hostname, cred));
                        }
                    }
                    ui.close();
                }
            }

            // "Enum AV" — detect installed AV/EDR
            if ui.button("🛡 Enum AV").clicked() {
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    // Resolve credential from logged_in_cred label
                    let mut cred_found = None;
                    if let Some(label) = logged_in_cred {
                        for c in &self.credentials {
                            let cl = if c.domain.is_empty() {
                                format!(".\\{}", c.username)
                            } else {
                                format!("{}\\{}", c.domain, c.username)
                            };
                            if cl == *label {
                                cred_found = Some(c.clone());
                                break;
                            }
                        }
                    }
                    if let Some(cred) = cred_found {
                        self.enumav_requests
                            .push((node, ip.clone(), hostname.clone(), cred));
                    } else if let Some(first) = self.credentials.first() {
                        self.enumav_requests.push((
                            node,
                            ip.clone(),
                            hostname.clone(),
                            first.clone(),
                        ));
                    }
                }
                ui.close();
            }

            // Get current logged_in state
            let current_cred = if let WorkflowNode::HostNode { logged_in_cred, .. } = &snarl[node] {
                logged_in_cred.clone()
            } else {
                None
            };

            // "Login As" submenu
            ui.menu_button("🔑 Login As", |ui| {
                ui.set_min_width(160.0);
                if self.credentials.is_empty() {
                    ui.label(
                        egui::RichText::new("No credentials saved")
                            .small()
                            .italics()
                            .color(Color32::from_rgb(160, 165, 175)),
                    );
                } else {
                    for cred in &self.credentials {
                        let cred_label = if cred.domain.is_empty() {
                            format!(".\\{}", cred.username)
                        } else {
                            format!("{}\\{}", cred.domain, cred.username)
                        };

                        let is_active = current_cred.as_deref() == Some(cred_label.as_str());
                        let icon = if is_active { "✔" } else { "  " };

                        let type_tag = match cred.cred_type {
                            crate::state::CredType::Hash => "🔒",
                            crate::state::CredType::Password => "🔑",
                        };
                        let label = format!("{icon} {type_tag} {cred_label}");

                        let text_color = if is_active {
                            Color32::from_rgb(80, 200, 120)
                        } else {
                            Color32::WHITE
                        };

                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new(&label).size(12.0).color(text_color),
                                )
                                .min_size(egui::vec2(150.0, 22.0)),
                            )
                            .clicked()
                        {
                            if !is_active {
                                // Get IP from the node
                                if let WorkflowNode::HostNode { ip, .. } = &snarl[node] {
                                    self.login_requests.push((ip.clone(), cred.clone()));
                                }
                            }
                            ui.close();
                        }
                    }
                }
            });

            ui.separator();
        }

        if ui.button("🗑 Supprimer noeud").clicked() {
            snarl.remove_node(node);
            ui.close();
        }
    }

    fn draw_background(
        &mut self,
        _background: Option<&BackgroundPattern>,
        viewport: &Rect,
        _snarl_style: &SnarlStyle,
        _style: &Style,
        painter: &egui::Painter,
        _snarl: &Snarl<WorkflowNode>,
    ) {
        // Draw subtle dot grid
        let min_x = (viewport.min.x / DOT_SPACING).floor() as i32;
        let max_x = (viewport.max.x / DOT_SPACING).ceil() as i32;
        let min_y = (viewport.min.y / DOT_SPACING).floor() as i32;
        let max_y = (viewport.max.y / DOT_SPACING).ceil() as i32;

        for ix in min_x..=max_x {
            for iy in min_y..=max_y {
                let x = ix as f32 * DOT_SPACING;
                let y = iy as f32 * DOT_SPACING;
                painter.circle_filled(Pos2::new(x, y), DOT_RADIUS, DOT_COLOR);
            }
        }
    }
}

/// Abbreviate a verbose OS string to fit a compact node card.
/// "Windows Server 2019 Build 19041" → "WinSrv 2019 (19041)"
/// "Windows 10 Pro Build 19044" → "Win10 Pro (19044)"
fn shorten_os(s: &str) -> String {
    let mut out = s
        .replace("Microsoft ", "")
        .replace("Windows Server", "WinSrv")
        .replace("Windows ", "Win");
    if let Some(idx) = out.find(" Build ") {
        let (head, tail) = out.split_at(idx);
        let build = tail.trim_start_matches(" Build ").trim();
        out = format!("{head} ({build})");
    }
    out
}

/// Parse share string "NAME [TYPE] (ACCESS)" into (name, type, access).
fn parse_share_string(s: &str) -> (&str, &str, &str) {
    // Format: "ADMIN$ [SPECIAL] (RW)"
    let (name, rest) = s.split_once(" [").unwrap_or((s, ""));
    let (stype, rest) = rest.split_once("] (").unwrap_or(("", rest));
    let access = rest.trim_end_matches(')');
    (name.trim(), stype, access)
}
