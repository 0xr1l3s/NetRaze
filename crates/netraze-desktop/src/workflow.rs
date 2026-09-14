use egui::{Color32, Pos2, Rect, Stroke, Style, Ui};
use egui_snarl::ui::{BackgroundPattern, NodeLayout, SnarlStyle, SnarlViewer};
use egui_snarl::{InPin, NodeId, OutPin, Snarl, ui::PinInfo};
use serde::{Deserialize, Serialize};

use crate::state::CredentialRecord;

use crate::theme;

const DOT_COLOR:   Color32 = theme::DOT_COLOR;
const DOT_SPACING: f32     = theme::DOT_SPACING;
const DOT_RADIUS:  f32     = theme::DOT_RADIUS;

// HostNode card palette — Vantage semantic tokens.
const HOST_PRIMARY:      Color32 = theme::FG;        // #F5F4F2
const HOST_OK:           Color32 = theme::SUCCESS;   // #55B77F
const HOST_WARN:         Color32 = theme::WARNING;   // #E2A44C
const HOST_BAD:          Color32 = theme::ERROR;     // #E8604C
const HOST_ADMIN_PURPLE: Color32 = theme::INFO;      // #5F9DE8 (admin = blue info)

/// Circle geometry for HostNode (radius, label height, gap between circle and label).
const HOST_R:         f32 = 28.0;
const HOST_LABEL_H:   f32 = 13.0;
const HOST_LABEL_GAP: f32 = 5.0;
/// Total body height allocated in show_body: circle diameter + gap + label.
const HOST_BODY_H: f32 = HOST_R * 2.0 + HOST_LABEL_GAP + HOST_LABEL_H;

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
        /// Label of the credential that enumerated these shares
        /// (`DOMAIN\user` / `.\user`) — resolved back to a full
        /// `CredentialRecord` at click time. Only the label is stored: snarl
        /// nodes are serde-serialized into the persisted workspace and the
        /// secret must not end up on disk.
        #[serde(default)]
        cred_label: Option<String>,
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
        /// Set once the result event landed — distinguishes "still
        /// scanning" from "finished, nothing found" (products may be
        /// legitimately empty in both states).
        #[serde(default)]
        done: bool,
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


impl WorkflowNode {
    pub fn label(&self) -> String {
        match self {
            WorkflowNode::TargetInput { .. } => "Target Input".to_owned(),
            WorkflowNode::ProtocolModule { protocol } => format!("Protocol: {protocol}"),
            WorkflowNode::CredentialNode { .. } => "Credential Node".to_owned(),
            WorkflowNode::ActionNode { action } => format!("Action: {action}"),
            WorkflowNode::OutputNode { .. } => "Output Node".to_owned(),
            WorkflowNode::GenericModule { name } => format!("Module: {name}"),
            WorkflowNode::HostNode { .. } => String::new(),
            WorkflowNode::SharesNode {
                host_ip, hostname, ..
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

        self.snarl.insert_node(
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
        // Disable the collapse triangle — HostNodes are circles and collapsing
        // breaks their appearance; no node kind benefits from collapsing here.
        style.collapsible = Some(false);
        style
    }
}

pub struct WorkflowViewer {
    pub credentials: Vec<CredentialRecord>,
    pub login_requests: Vec<(String, CredentialRecord)>,
    /// (source_node_id_raw, host_ip, hostname, credential) — trigger async share enum
    pub shares_requests: Vec<(NodeId, String, String, CredentialRecord)>,
    /// (host_ip, share_name, credential) — open browser window. The credential
    /// is resolved here from the SharesNode's label; `None` means the label
    /// could not be resolved (the error is pushed to `menu_errors` instead).
    pub browse_requests: Vec<(String, String, Option<CredentialRecord>)>,
    /// User-facing error strings raised while handling node context menus
    /// (e.g. an unresolvable credential label) — surfaced as log entries by
    /// the canvas.
    pub menu_errors: Vec<String>,
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
    /// Raw NodeId.0 of the node clicked — drained into state.selected_workflow_node.
    pub selected_node_id: Option<usize>,
}

impl WorkflowViewer {
    pub fn new(credentials: Vec<CredentialRecord>) -> Self {
        Self {
            credentials,
            login_requests: Vec::new(),
            shares_requests: Vec::new(),
            browse_requests: Vec::new(),
            menu_errors: Vec::new(),
            users_requests: Vec::new(),
            dump_requests: Vec::new(),
            enumav_requests: Vec::new(),
            fingerprint_requests: Vec::new(),
            console_requests: Vec::new(),
            selected_node_id: None,
        }
    }

    /// Resolve a `CredentialRecord` from its display label (e.g. `DOMAIN\user`).
    ///
    /// `(anonymous)` resolves to the synthesized null-session record —
    /// anonymous access needs no saved entry, it's the "no user provided"
    /// fallback.
    fn resolve_cred(&self, label: &Option<String>) -> Option<CredentialRecord> {
        let label = label.as_ref()?;
        if label == "(anonymous)" {
            return Some(crate::state::anonymous_record());
        }
        for c in &self.credentials {
            if &crate::state::cred_label(c) == label {
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
            WorkflowNode::SharesNode { .. }
            | WorkflowNode::UsersNode { .. }
            | WorkflowNode::DumpNode { .. }
            | WorkflowNode::EnumAvNode { .. } => {
                // Circular nodes — content is in the config panel, not the pin row.
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
                ui.label(target.to_string());
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
                PinInfo::circle()
                    .with_fill(Color32::TRANSPARENT)
                    .with_stroke(Stroke::NONE)
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
    // HostNode rendered as a circle: hide the header, transparent frame,
    // paint a filled circle + icon + hostname label in show_body.
    // ------------------------------------------------------------------

    fn show_header(
        &mut self,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) {
        let is_circular = matches!(
            &snarl[node],
            WorkflowNode::HostNode { .. }
                | WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        );
        if !is_circular {
            ui.label(self.title(&snarl[node]));
        }
    }

    fn node_layout(
        &mut self,
        default: NodeLayout,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        snarl: &Snarl<WorkflowNode>,
    ) -> NodeLayout {
        let is_circular = matches!(
            &snarl[node],
            WorkflowNode::HostNode { .. }
                | WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        );
        if is_circular {
            NodeLayout {
                min_pin_row_height: HOST_BODY_H,
                ..default
            }
        } else {
            default
        }
    }

    fn has_body(&mut self, node: &WorkflowNode) -> bool {
        matches!(
            node,
            WorkflowNode::HostNode { .. }
                | WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        )
    }

    fn show_body(
        &mut self,
        node: NodeId,
        inputs: &[InPin],
        outputs: &[OutPin],
        ui: &mut Ui,
        snarl: &mut Snarl<WorkflowNode>,
    ) {
        // Collect all draw parameters as owned values to avoid borrow conflicts
        // with the context_menu closure that needs &mut snarl.
        let draw_params: Option<(&'static str, String, Color32)> = match &snarl[node] {
            WorkflowNode::HostNode { ip, hostname, admin, .. } => {
                let is_admin = *admin;
                let label = if hostname.is_empty() || hostname == ip.as_str() {
                    ip.clone()
                } else {
                    hostname.clone()
                };
                let border = host_status_color(&snarl[node]).unwrap_or(theme::LINE_2);
                let icon: &'static str = if is_admin { "⚡" } else { "🖥" };
                Some((icon, label, border))
            }
            WorkflowNode::SharesNode { host_ip, hostname, shares, .. } => {
                let label = if hostname.is_empty() { host_ip.clone() } else { hostname.clone() };
                let border = if shares.is_empty() { theme::MUTED } else { theme::INFO };
                Some(("📂", label, border))
            }
            WorkflowNode::UsersNode { host_ip, hostname, users } => {
                let label = if hostname.is_empty() { host_ip.clone() } else { hostname.clone() };
                let border = if users.is_empty() { theme::MUTED } else { theme::INFO };
                Some(("👥", label, border))
            }
            WorkflowNode::DumpNode { host_ip, hostname, dump_type, entries, error, .. } => {
                let label = if hostname.is_empty() { host_ip.clone() } else { hostname.clone() };
                let icon: &'static str = if dump_type == "SAM" { "🔑" } else { "🔓" };
                let border = if error.is_some() {
                    theme::ERROR
                } else if !entries.is_empty() {
                    theme::SUCCESS
                } else {
                    theme::WARNING
                };
                Some((icon, label, border))
            }
            WorkflowNode::EnumAvNode { host_ip, hostname, products, done, .. } => {
                let label = if hostname.is_empty() { host_ip.clone() } else { hostname.clone() };
                let border = if !products.is_empty() {
                    theme::WARNING
                } else if *done {
                    theme::SUCCESS
                } else {
                    theme::MUTED
                };
                Some(("🛡", label, border))
            }
            _ => None,
        };

        if let Some((icon, label, border)) = draw_params {
            // Extra left padding prevents the circle stroke from being clipped
            // at the body-UI clip rect's left edge (clip rect min.x == rect.left()).
            const PAD_L: f32 = 3.0;
            let (rect, response) = ui.allocate_exact_size(
                egui::vec2(PAD_L + HOST_R * 2.0, HOST_BODY_H),
                egui::Sense::click(),
            );
            let center  = egui::pos2(rect.left() + PAD_L + HOST_R, rect.top() + HOST_R);
            let painter = ui.painter();

            painter.circle_filled(center, HOST_R, theme::ELEV_1);
            painter.circle_stroke(center, HOST_R - 1.0, egui::Stroke::new(2.0, border));
            painter.text(
                center,
                egui::Align2::CENTER_CENTER,
                icon,
                egui::FontId::new(20.0, egui::FontFamily::Proportional),
                egui::Color32::WHITE,
            );
            painter.text(
                egui::pos2(center.x, rect.bottom() - HOST_LABEL_H / 2.0),
                egui::Align2::CENTER_CENTER,
                &label,
                egui::FontId::new(10.0, egui::FontFamily::Proportional),
                theme::MUTED,
            );

            if response.clicked() {
                self.selected_node_id = Some(node.0);
            }
            // The body allocation is registered AFTER snarl's node-frame interact, so it
            // wins Flags::CLICKED in the hit test. snarl's own r.context_menu() on the
            // node frame never fires (r doesn't get CLICKED). Attach the menu here instead.
            response.context_menu(|menu_ui| {
                self.show_node_menu(node, inputs, outputs, menu_ui, snarl);
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

    /// Circular nodes (HostNode, SharesNode, etc.) get a fully transparent
    /// frame so the painted circle is the only visible chrome. All other
    /// node kinds keep the default snarl frame.
    fn node_frame(
        &mut self,
        default: egui::Frame,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        snarl: &Snarl<WorkflowNode>,
    ) -> egui::Frame {
        let is_circular = matches!(
            &snarl[node],
            WorkflowNode::HostNode { .. }
                | WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        );
        if is_circular {
            egui::Frame {
                fill: egui::Color32::TRANSPARENT,
                stroke: Stroke::NONE,
                corner_radius: egui::CornerRadius::ZERO,
                inner_margin: egui::Margin::ZERO,
                outer_margin: egui::Margin::ZERO,
                ..default
            }
        } else {
            default
        }
    }

    fn header_frame(
        &mut self,
        default: egui::Frame,
        node: NodeId,
        _inputs: &[InPin],
        _outputs: &[OutPin],
        snarl: &Snarl<WorkflowNode>,
    ) -> egui::Frame {
        let is_circular = matches!(
            &snarl[node],
            WorkflowNode::HostNode { .. }
                | WorkflowNode::SharesNode { .. }
                | WorkflowNode::UsersNode { .. }
                | WorkflowNode::DumpNode { .. }
                | WorkflowNode::EnumAvNode { .. }
        );
        if is_circular {
            egui::Frame {
                fill: egui::Color32::TRANSPARENT,
                stroke: Stroke::NONE,
                corner_radius: egui::CornerRadius::ZERO,
                inner_margin: egui::Margin::ZERO,
                outer_margin: egui::Margin::ZERO,
                ..default
            }
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
                host_ip,
                shares,
                cred_label,
                ..
            } = &snarl[node]
            {
                // Resolve the share-enumeration credential at click time —
                // the node only persists its label, never the secret.
                let cred = match self.resolve_cred(cred_label) {
                    Some(c) => Some(c),
                    None => {
                        self.menu_errors.push(format!(
                            "Cannot browse shares on {host_ip}: credential {} not found \
                             (it may have been renamed or deleted — re-run List Shares)",
                            cred_label.as_deref().unwrap_or("(none)")
                        ));
                        None
                    }
                };
                for s in shares {
                    let (name, _stype, access) = parse_share_string(s);
                    if access == "NO ACCESS" {
                        continue;
                    }
                    let label = format!("🔍 Browse {name}");
                    if ui.button(&label).clicked() {
                        self.browse_requests.push((
                            host_ip.clone(),
                            name.to_string(),
                            cred.clone(),
                        ));
                        ui.close();
                    }
                }
                ui.separator();
            }
        }

        if is_host {
            if ui.button("📋 Sélectionner").clicked() {
                self.selected_node_id = Some(node.0);
                ui.close();
            }
            ui.separator();
            // "Fingerprint" — re-run SMB fingerprint (no auth needed)
            if ui.button("🔍 Fingerprint").clicked() {
                if let WorkflowNode::HostNode { ip, .. } = &snarl[node] {
                    self.fingerprint_requests.push(ip.clone());
                }
                ui.close();
            }

            // "List Shares" — spawn a SharesNode. No login on the host →
            // anonymous (null session): the server's policy decides what
            // a null session may enumerate.
            if ui.button("📂 List Shares").clicked() {
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    let cred = self
                        .resolve_cred(logged_in_cred)
                        .unwrap_or_else(crate::state::anonymous_record);
                    self.shares_requests
                        .push((node, ip.clone(), hostname.clone(), cred));
                }
                ui.close();
            }

            // "List Users" — spawn a UsersNode. Same anonymous fallback;
            // hardened hosts refuse SAMR over a null session and the node
            // surfaces that error.
            if ui.button("👥 List Users").clicked() {
                if let WorkflowNode::HostNode {
                    ip,
                    hostname,
                    logged_in_cred,
                    ..
                } = &snarl[node]
                {
                    let cred = self
                        .resolve_cred(logged_in_cred)
                        .unwrap_or_else(crate::state::anonymous_record);
                    self.users_requests
                        .push((node, ip.clone(), hostname.clone(), cred));
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
            if is_pwned && ui.button("🖥 Get Console").clicked() {
                if let Some(label) = pwned_cred_label.as_deref() {
                    let cred_opt = self
                        .credentials
                        .iter()
                        .find(|c| crate::state::cred_label(c) == label)
                        .cloned();
                    if let Some(cred) = cred_opt {
                        self.console_requests.push((pwned_ip, pwned_hostname, cred));
                    }
                }
                ui.close();
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
                    let cred_found = if logged_in_cred.as_deref() == Some("(anonymous)") {
                        Some(crate::state::anonymous_record())
                    } else {
                        logged_in_cred.as_deref().and_then(|label| {
                            self.credentials
                                .iter()
                                .find(|c| crate::state::cred_label(c) == label)
                                .cloned()
                        })
                    };
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

                // Anonymous (null session) — always available, saved
                // credentials or not. It's the "no user provided" mode.
                {
                    let is_active = current_cred.as_deref() == Some("(anonymous)");
                    let icon = if is_active { "✔" } else { "  " };
                    let text_color = if is_active {
                        Color32::from_rgb(80, 200, 120)
                    } else {
                        Color32::WHITE
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(format!("{icon} 👤 (anonymous)"))
                                    .size(12.0)
                                    .color(text_color),
                            )
                            .min_size(egui::vec2(150.0, 22.0)),
                        )
                        .clicked()
                    {
                        if !is_active {
                            if let WorkflowNode::HostNode { ip, .. } = &snarl[node] {
                                self.login_requests
                                    .push((ip.clone(), crate::state::anonymous_record()));
                            }
                        }
                        ui.close();
                    }
                }

                if self.credentials.is_empty() {
                    ui.label(
                        egui::RichText::new("No credentials saved")
                            .small()
                            .italics()
                            .color(Color32::from_rgb(160, 165, 175)),
                    );
                } else {
                    for cred in &self.credentials {
                        let cred_label = crate::state::cred_label(cred);

                        let is_active = current_cred.as_deref() == Some(cred_label.as_str());
                        let icon = if is_active { "✔" } else { "  " };

                        let type_tag = match cred.cred_type {
                            crate::state::CredType::Hash => "🔒",
                            // Secret-less password credential = guest access.
                            crate::state::CredType::Password if cred.secret.is_empty() => "👤",
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


/// Parse share string "NAME [TYPE] (ACCESS)" into (name, type, access).
fn parse_share_string(s: &str) -> (&str, &str, &str) {
    // Format: "ADMIN$ [SPECIAL] (RW)"
    let (name, rest) = s.split_once(" [").unwrap_or((s, ""));
    let (stype, rest) = rest.split_once("] (").unwrap_or(("", rest));
    let access = rest.trim_end_matches(')');
    (name.trim(), stype, access)
}
