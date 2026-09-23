use egui_snarl::NodeId;

use crate::runtime::RuntimeServices;
use crate::state::AppState;
use crate::theme;
use crate::workflow::WorkflowNode;

const LABEL_COLOR: egui::Color32 = theme::MUTED;
const ACCENT: egui::Color32 = theme::ACC;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, runtime: &RuntimeServices) {
    // If a workflow node is selected, show its detail panel instead of the config.
    if let Some(raw_id) = state.selected_workflow_node {
        // Verify the node still exists before rendering.
        let exists = state
            .workflow
            .snarl
            .get_node(NodeId(raw_id))
            .is_some();

        if exists {
            show_node_panel(ui, state, runtime, raw_id);
            return;
        } else {
            // Node was removed — clear selection and fall through to default config.
            state.selected_workflow_node = None;
        }
    }

    show_default_config(ui, state, runtime);
}

// ── Default config panel ──────────────────────────────────────────────────────

fn show_default_config(
    ui: &mut egui::Ui,
    state: &mut AppState,
    runtime: &RuntimeServices,
) {
    ui.label(
        egui::RichText::new("⚙ Configuration")
            .size(14.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.add_space(8.0);

    // -- Target section --
    ui.label(egui::RichText::new("TARGET").small().strong().color(ACCENT));
    ui.add_space(2.0);

    ui.label(egui::RichText::new("IP / Range").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.target_config.target)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(4.0);

    ui.label(egui::RichText::new("Protocol").small().color(LABEL_COLOR));
    egui::ComboBox::from_id_salt("protocol_combo")
        .selected_text(&state.target_config.protocol)
        .width(ui.available_width())
        .show_ui(ui, |ui| {
            for proto in [
                "SMB", "LDAP", "RDP", "WinRM", "MSSQL", "SSH", "FTP", "Kerberos",
            ] {
                ui.selectable_value(&mut state.target_config.protocol, proto.to_owned(), proto);
            }
        });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    // -- Credentials section --
    ui.label(
        egui::RichText::new("CREDENTIALS")
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("Username").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.username)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("Password").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.password)
            .desired_width(f32::INFINITY)
            .password(true),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("NTLM Hash").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.ntlm_hash)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(2.0);

    ui.label(
        egui::RichText::new("Kerberos Ticket")
            .small()
            .color(LABEL_COLOR),
    );
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.kerberos_ticket)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    if state.target_config.protocol == "SMB" || state.target_config.protocol == "LDAP" {
        ui.label(
                egui::RichText::new(
                    "Use DOMAIN\\username when a domain is needed. NT hash takes priority over Password. Kerberos tickets are not supported yet.",
                )
                .small()
                .color(LABEL_COLOR),
            );
        ui.label(
            egui::RichText::new(
                "Blank credentials reuse each target's current login, or anonymous if there is none. Entering credentials overrides the login and adds them to Credential Manager when you run the scan. Workspace saves include credential secrets.",
            )
            .small()
            .color(LABEL_COLOR),
        );
    }
    if state.target_config.protocol == "LDAP" {
        ui.label(
            egui::RichText::new(
                "To force anonymous on a logged-in host, select Login As (anonymous) for that host. DOMAIN\\Guest with no secret attempts Guest NTLM; the server may reject it.",
            )
            .small()
            .color(LABEL_COLOR),
        );
    }
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    // -- Execution section --
    ui.label(
        egui::RichText::new("EXECUTION")
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Threads").small().color(LABEL_COLOR));
        ui.add(egui::DragValue::new(&mut state.threads).range(1..=1024));
    });
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Timeout (s)")
                .small()
                .color(LABEL_COLOR),
        );
        ui.add(egui::DragValue::new(&mut state.timeout_seconds).range(1..=600));
    });

    ui.add_space(4.0);
    if !state.selected_module.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Module:").small().color(LABEL_COLOR));
            ui.label(
                egui::RichText::new(&state.selected_module)
                    .strong()
                    .color(ACCENT),
            );
        });
    }

    ui.add_space(12.0);

    // -- Run button --
    let run_text = if state.is_running {
        "⏳ Running..."
    } else {
        "▶ Run"
    };
    let run_color = if state.is_running { theme::ELEV_2 } else { theme::ACC };
    let run_button = egui::Button::new(
        egui::RichText::new(run_text)
            .strong()
            .color(egui::Color32::WHITE)
            .size(14.0),
    )
    .fill(run_color)
    .corner_radius(egui::CornerRadius::same(4));

    let validation_error = scan_validation_error(state);
    let can_run = !state.is_running && validation_error.is_none();
    if ui
        .add_enabled_ui(can_run, |ui| {
            ui.add_sized([ui.available_width(), 36.0], run_button)
        })
        .inner
        .clicked()
    {
        state.is_running = true;
        state.status_text = "Running".to_owned();
        state.started_at = Some(std::time::Instant::now());
        state.progress = 0.0;
        state.progress_message = "Démarrage...".to_owned();

        let targets: Vec<String> = state
            .target_config
            .target
            .split([',', ' ', '\n'])
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        match state.target_config.protocol.as_str() {
            "LDAP" => match state.credential_config.as_record() {
                Ok(mut record) => {
                    if let Some(credential) = &mut record {
                        credential.protocol = "LDAP".to_owned();
                    }
                    if let Some(credential) = &record {
                        state.remember_scan_credential(credential.clone());
                    }
                    let plan = state.scan_credential_plan(record);
                    runtime.spawn_ldap_scan(targets, plan, state.threads, state.timeout_seconds);
                }
                Err(error) => {
                    state.is_running = false;
                    state.status_text = "Idle".to_owned();
                    runtime.emit_error(error);
                }
            },
            "SMB" => match state.credential_config.as_record() {
                Ok(mut record) => {
                    if let Some(credential) = &mut record {
                        credential.protocol = "SMB".to_owned();
                    }
                    if let Some(credential) = &record {
                        state.remember_scan_credential(credential.clone());
                    }
                    let plan = state.scan_credential_plan(record);
                    runtime.spawn_smb_scan(targets, plan, state.threads, state.timeout_seconds);
                }
                Err(error) => {
                    state.is_running = false;
                    state.status_text = "Idle".to_owned();
                    runtime.emit_error(error);
                }
            },
            protocol => {
                state.is_running = false;
                state.status_text = "Idle".to_owned();
                runtime.emit_error(format!(
                    "Protocol {protocol} does not have a desktop scan workflow yet"
                ));
            }
        }
    }

    if let Some(error) = validation_error {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(error).small().color(
            if state.target_config.protocol == "LDAP" {
                theme::WARNING
            } else {
                LABEL_COLOR
            },
        ));
    }
}

fn scan_validation_error(state: &AppState) -> Option<String> {
    if state.target_config.target.trim().is_empty() {
        return Some("Enter at least one host, range, or CIDR target".to_owned());
    }
    match state.target_config.protocol.as_str() {
        "SMB" => state.credential_config.as_record().err(),
        "LDAP" => {
            let credential = match state.credential_config.as_record() {
                Ok(Some(credential)) => credential,
                Ok(None) => crate::state::anonymous_record(),
                Err(error) => return Some(error),
            };
            crate::runtime::cred_to_ldap_auth(&credential)
                .map(|_| ())
                .map_err(|error| format!("Invalid LDAP credential: {error}"))
                .err()
        }
        protocol => Some(format!(
            "Protocol {protocol} does not have a desktop scan workflow yet"
        )),
    }
}

// ── Per-node detail panel ─────────────────────────────────────────────────────

fn show_node_panel(
    ui: &mut egui::Ui,
    state: &mut AppState,
    runtime: &RuntimeServices,
    raw_id: usize,
) {
    let node_id = NodeId(raw_id);

    if let WorkflowNode::DirectoryNode {
        endpoint,
        hostname,
        inventory,
        error,
        loading,
        cred_label,
    } = &state.workflow.snarl[node_id]
    {
        let export = state.bloodhound_exports.get(endpoint);
        let action = super::directory_panel::show(
            ui,
            raw_id,
            super::directory_panel::DirectoryView {
                endpoint,
                hostname,
                inventory: inventory.as_deref(),
                error: error.as_deref(),
                loading: *loading,
                cred_label: cred_label.as_deref(),
                bloodhound_export: export.map(|export| {
                    super::directory_panel::BloodHoundExportView {
                        running: export.running,
                        phase: &export.phase,
                        output_directory: export.output_directory.as_deref(),
                        exported_object_count: export.exported_object_count,
                        json_file_count: export.json_files.len(),
                        zip_file: export.zip_file.as_deref(),
                        error: export.error.as_deref(),
                    }
                }),
            },
        );
        let endpoint = endpoint.clone();
        let cred_label = cred_label.clone();
        if action == super::directory_panel::DirectoryAction::ExportBloodHoundCe {
            start_bloodhound_export(state, runtime, endpoint, cred_label);
        }
        return;
    }

    // Large AD directories must not be cloned on every egui repaint.
    if let WorkflowNode::UsersNode {
        host_ip,
        hostname,
        users,
        source,
        fallback_used,
        error,
        done,
        loading,
        cred_label,
    } = &state.workflow.snarl[node_id]
    {
        let refresh = show_users_panel(
            ui,
            host_ip,
            hostname,
            users,
            *source,
            *fallback_used,
            error.as_deref(),
            *done,
            *loading,
            cred_label.as_deref(),
        );
        if !refresh {
            return;
        }
        let host_ip = host_ip.clone();
        let cred_label = cred_label.clone();
        let host = state.workflow.snarl.node_ids().find_map(|(id, node)| {
            if let WorkflowNode::HostNode {
                ip,
                hostname,
                logged_in_cred,
                ..
            } = node
            {
                (ip == &host_ip).then(|| (id.0, hostname.clone(), logged_in_cred.clone()))
            } else {
                None
            }
        });
        if let Some((host_id, current_hostname, login_label)) = host {
            let label = login_label.or(cred_label);
            let credential = match label.as_deref() {
                None | Some("(anonymous)") => Some(crate::state::anonymous_record()),
                Some(label) => state
                    .credentials
                    .iter()
                    .find(|cred| crate::state::cred_label(cred) == label)
                    .cloned(),
            };
            if let Some(credential) = credential {
                state.queue_user_enum(host_id, host_ip, current_hostname, credential);
            } else {
                state.add_log(
                    crate::runtime::LogLevel::Error,
                    "Cannot refresh users: the credential is no longer available",
                );
            }
        }
        return;
    }

    match state.workflow.snarl[node_id].clone() {
        WorkflowNode::HostNode {
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
        } => {
            show_host_panel(
                ui,
                &ip,
                &hostname,
                &os_info,
                &domain,
                signing,
                smbv1,
                &shares,
                admin,
                &users,
                &logged_in_cred,
            );
        }
        WorkflowNode::SharesNode {
            host_ip,
            hostname,
            shares,
            error,
            cred_label,
        } => {
            show_shares_panel(
                ui,
                &host_ip,
                &hostname,
                &shares,
                error.as_deref(),
                cred_label.as_deref(),
            );
        }
        WorkflowNode::UsersNode { .. } => unreachable!("users are rendered by reference above"),
        WorkflowNode::DirectoryNode { .. } => {
            unreachable!("directory inventories are rendered by reference above")
        }
        WorkflowNode::DumpNode {
            host_ip,
            hostname,
            dump_type,
            entries,
            error,
        } => {
            show_dump_panel(
                ui,
                &host_ip,
                &hostname,
                &dump_type,
                &entries,
                error.as_deref(),
            );
        }
        WorkflowNode::EnumAvNode {
            host_ip,
            hostname,
            products,
            error,
            done,
        } => {
            show_enumav_panel(ui, &host_ip, &hostname, &products, error.as_deref(), done.clone());
        }
        _ => {}
    }
}

fn start_bloodhound_export(
    state: &mut AppState,
    runtime: &RuntimeServices,
    endpoint: String,
    directory_cred_label: Option<String>,
) {
    let Some(output_directory) = rfd::FileDialog::new()
        .set_title("Select BloodHound CE output directory")
        .set_directory(".")
        .pick_folder()
    else {
        return;
    };

    let login_label = state.host_login_label(&endpoint).or(directory_cred_label);
    let credential = match login_label.as_deref() {
        None | Some("(anonymous)") => crate::state::anonymous_record(),
        Some(label) => match state.resolve_scan_login(label) {
            Ok(credential) => credential,
            Err(error) => {
                state.add_log(
                    crate::runtime::LogLevel::Error,
                    format!("Cannot export BloodHound CE for {endpoint}: {error}"),
                );
                return;
            }
        },
    };
    if let Err(error) = crate::runtime::cred_to_ldap_auth(&credential) {
        state.add_log(
            crate::runtime::LogLevel::Error,
            format!("Cannot export BloodHound CE for {endpoint}: {error}"),
        );
        return;
    }

    state.bloodhound_exports.insert(
        endpoint.clone(),
        crate::state::BloodHoundExportState::queued(output_directory.clone()),
    );
    state.bottom_panel_open = true;
    runtime.spawn_bloodhound_ce_export(
        endpoint,
        credential,
        output_directory,
        state.timeout_seconds,
    );
}

fn panel_header(ui: &mut egui::Ui, icon: &str, host_ip: &str, hostname: &str, section: &str) {
    ui.label(
        egui::RichText::new(format!("{icon} {section}"))
            .size(14.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(host_ip)
            .monospace()
            .size(12.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    if !hostname.is_empty() && hostname != host_ip {
        ui.label(
            egui::RichText::new(hostname)
                .monospace()
                .size(10.0)
                .color(theme::FG_2),
        );
    }
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);
}

fn show_host_panel(
    ui: &mut egui::Ui,
    ip: &str,
    hostname: &str,
    os_info: &str,
    domain: &str,
    signing: Option<bool>,
    smbv1: Option<bool>,
    shares: &[String],
    admin: bool,
    users: &[String],
    logged_in_cred: &Option<String>,
) {
    panel_header(ui, "🖥", ip, hostname, "Host");

    if !os_info.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("OS").small().color(LABEL_COLOR));
            ui.label(egui::RichText::new(os_info).small().color(egui::Color32::WHITE));
        });
    }
    if !domain.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Domain").small().color(LABEL_COLOR));
            ui.label(egui::RichText::new(domain).small().color(egui::Color32::WHITE));
        });
    }

    ui.add_space(4.0);

    if admin {
        let badge = if let Some(c) = logged_in_cred {
            format!("⚡ Pwn3d!  {c}")
        } else {
            "⚡ ADMIN".to_owned()
        };
        ui.label(egui::RichText::new(badge).small().strong().color(theme::SUCCESS));
    } else if let Some(c) = logged_in_cred {
        ui.label(egui::RichText::new(format!("🔑 {c}")).small().color(theme::WARNING));
    }

    ui.add_space(2.0);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Signing").small().color(LABEL_COLOR));
        let (lbl, col) = match signing {
            Some(true)  => ("Yes", theme::SUCCESS),
            Some(false) => ("No",  theme::WARNING),
            None        => ("—",   LABEL_COLOR),
        };
        ui.label(egui::RichText::new(lbl).small().strong().color(col));
    });
    if matches!(smbv1, Some(true)) {
        ui.label(egui::RichText::new("⚠ SMBv1 active").small().color(theme::ERROR));
    }

    if !shares.is_empty() {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format!("SHARES ({})", shares.len()))
                .small()
                .strong()
                .color(ACCENT),
        );
        ui.add_space(2.0);
        egui::ScrollArea::vertical()
            .id_salt("cfg_host_shares")
            .max_height(100.0)
            .show(ui, |ui| {
                for share in shares {
                    let acc_color = if share.contains("(RW)") {
                        theme::SUCCESS
                    } else if share.contains("(R)") {
                        theme::INFO
                    } else {
                        theme::ERROR
                    };
                    if let Some(p) = share.rfind('(') {
                        let main = share[..p].trim_end();
                        let acc  = &share[p..];
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            ui.label(egui::RichText::new(main).monospace().size(9.5).color(LABEL_COLOR));
                            ui.label(egui::RichText::new(acc).monospace().size(9.5).strong().color(acc_color));
                        });
                    } else {
                        ui.label(egui::RichText::new(share.as_str()).monospace().size(9.5).color(LABEL_COLOR));
                    }
                }
            });
    }

    if !users.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format!("USERS ({})", users.len()))
                .small()
                .strong()
                .color(ACCENT),
        );
        ui.add_space(2.0);
        egui::ScrollArea::vertical()
            .id_salt("cfg_host_users")
            .max_height(80.0)
            .show(ui, |ui| {
                for u in users.iter().take(20) {
                    ui.label(egui::RichText::new(u.as_str()).monospace().size(9.5).color(LABEL_COLOR));
                }
                if users.len() > 20 {
                    ui.label(
                        egui::RichText::new(format!("… +{} more", users.len() - 20))
                            .small()
                            .color(LABEL_COLOR),
                    );
                }
            });
    }
}

fn show_shares_panel(
    ui: &mut egui::Ui,
    host_ip: &str,
    hostname: &str,
    shares: &[String],
    error: Option<&str>,
    cred_label: Option<&str>,
) {
    panel_header(ui, "📂", host_ip, hostname, "Shares");

    if let Some(c) = cred_label {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Credential").small().color(LABEL_COLOR));
            ui.label(egui::RichText::new(c).small().monospace().color(theme::INFO));
        });
        ui.add_space(4.0);
    }

    if let Some(error) = error {
        ui.label(egui::RichText::new(error).small().color(theme::ERROR));
        return;
    }

    if shares.is_empty() {
        ui.label(egui::RichText::new("⚠ No shares found").small().color(theme::WARNING));
        return;
    }

    ui.label(
        egui::RichText::new(format!("SHARES ({})", shares.len()))
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    egui::ScrollArea::vertical()
        .id_salt("cfg_shares_list")
        .max_height(ui.available_height() - 20.0)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 5.0;
            for share_str in shares {
                let (name, stype, access) = parse_share_string(share_str);
                let access_color = match access {
                    "RW" => theme::SUCCESS,
                    "R"  => theme::INFO,
                    _    => theme::ERROR,
                };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(egui::RichText::new("📁").small());
                    ui.label(egui::RichText::new(name).small().strong().color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new(format!("[{stype}]")).small().color(LABEL_COLOR));
                    let badge = egui::Button::new(
                        egui::RichText::new(access).small().strong().color(egui::Color32::WHITE),
                    )
                    .fill(access_color)
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE)
                    .sense(egui::Sense::hover());
                    ui.add(badge);
                });
            }
        });
}

fn show_users_panel(
    ui: &mut egui::Ui,
    host_ip: &str,
    hostname: &str,
    users: &[crate::workflow::UserEntry],
    source: Option<netraze_core::UserEnumerationSource>,
    fallback_used: bool,
    error: Option<&str>,
    done: bool,
    loading: bool,
    cred_label: Option<&str>,
) -> bool {
    panel_header(ui, "👥", host_ip, hostname, "Users");

    let refresh = ui
        .add_enabled(!loading, egui::Button::new("↻ Refresh users"))
        .clicked();
    if let Some(label) = cred_label {
        ui.label(
            egui::RichText::new(format!("Credential: {label}"))
                .small()
                .color(LABEL_COLOR),
        );
    }
    if loading {
        ui.spinner();
        ui.label("Enumerating users…");
        return refresh;
    }
    if let Some(error) = error {
        ui.colored_label(theme::ERROR, format!("Enumeration failed: {error}"));
        return refresh;
    }
    if let Some(source) = source {
        let label = match source {
            netraze_core::UserEnumerationSource::Ldap => "LDAP",
            netraze_core::UserEnumerationSource::Samr => "SAMR",
        };
        ui.label(format!("Source: {label}"));
        if fallback_used {
            ui.colored_label(theme::WARNING, "LDAP unavailable; SAMR fallback succeeded");
        }
    }

    if users.is_empty() {
        ui.label(
            egui::RichText::new(if done {
                "No users found"
            } else {
                "Not enumerated yet"
            })
            .small()
            .color(LABEL_COLOR),
        );
        return refresh;
    }

    ui.label(
        egui::RichText::new(format!("USERS ({})", users.len()))
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    egui::ScrollArea::vertical()
        .id_salt("cfg_users_list")
        .max_height(ui.available_height() - 20.0)
        .show_rows(ui, 22.0, users.len(), |ui, rows| {
            ui.spacing_mut().item_spacing.y = 4.0;
            for user in &users[rows] {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let icon = if user.privilege_level == 2 { "👑" } else { "👤" };
                    ui.label(egui::RichText::new(icon).small());
                    let name_color = if user.disabled { LABEL_COLOR } else { egui::Color32::WHITE };
                    ui.label(egui::RichText::new(&user.name).small().strong().color(name_color));

                    let (priv_label, priv_color) = match user.privilege_level {
                        2 => ("ADMIN", theme::ERROR),
                        1 => ("USER",  theme::INFO),
                        _ => ("GUEST", LABEL_COLOR),
                    };
                    let badge = egui::Button::new(
                        egui::RichText::new(priv_label).small().strong().color(egui::Color32::WHITE),
                    )
                    .fill(priv_color)
                    .corner_radius(egui::CornerRadius::same(3))
                    .stroke(egui::Stroke::NONE)
                    .sense(egui::Sense::hover());
                    ui.add(badge);

                    if user.disabled {
                        ui.label(egui::RichText::new("DISABLED").small().color(theme::WARNING));
                    }
                    if user.locked {
                        ui.label(egui::RichText::new("🔒").small());
                    }
                });
            }
        });
    refresh
}

fn show_dump_panel(
    ui: &mut egui::Ui,
    host_ip: &str,
    hostname: &str,
    dump_type: &str,
    entries: &[String],
    error: Option<&str>,
) {
    let icon = if dump_type == "SAM" { "🔑" } else { "🔓" };
    panel_header(ui, icon, host_ip, hostname, dump_type);

    if let Some(err) = error {
        ui.label(egui::RichText::new(format!("⚠ {err}")).small().color(theme::WARNING));
        ui.add_space(4.0);
    }

    if entries.is_empty() && error.is_none() {
        ui.label(egui::RichText::new("⏳ Dumping...").small().color(LABEL_COLOR));
        return;
    }

    if entries.is_empty() {
        return;
    }

    ui.label(
        egui::RichText::new(format!("ENTRIES ({})", entries.len()))
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    let is_sam = dump_type == "SAM";
    egui::ScrollArea::vertical()
        .id_salt("cfg_dump_list")
        .max_height(ui.available_height() - 20.0)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            for entry in entries {
                if is_sam {
                    let parts: Vec<&str> = entry.splitn(7, ':').collect();
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        if parts.len() >= 4 {
                            ui.label(
                                egui::RichText::new(parts[0])
                                    .small()
                                    .strong()
                                    .color(egui::Color32::WHITE)
                                    .family(egui::FontFamily::Monospace),
                            );
                            ui.label(
                                egui::RichText::new(format!(":{}", parts[1]))
                                    .small()
                                    .color(LABEL_COLOR)
                                    .family(egui::FontFamily::Monospace),
                            );
                            ui.label(
                                egui::RichText::new(format!(":{}:{}:::", parts[2], parts[3]))
                                    .small()
                                    .color(theme::SUCCESS)
                                    .family(egui::FontFamily::Monospace),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new(entry)
                                    .small()
                                    .color(egui::Color32::WHITE)
                                    .family(egui::FontFamily::Monospace),
                            );
                        }
                    });
                } else {
                    ui.label(
                        egui::RichText::new(entry)
                            .small()
                            .color(egui::Color32::from_rgb(200, 160, 255))
                            .family(egui::FontFamily::Monospace),
                    );
                }
            }
        });
}

fn show_enumav_panel(
    ui: &mut egui::Ui,
    host_ip: &str,
    hostname: &str,
    products: &[String],
    error: Option<&str>,
    done: bool,
) {
    panel_header(ui, "🛡", host_ip, hostname, "AV/EDR");

    if let Some(err) = error {
        ui.label(egui::RichText::new(format!("⚠ {err}")).small().color(theme::WARNING));
        ui.add_space(4.0);
    }

    if !done && products.is_empty() {
        ui.label(egui::RichText::new("⏳ Scanning...").small().color(LABEL_COLOR));
        return;
    }

    if done && products.is_empty() {
        ui.label(
            egui::RichText::new("No AV/EDR detected")
                .small()
                .italics()
                .color(LABEL_COLOR),
        );
        return;
    }

    ui.label(
        egui::RichText::new(format!("PRODUCTS ({})", products.len()))
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    egui::ScrollArea::vertical()
        .id_salt("cfg_av_list")
        .max_height(ui.available_height() - 20.0)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            for product_line in products {
                let (name, status) = product_line.split_once('|').unwrap_or((product_line, ""));
                let (dot, color) = match status {
                    "INSTALLED and RUNNING" => ("🟢", theme::SUCCESS),
                    "RUNNING"               => ("🔵", theme::INFO),
                    "INSTALLED"             => ("🟡", theme::WARNING),
                    _                       => ("⚪", LABEL_COLOR),
                };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(egui::RichText::new(dot).small());
                    ui.label(egui::RichText::new(name).small().strong().color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new(status).small().color(color));
                });
            }
        });
}

fn parse_share_string(s: &str) -> (&str, &str, &str) {
    let (name, rest) = s.split_once(" [").unwrap_or((s, ""));
    let (stype, rest) = rest.split_once("] (").unwrap_or(("", rest));
    let access = rest.trim_end_matches(')');
    (name.trim(), stype, access)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ldap_state() -> AppState {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut state = AppState::new(rx);
        state.target_config.target = "dc.example.test".to_owned();
        state.target_config.protocol = "LDAP".to_owned();
        state
    }

    #[test]
    fn ldap_run_accepts_anonymous_and_inline_password_but_rejects_missing_named_secret() {
        let mut state = ldap_state();
        assert!(scan_validation_error(&state).is_none());
        state.credential_config.username = "EXAMPLE\\alice".to_owned();
        assert!(scan_validation_error(&state).is_some());
        state.credential_config.password = "test-only-password".to_owned();
        assert!(scan_validation_error(&state).is_none());
    }

    #[test]
    fn ldap_run_accepts_explicit_guest_without_secret() {
        let mut state = ldap_state();
        state.credential_config.username = "EXAMPLE\\Guest".to_owned();
        assert!(scan_validation_error(&state).is_none());
    }

    #[test]
    fn ldap_run_rejects_malformed_inline_nt_hashes() {
        let mut state = ldap_state();
        state.credential_config.username = "EXAMPLE\\alice".to_owned();
        state.credential_config.ntlm_hash = "not-an-nt-hash".to_owned();
        assert!(
            scan_validation_error(&state)
                .is_some_and(|error| error.starts_with("NT hash must be 32 hex chars"))
        );
    }
}
