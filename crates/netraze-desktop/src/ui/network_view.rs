use crate::state::{AppState, HostStatus};

const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);
const GREEN: egui::Color32 = egui::Color32::from_rgb(80, 200, 120);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(220, 170, 60);
const BLUE: egui::Color32 = egui::Color32::from_rgb(80, 140, 220);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 80, 80);

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("📁 Network")
            .size(12.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.add_space(2.0);

    // Find selected host data for detail panel
    let selected_host_data = state.selected_host.as_ref().and_then(|sel_ip| {
        state
            .networks
            .iter()
            .flat_map(|n| &n.hosts)
            .find(|h| h.ip == *sel_ip)
            .cloned()
    });

    egui::ScrollArea::vertical()
        .id_salt("network_tree_scroll")
        .auto_shrink([false, false])
        .max_height(if selected_host_data.is_some() {
            ui.available_height() * 0.45
        } else {
            ui.available_height()
        })
        .show(ui, |ui| {
            let subnet_count = state.networks.len();
            for si in 0..subnet_count {
                let cidr = state.networks[si].cidr.clone();
                let expanded = state.networks[si].expanded;
                let host_count = state.networks[si].hosts.len();

                let toggle_icon = if expanded { "▾" } else { "▸" };
                let header = format!("{toggle_icon} 🌐 {cidr}  ({host_count} hosts)");
                let header_resp = ui.add(
                    egui::Label::new(
                        egui::RichText::new(&header)
                            .monospace()
                            .size(11.0)
                            .strong()
                            .color(ACCENT),
                    )
                    .sense(egui::Sense::click()),
                );
                if header_resp.clicked() {
                    state.networks[si].expanded = !expanded;
                }

                if expanded {
                    for hi in 0..host_count {
                        let host = &state.networks[si].hosts[hi];
                        let ip = host.ip.clone();
                        let hostname = host.hostname.clone();
                        let os_info = host.os_info.clone();
                        let shares = host.shares.clone();
                        let admin_flag = host.admin;
                        let users = host.users.clone();
                        let status = host.status.clone();

                        let (status_icon, color) = match status {
                            HostStatus::Accessible => ("●", GREEN),
                            HostStatus::Locked => ("●", YELLOW),
                            HostStatus::Unknown => ("○", TEXT_DIM),
                        };

                        let is_selected = state.selected_host.as_deref() == Some(&ip);
                        let prefix = if is_selected { "▸" } else { " " };

                        // Format: ● 172.18.247.15 (HOSTNAME)
                        let label = if hostname.is_empty() || hostname == ip {
                            format!("  {prefix} {status_icon} {ip}")
                        } else {
                            format!("  {prefix} {status_icon} {ip} ({hostname})")
                        };

                        let text_color = if is_selected {
                            egui::Color32::WHITE
                        } else {
                            color
                        };

                        let resp = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&label)
                                    .monospace()
                                    .size(10.5)
                                    .color(text_color),
                            )
                            .sense(egui::Sense::click()),
                        );
                        if resp.clicked() {
                            state.selected_host = Some(ip.clone());
                        }

                        // Right-click context menu
                        let ctx_ip = ip.clone();
                        let ctx_hostname = hostname.clone();
                        let ctx_os = os_info.clone();
                        let ctx_shares = shares.clone();
                        let ctx_users = users.clone();
                        resp.context_menu(|ui| {
                            ui.label(
                                egui::RichText::new(&ctx_ip)
                                    .small()
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            );
                            ui.separator();
                            if ui.button("📌 Send to Workspace").clicked() {
                                let added = state.workflow.add_host_node(
                                    ctx_ip.clone(),
                                    ctx_hostname.clone(),
                                    ctx_os.clone(),
                                    ctx_shares.clone(),
                                    admin_flag,
                                    ctx_users.clone(),
                                );
                                if added {
                                    state.pending_fingerprints.push(ctx_ip.clone());
                                }
                                ui.close();
                            }
                            // Get Console — only offered on pwned hosts.
                            // Credential is picked from a submenu because HostRecord does not
                            // track which credential pwned the host.
                            if admin_flag && !state.credentials.is_empty() {
                                ui.menu_button("🖥 Get Console", |ui| {
                                    ui.set_min_width(180.0);
                                    let mut to_open: Option<crate::state::CredentialRecord> = None;
                                    for cred in &state.credentials {
                                        let cred_label = if cred.domain.is_empty() {
                                            format!(".\\{}", cred.username)
                                        } else {
                                            format!("{}\\{}", cred.domain, cred.username)
                                        };
                                        let type_tag = match cred.cred_type {
                                            crate::state::CredType::Hash => "[H]",
                                            crate::state::CredType::Password => "[P]",
                                        };
                                        let label = format!("{type_tag} {cred_label}");
                                        if ui.button(label).clicked() {
                                            to_open = Some(cred.clone());
                                            ui.close();
                                        }
                                    }
                                    if let Some(cred) = to_open {
                                        state.open_console(
                                            ctx_ip.clone(),
                                            ctx_hostname.clone(),
                                            cred,
                                        );
                                    }
                                });
                            }
                        });
                    }
                }
            }

            if state.networks.is_empty() {
                ui.label(
                    egui::RichText::new("No networks scanned yet")
                        .italics()
                        .color(TEXT_DIM),
                );
            }
        });

    // -- Host detail panel --
    if let Some(host) = selected_host_data {
        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("host_detail_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(format!("📋 {}", host.ip))
                        .size(11.0)
                        .strong()
                        .color(egui::Color32::WHITE),
                );

                if !host.hostname.is_empty() && host.hostname != host.ip {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Name:").small().color(TEXT_DIM));
                        ui.label(
                            egui::RichText::new(&host.hostname)
                                .small()
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                    });
                }
                if !host.os_info.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("OS:").small().color(TEXT_DIM));
                        ui.label(
                            egui::RichText::new(&host.os_info)
                                .small()
                                .color(egui::Color32::WHITE),
                        );
                    });
                }
                if host.admin {
                    ui.label(
                        egui::RichText::new("⚡ ADMIN ACCESS")
                            .small()
                            .strong()
                            .color(GREEN),
                    );
                }

                if !host.shares.is_empty() {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new("Shares:")
                            .small()
                            .strong()
                            .color(ACCENT),
                    );
                    for share_str in &host.shares {
                        // Parse access tag from the share string: "NAME [TYPE] (ACCESS)"
                        let access_color = if share_str.contains("(RW)") {
                            GREEN
                        } else if share_str.contains("(R)") {
                            BLUE
                        } else {
                            RED
                        };

                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            // Split: name [type] and (access)
                            if let Some(paren_start) = share_str.rfind('(') {
                                let main_part = &share_str[..paren_start].trim_end();
                                let access_part = &share_str[paren_start..];
                                ui.label(
                                    egui::RichText::new(format!("  {main_part} "))
                                        .monospace()
                                        .size(9.5)
                                        .color(TEXT_DIM),
                                );
                                ui.label(
                                    egui::RichText::new(access_part)
                                        .monospace()
                                        .size(9.5)
                                        .strong()
                                        .color(access_color),
                                );
                            } else {
                                ui.label(
                                    egui::RichText::new(format!("  {share_str}"))
                                        .monospace()
                                        .size(9.5)
                                        .color(TEXT_DIM),
                                );
                            }
                        });
                    }
                }

                if !host.users.is_empty() {
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new("Users:").small().strong().color(ACCENT));
                    for user in &host.users {
                        ui.label(
                            egui::RichText::new(format!("  {user}"))
                                .monospace()
                                .size(9.5)
                                .color(TEXT_DIM),
                        );
                    }
                }
            });
    }
}
