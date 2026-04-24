use crate::state::{AppState, HostStatus};
use crate::workflow::WorkflowNode;
use egui::{Color32, Pos2, Rect, Ui};

const TEXT_DIM: Color32 = Color32::from_rgb(160, 165, 175);
const ROW_ALT: Color32 = Color32::from_rgba_premultiplied(14, 18, 25, 180);
const ROW_HOVER: Color32 = Color32::from_rgba_premultiplied(35, 42, 54, 200);
const SEPARATOR: Color32 = Color32::from_rgb(40, 46, 58);
const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
const BLUE: Color32 = Color32::from_rgb(80, 170, 255);
const YELLOW: Color32 = Color32::from_rgb(220, 200, 60);
const DOT_COLOR: Color32 = Color32::from_rgb(38, 44, 56);
const DOT_SPACING: f32 = 20.0;
const DOT_RADIUS: f32 = 1.0;
const ROW_H: f32 = 30.0;

struct FlatHost {
    ip: String,
    hostname: String,
    os_info: String,
    shares_count: usize,
    users_count: usize,
    admin: bool,
    status: HostStatus,
}

pub fn show(ui: &mut Ui, state: &mut AppState) {
    ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);

    // ── Draw dot-grid background (same as workspace canvas) ──
    let full_rect = ui.available_rect_before_wrap();
    let painter = ui.painter();
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

    // ── Merge data: networks + workflow nodes ──
    let mut all: Vec<FlatHost> = state
        .networks
        .iter()
        .flat_map(|net| {
            net.hosts.iter().map(|h| {
                let mut fh = FlatHost {
                    ip: h.ip.clone(),
                    hostname: h.hostname.clone(),
                    os_info: h.os_info.clone(),
                    shares_count: h.shares.len(),
                    users_count: h.users.len(),
                    admin: h.admin,
                    status: h.status.clone(),
                };
                // Enrich from workflow nodes
                for node in state.workflow.snarl.nodes() {
                    match node {
                        WorkflowNode::HostNode {
                            ip: nip,
                            hostname: nh,
                            os_info: nos,
                            admin: na,
                            shares,
                            users,
                            ..
                        } => {
                            if *nip == fh.ip {
                                if fh.hostname.is_empty() && !nh.is_empty() {
                                    fh.hostname = nh.clone();
                                }
                                if fh.os_info.is_empty() && !nos.is_empty() {
                                    fh.os_info = nos.clone();
                                }
                                if *na {
                                    fh.admin = true;
                                    fh.status = HostStatus::Accessible;
                                }
                                if fh.shares_count == 0 && !shares.is_empty() {
                                    fh.shares_count = shares.len();
                                }
                                if fh.users_count == 0 && !users.is_empty() {
                                    fh.users_count = users.len();
                                }
                            }
                        }
                        WorkflowNode::SharesNode {
                            host_ip, shares, ..
                        } => {
                            if *host_ip == fh.ip && fh.shares_count == 0 {
                                fh.shares_count = shares.len();
                            }
                        }
                        WorkflowNode::UsersNode { host_ip, users, .. } => {
                            if *host_ip == fh.ip && fh.users_count == 0 {
                                fh.users_count = users.len();
                            }
                        }
                        _ => {}
                    }
                }
                fh
            })
        })
        .collect();

    // Also add workflow hosts not in networks
    for node in state.workflow.snarl.nodes() {
        if let WorkflowNode::HostNode {
            ip,
            hostname,
            os_info,
            admin,
            shares,
            users,
            ..
        } = node
        {
            if !all.iter().any(|h| h.ip == *ip) {
                all.push(FlatHost {
                    ip: ip.clone(),
                    hostname: hostname.clone(),
                    os_info: os_info.clone(),
                    shares_count: shares.len(),
                    users_count: users.len(),
                    admin: *admin,
                    status: if *admin {
                        HostStatus::Accessible
                    } else {
                        HostStatus::Unknown
                    },
                });
            }
        }
    }

    let query = state.target_search.to_ascii_lowercase();
    let filtered: Vec<usize> = (0..all.len())
        .filter(|&i| {
            if query.is_empty() {
                return true;
            }
            all[i].ip.to_ascii_lowercase().contains(&query)
                || all[i].hostname.to_ascii_lowercase().contains(&query)
                || all[i].os_info.to_ascii_lowercase().contains(&query)
        })
        .collect();

    let total = all.len();
    let shown = filtered.len();
    let pwned = all.iter().filter(|h| h.admin).count();
    let authed = all
        .iter()
        .filter(|h| matches!(h.status, HostStatus::Accessible | HostStatus::Locked))
        .count();

    // ── Top header ──
    let pad = 20.0;
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.label(
            egui::RichText::new("🎯 Targets")
                .size(18.0)
                .strong()
                .color(Color32::WHITE),
        );
        ui.add_space(16.0);
        badge(ui, &total.to_string(), "total", TEXT_DIM);
        badge(ui, &pwned.to_string(), "pwn3d", GREEN);
        badge(ui, &authed.to_string(), "auth", BLUE);
        if shown != total {
            badge(ui, &shown.to_string(), "match", YELLOW);
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(pad);
            ui.add(
                egui::TextEdit::singleline(&mut state.target_search)
                    .desired_width(240.0)
                    .hint_text("🔍  Search IP, hostname, OS…")
                    .font(egui::TextStyle::Monospace),
            );
        });
    });
    ui.add_space(6.0);

    // Separator
    {
        let r = ui.available_rect_before_wrap();
        ui.painter().hline(
            (r.left() + pad)..=(r.right() - pad),
            r.top(),
            egui::Stroke::new(1.0, SEPARATOR),
        );
        ui.add_space(2.0);
    }

    // Column widths
    let tw = (ui.available_width() - pad * 2.0).max(700.0);
    let c_ip = tw * 0.13;
    let c_proto = tw * 0.07;
    let c_status = tw * 0.10;
    let c_host = tw * 0.16;
    let c_os = tw * 0.34;
    let c_shares = tw * 0.08;
    let c_users = tw * 0.08;
    let col_labels = [
        ("IP", c_ip),
        ("PROTOCOL", c_proto),
        ("STATUS", c_status),
        ("HOSTNAME", c_host),
        ("OS", c_os),
        ("SHARES", c_shares),
        ("USERS", c_users),
    ];

    // ── Header row ──
    {
        let (hr, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 22.0), egui::Sense::hover());
        let y = hr.center().y;
        let mut x = hr.left() + pad;
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
            (r.left() + pad)..=(r.right() - pad),
            r.top(),
            egui::Stroke::new(1.0, SEPARATOR),
        );
        ui.add_space(1.0);
    }

    // ── Rows ──
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            let mut send_idx: Option<usize> = None;

            for (row_idx, &host_idx) in filtered.iter().enumerate() {
                let h = &all[host_idx];
                let is_alt = row_idx % 2 == 1;

                let (row_rect, row_resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), ROW_H),
                    egui::Sense::click(),
                );

                // Background
                let bg = if row_resp.hovered() {
                    ROW_HOVER
                } else if is_alt {
                    ROW_ALT
                } else {
                    Color32::TRANSPARENT
                };
                ui.painter().rect_filled(row_rect, 0.0, bg);

                let y = row_rect.center().y;
                let mut x = row_rect.left() + pad;
                let fm = egui::FontId::new(12.0, egui::FontFamily::Monospace);
                let fs = egui::FontId::new(11.0, egui::FontFamily::Monospace);
                let fp = egui::FontId::new(12.0, egui::FontFamily::Proportional);
                let fps = egui::FontId::new(11.0, egui::FontFamily::Proportional);

                // IP
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &h.ip,
                    fm.clone(),
                    Color32::WHITE,
                );
                x += c_ip;

                // Protocol
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    "SMB",
                    fs.clone(),
                    BLUE,
                );
                x += c_proto;

                // Status badge
                if h.admin {
                    let br =
                        Rect::from_min_size(Pos2::new(x + 2.0, y - 9.0), egui::vec2(66.0, 18.0));
                    ui.painter().rect_filled(
                        br,
                        egui::CornerRadius::same(3),
                        Color32::from_rgb(150, 30, 30),
                    );
                    ui.painter().text(
                        br.center(),
                        egui::Align2::CENTER_CENTER,
                        "Pwn3d!",
                        fs.clone(),
                        Color32::WHITE,
                    );
                } else {
                    match h.status {
                        HostStatus::Accessible | HostStatus::Locked => {
                            let br = Rect::from_min_size(
                                Pos2::new(x + 2.0, y - 9.0),
                                egui::vec2(66.0, 18.0),
                            );
                            ui.painter().rect_filled(
                                br,
                                egui::CornerRadius::same(3),
                                Color32::from_rgb(25, 55, 35),
                            );
                            ui.painter().text(
                                br.center(),
                                egui::Align2::CENTER_CENTER,
                                "Auth ✔",
                                fs.clone(),
                                GREEN,
                            );
                        }
                        HostStatus::Unknown => {
                            ui.painter().text(
                                Pos2::new(x + 4.0, y),
                                egui::Align2::LEFT_CENTER,
                                "—",
                                fs.clone(),
                                TEXT_DIM,
                            );
                        }
                    }
                }
                x += c_status;

                // Hostname
                let hn = if h.hostname.is_empty() {
                    "—"
                } else {
                    &h.hostname
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    hn,
                    fp.clone(),
                    Color32::WHITE,
                );
                x += c_host;

                // OS
                let os = if h.os_info.is_empty() {
                    "—"
                } else {
                    &h.os_info
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    os,
                    fps.clone(),
                    TEXT_DIM,
                );
                x += c_os;

                // Shares
                let sc = h.shares_count;
                let (st, sc_col) = if sc > 0 {
                    (format!("{sc}"), BLUE)
                } else {
                    ("—".into(), TEXT_DIM)
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &st,
                    fs.clone(),
                    sc_col,
                );
                x += c_shares;

                // Users
                let uc = h.users_count;
                let (ut, uc_col) = if uc > 0 {
                    (format!("{uc}"), BLUE)
                } else {
                    ("—".into(), TEXT_DIM)
                };
                ui.painter().text(
                    Pos2::new(x + 4.0, y),
                    egui::Align2::LEFT_CENTER,
                    &ut,
                    fs.clone(),
                    uc_col,
                );

                // Context menu
                row_resp.context_menu(|ui| {
                    if ui.button("📌  Send to Workspace").clicked() {
                        send_idx = Some(host_idx);
                        ui.close();
                    }
                });
            }

            // Process send-to-workspace
            if let Some(idx) = send_idx {
                let h = &all[idx];
                let added = state.workflow.add_host_node(
                    h.ip.clone(),
                    h.hostname.clone(),
                    h.os_info.clone(),
                    Vec::new(),
                    h.admin,
                    Vec::new(),
                );
                if added {
                    state.pending_fingerprints.push(h.ip.clone());
                }
            }

            // Empty state
            if filtered.is_empty() {
                ui.add_space(80.0);
                ui.vertical_centered(|ui| {
                    if total == 0 {
                        ui.label(
                            egui::RichText::new("No targets scanned yet")
                                .size(16.0)
                                .color(TEXT_DIM),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(
                                "Run a scan from the Workspace tab to populate this view",
                            )
                            .size(12.0)
                            .color(TEXT_DIM)
                            .italics(),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("No hosts match your search")
                                .size(14.0)
                                .color(TEXT_DIM),
                        );
                    }
                });
            }
        });
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
