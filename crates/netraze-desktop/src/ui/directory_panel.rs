//! Read-only Active Directory inventory presentation.
//!
//! The workflow node owns one directory snapshot. This panel borrows that
//! snapshot and keeps only lightweight tab/search state in egui's temporary
//! data store, avoiding a clone of large LDAP result sets on every repaint.

use netraze_core::{
    DirectoryComputer, DirectoryGroup, DirectoryInventory, DirectoryPrincipalKind,
    DirectorySection, DirectoryUser,
};

use crate::theme;

const LABEL_COLOR: egui::Color32 = theme::MUTED;
const ACCENT: egui::Color32 = theme::ACC;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum DirectoryTab {
    #[default]
    Overview,
    Users,
    Groups,
    Computers,
    Organization,
    Topology,
    Privileged,
    Services,
    Security,
}

impl DirectoryTab {
    const ALL: [(Self, &'static str); 9] = [
        (Self::Overview, "Overview"),
        (Self::Users, "Users"),
        (Self::Groups, "Groups"),
        (Self::Computers, "Computers"),
        (Self::Organization, "OUs"),
        (Self::Topology, "Topology"),
        (Self::Privileged, "Privileged"),
        (Self::Services, "Services"),
        (Self::Security, "Security"),
    ];
}

pub(super) struct DirectoryView<'a> {
    pub endpoint: &'a str,
    pub hostname: &'a str,
    pub inventory: Option<&'a DirectoryInventory>,
    pub error: Option<&'a str>,
    pub loading: bool,
    pub cred_label: Option<&'a str>,
}

pub(super) fn show(ui: &mut egui::Ui, node_key: usize, view: DirectoryView<'_>) {
    header(ui, view.endpoint, view.hostname, view.cred_label);
    if view.loading {
        ui.spinner();
        ui.label("Discovering the directory…");
        return;
    }
    if let Some(error) = view.error {
        ui.colored_label(theme::ERROR, format!("LDAP discovery failed: {error}"));
        return;
    }
    let Some(inventory) = view.inventory else {
        ui.colored_label(theme::WARNING, "No directory inventory is available");
        return;
    };

    let tab_id = egui::Id::new(("directory-tab", node_key));
    let mut selected = ui
        .ctx()
        .data_mut(|data| data.get_temp::<DirectoryTab>(tab_id).unwrap_or_default());
    ui.horizontal_wrapped(|ui| {
        for (tab, label) in DirectoryTab::ALL {
            if ui.selectable_label(selected == tab, label).clicked() {
                selected = tab;
            }
        }
    });
    ui.ctx().data_mut(|data| data.insert_temp(tab_id, selected));
    ui.separator();

    let search_id = egui::Id::new(("directory-search", node_key));
    let searchable = !matches!(selected, DirectoryTab::Overview | DirectoryTab::Security);
    let mut search = ui
        .ctx()
        .data_mut(|data| data.get_temp::<String>(search_id).unwrap_or_default());
    if searchable {
        ui.add(
            egui::TextEdit::singleline(&mut search)
                .hint_text("Filter this tab…")
                .desired_width(f32::INFINITY),
        );
        ui.ctx()
            .data_mut(|data| data.insert_temp(search_id, search.clone()));
    }
    let query = search.trim().to_ascii_lowercase();

    match selected {
        DirectoryTab::Overview => show_overview(ui, inventory),
        DirectoryTab::Users => show_users(ui, &inventory.users, &query),
        DirectoryTab::Groups => show_groups(ui, &inventory.groups, &query),
        DirectoryTab::Computers => show_computers(ui, &inventory.computers, &query),
        DirectoryTab::Organization => show_organization(ui, inventory, &query),
        DirectoryTab::Topology => show_topology(ui, inventory, &query),
        DirectoryTab::Privileged => show_privileged(ui, inventory, &query),
        DirectoryTab::Services => show_services(ui, inventory, &query),
        DirectoryTab::Security => show_security(ui, inventory),
    }
}

fn header(ui: &mut egui::Ui, endpoint: &str, hostname: &str, cred_label: Option<&str>) {
    ui.label(
        egui::RichText::new("📚 AD Directory")
            .size(14.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.label(
        egui::RichText::new(endpoint)
            .monospace()
            .strong()
            .color(egui::Color32::WHITE),
    );
    if !hostname.is_empty() && hostname != endpoint {
        ui.label(
            egui::RichText::new(hostname)
                .monospace()
                .small()
                .color(theme::FG_2),
        );
    }
    if let Some(label) = cred_label {
        ui.label(
            egui::RichText::new(format!("Credential: {label}"))
                .small()
                .color(theme::INFO),
        );
    }
    ui.add_space(4.0);
}

fn show_overview(ui: &mut egui::Ui, inventory: &DirectoryInventory) {
    let server = &inventory.server;
    heading(ui, "DIRECTORY SERVER");
    field(ui, "Default naming context", &server.default_naming_context);
    optional_field(
        ui,
        "Root domain",
        server.root_domain_naming_context.as_deref(),
    );
    optional_field(
        ui,
        "Configuration",
        server.configuration_naming_context.as_deref(),
    );
    optional_field(ui, "Schema", server.schema_naming_context.as_deref());
    optional_field(ui, "Server", server.server_name.as_deref());
    optional_field(ui, "Service", server.service_name.as_deref());
    optional_number(
        ui,
        "DC functional level",
        server.domain_controller_functionality,
    );
    optional_number(ui, "Domain functional level", server.domain_functionality);
    optional_number(ui, "Forest functional level", server.forest_functionality);
    optional_bool(ui, "Global catalog ready", server.global_catalog_ready);
    optional_bool(ui, "Synchronized", server.synchronized);

    ui.add_space(8.0);
    heading(ui, "INVENTORY");
    count(ui, "Users", inventory.users.items.len());
    count(ui, "Groups", inventory.groups.items.len());
    count(ui, "Computers", inventory.computers.items.len());
    count(ui, "OUs / containers", inventory.organization.items.len());
    count(
        ui,
        "Privileged principals",
        inventory.privileged.items.len(),
    );
    count(ui, "Service principals", inventory.services.items.len());

    ui.add_space(8.0);
    heading(ui, "ROOTDSE CAPABILITIES");
    wrapped_values(ui, "LDAP versions", &server.supported_ldap_versions);
    wrapped_values(ui, "SASL mechanisms", &server.supported_sasl_mechanisms);
    wrapped_values(ui, "Controls", &server.supported_controls);
    wrapped_values(ui, "Extensions", &server.supported_extensions);
    wrapped_values(ui, "Capabilities", &server.supported_capabilities);

    for (name, section) in [
        ("Users", section_view(&inventory.users)),
        ("Groups", section_view(&inventory.groups)),
        ("Computers", section_view(&inventory.computers)),
        ("Organization", section_view(&inventory.organization)),
        ("Topology", section_view(&inventory.topology)),
        ("Privileged", section_view(&inventory.privileged)),
        ("Services", section_view(&inventory.services)),
        ("Security", section_view(&inventory.security)),
    ] {
        show_issue_values(ui, name, section.error, section.referrals);
    }
}

fn show_users(ui: &mut egui::Ui, section: &DirectorySection<DirectoryUser>, query: &str) {
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |user| {
        matches_query(
            query,
            [
                user.name.as_str(),
                user.dn.as_str(),
                user.display_name.as_deref().unwrap_or_default(),
                user.user_principal_name.as_deref().unwrap_or_default(),
            ],
        )
    });
    list_rows(ui, "directory-users", &indices, |ui, index| {
        let user = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(&user.name)
                    .strong()
                    .color(if user.disabled {
                        LABEL_COLOR
                    } else {
                        egui::Color32::WHITE
                    }),
            );
            if user.admin_count {
                badge(ui, "ADMIN", theme::ERROR);
            }
            if user.disabled {
                badge(ui, "DISABLED", theme::WARNING);
            }
            if user.locked {
                badge(ui, "LOCKED", theme::WARNING);
            }
            if !user.service_principal_names.is_empty() {
                badge(
                    ui,
                    &format!("{} SPNs", user.service_principal_names.len()),
                    theme::INFO,
                );
            }
        });
        detail(ui, user.user_principal_name.as_deref().unwrap_or(&user.dn));
    });
}

fn show_groups(ui: &mut egui::Ui, section: &DirectorySection<DirectoryGroup>, query: &str) {
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |group| {
        matches_query(query, [group.name.as_str(), group.dn.as_str()])
    });
    list_rows(ui, "directory-groups", &indices, |ui, index| {
        let group = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(&group.name)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
            badge(ui, group_scope(group.group_type), theme::INFO);
            badge(
                ui,
                if group_type_bits(group.group_type) & 0x8000_0000 != 0 {
                    "SECURITY"
                } else {
                    "DISTRIBUTION"
                },
                LABEL_COLOR,
            );
            if group.admin_count {
                badge(ui, "ADMIN", theme::ERROR);
            }
        });
        detail(
            ui,
            &format!(
                "{} direct members • {} parent groups",
                group.members.len(),
                group.member_of.len()
            ),
        );
    });
}

fn show_computers(ui: &mut egui::Ui, section: &DirectorySection<DirectoryComputer>, query: &str) {
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |computer| {
        matches_query(
            query,
            [
                computer.name.as_str(),
                computer.dn.as_str(),
                computer.dns_host_name.as_deref().unwrap_or_default(),
                computer.operating_system.as_deref().unwrap_or_default(),
            ],
        )
    });
    list_rows(ui, "directory-computers", &indices, |ui, index| {
        let computer = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(&computer.name)
                    .strong()
                    .color(if computer.disabled {
                        LABEL_COLOR
                    } else {
                        egui::Color32::WHITE
                    }),
            );
            if computer.disabled {
                badge(ui, "DISABLED", theme::WARNING);
            }
            if computer.trusted_for_delegation {
                badge(ui, "UNCONSTRAINED DELEGATION", theme::ERROR);
            }
            if computer.trusted_to_auth_for_delegation {
                badge(ui, "PROTOCOL TRANSITION", theme::WARNING);
            }
        });
        let host = computer.dns_host_name.as_deref().unwrap_or(&computer.dn);
        let os = computer.operating_system.as_deref().unwrap_or("unknown OS");
        detail(
            ui,
            &format!(
                "{host} • {os} • {} SPNs",
                computer.service_principal_names.len()
            ),
        );
    });
}

fn show_organization(ui: &mut egui::Ui, inventory: &DirectoryInventory, query: &str) {
    let section = &inventory.organization;
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |container| {
        matches_query(query, [container.name.as_str(), container.dn.as_str()])
    });
    list_rows(ui, "directory-organization", &indices, |ui, index| {
        let container = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(if container.is_organizational_unit {
                "🏢"
            } else {
                "📁"
            });
            ui.label(
                egui::RichText::new(&container.name)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
            if !container.gpo_links.is_empty() {
                badge(
                    ui,
                    &format!("{} GPO links", container.gpo_links.len()),
                    theme::INFO,
                );
            }
        });
        detail(ui, container.parent_dn.as_deref().unwrap_or(&container.dn));
    });
}

fn show_topology(ui: &mut egui::Ui, inventory: &DirectoryInventory, query: &str) {
    show_section_status(ui, &inventory.topology);
    egui::ScrollArea::vertical()
        .id_salt("directory-topology")
        .max_height((ui.available_height() - 12.0).max(100.0))
        .show(ui, |ui| {
            for topology in &inventory.topology.items {
                heading(ui, &format!("DOMAINS ({})", topology.domains.len()));
                for domain in &topology.domains {
                    let text = domain.dns_root.as_deref().unwrap_or(&domain.dn);
                    if matches_query(query, [text, domain.dn.as_str()]) {
                        ui.label(egui::RichText::new(text).strong());
                        detail(ui, &domain.dn);
                    }
                }
                heading(ui, &format!("TRUSTS ({})", topology.trusts.len()));
                for trust in &topology.trusts {
                    if matches_query(query, [trust.partner.as_str(), trust.dn.as_str()]) {
                        ui.label(egui::RichText::new(&trust.partner).strong());
                        detail(
                            ui,
                            &format!(
                                "direction {:?} • type {:?} • attributes {:?}",
                                trust.direction, trust.trust_type, trust.attributes
                            ),
                        );
                    }
                }
                heading(ui, &format!("SITES ({})", topology.sites.len()));
                for site in &topology.sites {
                    if matches_query(query, [site.name.as_str(), site.dn.as_str()]) {
                        ui.label(egui::RichText::new(&site.name).strong());
                        detail(ui, site.location.as_deref().unwrap_or(&site.dn));
                    }
                }
                heading(ui, &format!("SUBNETS ({})", topology.subnets.len()));
                for subnet in &topology.subnets {
                    if matches_query(query, [subnet.name.as_str(), subnet.dn.as_str()]) {
                        ui.label(egui::RichText::new(&subnet.name).strong());
                        detail(ui, subnet.site_dn.as_deref().unwrap_or("unassigned"));
                    }
                }
                heading(
                    ui,
                    &format!("GROUP POLICIES ({})", topology.group_policies.len()),
                );
                for policy in &topology.group_policies {
                    let name = policy.display_name.as_deref().unwrap_or(&policy.id);
                    if matches_query(query, [name, policy.dn.as_str()]) {
                        ui.label(egui::RichText::new(name).strong());
                        detail(ui, policy.file_system_path.as_deref().unwrap_or(&policy.dn));
                    }
                }
            }
        });
}

fn show_privileged(ui: &mut egui::Ui, inventory: &DirectoryInventory, query: &str) {
    let section = &inventory.privileged;
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |principal| {
        matches_query(
            query,
            [principal.name.as_str(), principal.dn.as_str()]
                .into_iter()
                .chain(principal.reasons.iter().map(String::as_str)),
        )
    });
    list_rows(ui, "directory-privileged", &indices, |ui, index| {
        let principal = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(&principal.name)
                    .strong()
                    .color(theme::ERROR),
            );
            badge(ui, principal_kind(principal.kind), theme::INFO);
        });
        detail(ui, &principal.reasons.join(" • "));
    });
}

fn show_services(ui: &mut egui::Ui, inventory: &DirectoryInventory, query: &str) {
    let section = &inventory.services;
    show_section_status(ui, section);
    let indices = filtered_indices(&section.items, |principal| {
        matches_query(
            query,
            [principal.name.as_str(), principal.dn.as_str()]
                .into_iter()
                .chain(principal.service_principal_names.iter().map(String::as_str)),
        )
    });
    list_rows(ui, "directory-services", &indices, |ui, index| {
        let principal = &section.items[index];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(&principal.name)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
            badge(ui, principal_kind(principal.kind), theme::INFO);
            badge(
                ui,
                &format!("{} SPNs", principal.service_principal_names.len()),
                ACCENT,
            );
        });
        let summary = principal.dns_host_name.as_deref().unwrap_or_else(|| {
            principal
                .service_principal_names
                .first()
                .map_or(&principal.dn, String::as_str)
        });
        ui.label(
            egui::RichText::new(summary)
                .small()
                .monospace()
                .color(LABEL_COLOR),
        )
        .on_hover_text(principal.service_principal_names.join("\n"));
    });
}

fn show_security(ui: &mut egui::Ui, inventory: &DirectoryInventory) {
    let section = &inventory.security;
    show_section_status(ui, section);
    let Some(settings) = section.items.first() else {
        ui.label("No domain security settings were returned");
        return;
    };
    egui::ScrollArea::vertical()
        .id_salt("directory-security")
        .max_height((ui.available_height() - 12.0).max(100.0))
        .show(ui, |ui| {
            heading(ui, "PASSWORD POLICY");
            optional_number(ui, "Minimum length", settings.minimum_password_length);
            optional_number(ui, "History length", settings.password_history_length);
            optional_duration(ui, "Minimum age", settings.minimum_password_age_100ns);
            optional_duration(ui, "Maximum age", settings.maximum_password_age_100ns);
            optional_hex(ui, "Password properties", settings.password_properties);

            heading(ui, "LOCKOUT AND DOMAIN POLICY");
            optional_number(ui, "Lockout threshold", settings.lockout_threshold);
            optional_duration(ui, "Lockout duration", settings.lockout_duration_100ns);
            optional_duration(
                ui,
                "Observation window",
                settings.lockout_observation_window_100ns,
            );
            optional_number(ui, "Machine account quota", settings.machine_account_quota);
            optional_number(
                ui,
                "Domain behavior version",
                settings.domain_behavior_version,
            );

            heading(ui, "LDAP SESSION");
            bool_field(ui, "NTLM signing negotiated", settings.session_signing);
            bool_field(ui, "NTLM sealing negotiated", settings.session_sealing);
            tested_bool(
                ui,
                "Server signing enforcement",
                settings.signing_enforcement,
            );
            tested_bool(
                ui,
                "Channel binding enforcement",
                settings.channel_binding_enforcement,
            );
            tested_bool(ui, "Anonymous access", settings.anonymous_access);
            tested_bool(ui, "StartTLS available", settings.start_tls_available);
            tested_bool(ui, "LDAPS available", settings.ldaps_available);

            if !settings.ldap_admin_limits.is_empty() {
                heading(ui, "LDAP QUERY POLICY");
                for (name, value) in &settings.ldap_admin_limits {
                    field(ui, name, value);
                }
            }
        });
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(7.0);
    ui.label(egui::RichText::new(text).small().strong().color(ACCENT));
}

fn field(ui: &mut egui::Ui, name: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(name).small().color(LABEL_COLOR));
        ui.label(
            egui::RichText::new(value)
                .small()
                .monospace()
                .color(egui::Color32::WHITE),
        );
    });
}

fn optional_field(ui: &mut egui::Ui, name: &str, value: Option<&str>) {
    field(ui, name, value.unwrap_or("Not reported"));
}

fn optional_number(ui: &mut egui::Ui, name: &str, value: Option<u32>) {
    field(
        ui,
        name,
        &value.map_or_else(|| "Not reported".to_owned(), |value| value.to_string()),
    );
}

fn optional_hex(ui: &mut egui::Ui, name: &str, value: Option<u32>) {
    field(
        ui,
        name,
        &value.map_or_else(
            || "Not reported".to_owned(),
            |value| format!("0x{value:08x}"),
        ),
    );
}

fn optional_duration(ui: &mut egui::Ui, name: &str, value: Option<i64>) {
    field(
        ui,
        name,
        &value.map_or_else(|| "Not reported".to_owned(), format_ad_duration),
    );
}

fn optional_bool(ui: &mut egui::Ui, name: &str, value: Option<bool>) {
    field(
        ui,
        name,
        value.map_or("Not reported", |value| if value { "Yes" } else { "No" }),
    );
}

fn tested_bool(ui: &mut egui::Ui, name: &str, value: Option<bool>) {
    field(
        ui,
        name,
        value.map_or("Not tested", |value| if value { "Yes" } else { "No" }),
    );
}

fn bool_field(ui: &mut egui::Ui, name: &str, value: bool) {
    field(ui, name, if value { "Yes" } else { "No" });
}

fn count(ui: &mut egui::Ui, name: &str, value: usize) {
    field(ui, name, &value.to_string());
}

fn wrapped_values(ui: &mut egui::Ui, name: &str, values: &[String]) {
    if values.is_empty() {
        field(ui, name, "Not reported");
    } else {
        field(ui, name, &values.join(", "));
    }
}

fn detail(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .small()
            .monospace()
            .color(LABEL_COLOR),
    );
}

fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.label(egui::RichText::new(text).small().strong().color(color));
}

fn list_rows(
    ui: &mut egui::Ui,
    id: &'static str,
    indices: &[usize],
    mut row: impl FnMut(&mut egui::Ui, usize),
) {
    if indices.is_empty() {
        ui.label(
            egui::RichText::new("No matching entries")
                .small()
                .color(LABEL_COLOR),
        );
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height((ui.available_height() - 12.0).max(100.0))
        .show_rows(ui, 44.0, indices.len(), |ui, rows| {
            for filtered_index in rows {
                row(ui, indices[filtered_index]);
                ui.separator();
            }
        });
}

fn filtered_indices<T>(items: &[T], mut predicate: impl FnMut(&T) -> bool) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| predicate(item).then_some(index))
        .collect()
}

fn matches_query<'a>(query: &str, values: impl IntoIterator<Item = &'a str>) -> bool {
    query.is_empty()
        || values
            .into_iter()
            .any(|value| value.to_ascii_lowercase().contains(query))
}

fn show_section_status<T>(ui: &mut egui::Ui, section: &DirectorySection<T>) {
    show_issue_values(
        ui,
        "This section",
        section.error.as_deref(),
        &section.referrals,
    );
}

#[derive(Clone, Copy)]
struct SectionView<'a> {
    error: Option<&'a str>,
    referrals: &'a [String],
}

fn section_view<T>(section: &DirectorySection<T>) -> SectionView<'_> {
    SectionView {
        error: section.error.as_deref(),
        referrals: &section.referrals,
    }
}

fn show_issue_values(ui: &mut egui::Ui, name: &str, error: Option<&str>, referrals: &[String]) {
    if let Some(error) = error {
        ui.colored_label(theme::WARNING, format!("{name}: {error}"));
    }
    for referral in referrals {
        ui.colored_label(
            theme::WARNING,
            format!("{name} referral (not followed): {referral}"),
        );
    }
}

fn group_scope(group_type: i32) -> &'static str {
    match group_type_bits(group_type) & 0x0000_000e {
        0x0000_0002 => "GLOBAL",
        0x0000_0004 => "DOMAIN LOCAL",
        0x0000_0008 => "UNIVERSAL",
        _ => "UNKNOWN SCOPE",
    }
}

fn group_type_bits(group_type: i32) -> u32 {
    u32::from_ne_bytes(group_type.to_ne_bytes())
}

fn principal_kind(kind: DirectoryPrincipalKind) -> &'static str {
    match kind {
        DirectoryPrincipalKind::User => "USER",
        DirectoryPrincipalKind::Group => "GROUP",
        DirectoryPrincipalKind::Computer => "COMPUTER",
        DirectoryPrincipalKind::ManagedServiceAccount => "MANAGED SERVICE ACCOUNT",
    }
}

fn format_ad_duration(value: i64) -> String {
    let seconds = value.unsigned_abs() / 10_000_000;
    if seconds != 0 && seconds % 86_400 == 0 {
        format!("{} days", seconds / 86_400)
    } else if seconds != 0 && seconds % 3_600 == 0 {
        format!("{} hours", seconds / 3_600)
    } else {
        format!("{seconds} seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_type_bits_are_presented_without_signed_overflow() {
        assert_eq!(group_scope(i32::MIN | 0x2), "GLOBAL");
        assert_eq!(group_scope(i32::MIN | 0x4), "DOMAIN LOCAL");
        assert_eq!(group_scope(i32::MIN | 0x8), "UNIVERSAL");
    }

    #[test]
    fn ad_intervals_are_human_readable_and_handle_minimum_value() {
        assert_eq!(format_ad_duration(-864_000_000_000), "1 days");
        assert!(!format_ad_duration(i64::MIN).is_empty());
    }

    #[test]
    fn search_matches_case_insensitively_across_fields() {
        assert!(matches_query("alice", ["CN=ALICE,DC=example", "Alice"]));
        assert!(!matches_query("bob", ["CN=ALICE,DC=example", "Alice"]));
    }
}
