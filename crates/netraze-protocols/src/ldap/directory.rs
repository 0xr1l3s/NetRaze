//! Read-only Active Directory collectors built on the bounded LDAP client.

use netraze_core::{
    DirectoryComputer, DirectoryContainer, DirectoryDomain, DirectoryGroup, DirectoryInventory,
    DirectoryPrincipalKind, DirectorySection, DirectorySecuritySettings, DirectoryServerInfo,
    DirectorySite, DirectorySubnet, DirectoryTopology, DirectoryTrust, DirectoryUser, GpoLink,
    GroupPolicy, PrivilegedPrincipal, ServicePrincipal,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::{LdapClient, LdapEntry, SearchOutcome};

const ACCOUNT_DISABLED: u32 = 0x0000_0002;
const ACCOUNT_LOCKED: u32 = 0x0000_0010;
const PASSWORD_NOT_REQUIRED: u32 = 0x0000_0020;
const PASSWORD_NEVER_EXPIRES: u32 = 0x0001_0000;
const TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x0100_0000;
const MAX_GPO_LINKS: usize = 4_096;
const MAX_GPO_LINK_LENGTH: usize = 1024 * 1024;

pub(super) async fn collect(
    client: &mut LdapClient,
    server: DirectoryServerInfo,
) -> DirectoryInventory {
    let base = server.default_naming_context.clone();
    let users = collect_users(client, &base).await;
    let mut groups = collect_groups(client, &base).await;
    let computers = collect_computers(client, &base).await;
    augment_group_members(&mut groups.items, &users.items, &computers.items);
    let organization = collect_organization(client, &base).await;
    let topology = collect_topology(client, &server).await;
    let privileged = analyze_privileged(&users, &groups, &computers);
    let services = collect_services(client, &base, &users.items, &computers.items).await;
    let security = collect_security(client, &server).await;
    DirectoryInventory {
        server,
        users,
        groups,
        computers,
        organization,
        topology,
        privileged,
        services,
        security,
    }
}

fn augment_group_members(
    groups: &mut [DirectoryGroup],
    users: &[DirectoryUser],
    computers: &[DirectoryComputer],
) {
    let group_dns = groups
        .iter()
        .enumerate()
        .map(|(index, group)| (group.dn.to_ascii_lowercase(), index))
        .collect::<HashMap<_, _>>();
    let mut reverse = Vec::new();
    for user in users {
        reverse.extend(
            user.member_of
                .iter()
                .map(|group| (group.to_ascii_lowercase(), user.dn.clone())),
        );
    }
    for computer in computers {
        reverse.extend(
            computer
                .member_of
                .iter()
                .map(|group| (group.to_ascii_lowercase(), computer.dn.clone())),
        );
    }
    for group in groups.iter() {
        reverse.extend(
            group
                .member_of
                .iter()
                .map(|parent| (parent.to_ascii_lowercase(), group.dn.clone())),
        );
    }
    for (group_dn, member_dn) in reverse {
        if let Some(index) = group_dns.get(&group_dn) {
            groups[*index].members.push(member_dn);
        }
    }
    for group in groups {
        group
            .members
            .sort_by(|left, right| compare_names(left, right));
        group
            .members
            .dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    }
}

fn analyze_privileged(
    users: &DirectorySection<DirectoryUser>,
    groups: &DirectorySection<DirectoryGroup>,
    computers: &DirectorySection<DirectoryComputer>,
) -> DirectorySection<PrivilegedPrincipal> {
    let group_by_dn = groups
        .items
        .iter()
        .map(|group| (group.dn.to_ascii_lowercase(), group))
        .collect::<HashMap<_, _>>();
    let privileged_groups = groups
        .items
        .iter()
        .filter(|group| {
            group.admin_count || group.object_sid.as_deref().is_some_and(privileged_sid)
        })
        .map(|group| group.dn.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut principals = Vec::new();

    for group in &groups.items {
        let mut reasons = BTreeSet::new();
        if group.admin_count {
            reasons.insert("adminCount=1 (AdminSDHolder-protected)".to_owned());
        }
        if let Some(sid) = group.object_sid.as_deref()
            && privileged_sid(sid)
        {
            reasons.insert(format!("well-known privileged group SID {sid}"));
        }
        reasons.extend(nested_privilege_reasons(
            &group.member_of,
            &group_by_dn,
            &privileged_groups,
        ));
        if !reasons.is_empty() {
            principals.push(PrivilegedPrincipal {
                dn: group.dn.clone(),
                name: group.name.clone(),
                kind: DirectoryPrincipalKind::Group,
                reasons: reasons.into_iter().collect(),
                member_of: group.member_of.clone(),
            });
        }
    }

    for user in &users.items {
        let mut reasons = BTreeSet::new();
        if user.admin_count {
            reasons.insert("adminCount=1 (AdminSDHolder-protected)".to_owned());
        }
        reasons.extend(nested_privilege_reasons(
            &user.member_of,
            &group_by_dn,
            &privileged_groups,
        ));
        if let Some(reason) = primary_group_reason(
            user.object_sid.as_deref(),
            user.primary_group_id,
            &groups.items,
        ) {
            reasons.insert(reason);
        }
        if !reasons.is_empty() {
            principals.push(PrivilegedPrincipal {
                dn: user.dn.clone(),
                name: user.name.clone(),
                kind: DirectoryPrincipalKind::User,
                reasons: reasons.into_iter().collect(),
                member_of: user.member_of.clone(),
            });
        }
    }

    for computer in &computers.items {
        let reasons =
            nested_privilege_reasons(&computer.member_of, &group_by_dn, &privileged_groups);
        if !reasons.is_empty() {
            principals.push(PrivilegedPrincipal {
                dn: computer.dn.clone(),
                name: computer.name.clone(),
                kind: DirectoryPrincipalKind::Computer,
                reasons,
                member_of: computer.member_of.clone(),
            });
        }
    }

    principals.sort_by(|left, right| compare_names(&left.name, &right.name));
    let errors = [&users.error, &groups.error, &computers.error]
        .into_iter()
        .filter_map(|error| error.as_deref())
        .collect::<Vec<_>>();
    DirectorySection {
        items: principals,
        referrals: Vec::new(),
        error: (!errors.is_empty()).then(|| {
            format!(
                "privilege analysis is partial because prerequisite inventory failed: {}",
                errors.join("; ")
            )
        }),
    }
}

fn nested_privilege_reasons(
    initial_groups: &[String],
    group_by_dn: &HashMap<String, &DirectoryGroup>,
    privileged_groups: &HashSet<String>,
) -> Vec<String> {
    let mut queue = initial_groups.iter().cloned().collect::<VecDeque<_>>();
    let mut visited = HashSet::new();
    let mut reasons = BTreeSet::new();
    while let Some(group_dn) = queue.pop_front() {
        let key = group_dn.to_ascii_lowercase();
        if !visited.insert(key.clone()) {
            continue;
        }
        if privileged_groups.contains(&key) {
            let group_name = group_by_dn
                .get(&key)
                .map_or(group_dn.as_str(), |group| group.name.as_str());
            reasons.insert(format!("direct or nested member of {group_name}"));
        }
        if let Some(group) = group_by_dn.get(&key) {
            queue.extend(group.member_of.iter().cloned());
        }
    }
    reasons.into_iter().collect()
}

fn primary_group_reason(
    object_sid: Option<&str>,
    primary_group_id: Option<u32>,
    groups: &[DirectoryGroup],
) -> Option<String> {
    let object_sid = object_sid?;
    let primary_group_id = primary_group_id?;
    let domain_sid = object_sid.rsplit_once('-')?.0;
    let primary_sid = format!("{domain_sid}-{primary_group_id}");
    let group = groups.iter().find(|group| {
        group
            .object_sid
            .as_deref()
            .is_some_and(|sid| sid.eq_ignore_ascii_case(&primary_sid))
    })?;
    privileged_sid(&primary_sid).then(|| format!("primary group is {}", group.name))
}

fn privileged_sid(sid: &str) -> bool {
    const BUILTIN: [&str; 6] = [
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-32-552",
    ];
    BUILTIN
        .iter()
        .any(|candidate| sid.eq_ignore_ascii_case(candidate))
        || sid
            .rsplit_once('-')
            .and_then(|(_, rid)| rid.parse::<u32>().ok())
            .is_some_and(|rid| matches!(rid, 512 | 518 | 519 | 520))
}

async fn collect_services(
    client: &mut LdapClient,
    base: &str,
    users: &[DirectoryUser],
    computers: &[DirectoryComputer],
) -> DirectorySection<ServicePrincipal> {
    let mut items = users
        .iter()
        .filter(|user| !user.service_principal_names.is_empty())
        .map(|user| ServicePrincipal {
            dn: user.dn.clone(),
            name: user.name.clone(),
            kind: DirectoryPrincipalKind::User,
            dns_host_name: None,
            service_principal_names: user.service_principal_names.clone(),
            supported_encryption_types: user.supported_encryption_types,
        })
        .chain(
            computers
                .iter()
                .filter(|computer| !computer.service_principal_names.is_empty())
                .map(|computer| ServicePrincipal {
                    dn: computer.dn.clone(),
                    name: computer.name.clone(),
                    kind: DirectoryPrincipalKind::Computer,
                    dns_host_name: computer.dns_host_name.clone(),
                    service_principal_names: computer.service_principal_names.clone(),
                    supported_encryption_types: computer.supported_encryption_types,
                }),
        )
        .collect::<Vec<_>>();
    let result = client
        .search(
            base,
            "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))",
            &[
                "objectClass",
                "sAMAccountName",
                "dNSHostName",
                "servicePrincipalName",
                "msDS-SupportedEncryptionTypes",
            ],
        )
        .await;
    let (referrals, error) = match result {
        Ok(outcome) => {
            items.extend(outcome.entries.iter().filter_map(service_from_entry));
            (outcome.referrals, None)
        }
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    items.sort_by(|left, right| compare_names(&left.name, &right.name));
    items.dedup_by(|left, right| left.dn.eq_ignore_ascii_case(&right.dn));
    DirectorySection {
        items,
        referrals,
        error,
    }
}

fn service_from_entry(entry: &LdapEntry) -> Option<ServicePrincipal> {
    Some(ServicePrincipal {
        dn: entry.dn.clone(),
        name: text(entry, "sAMAccountName")?,
        kind: DirectoryPrincipalKind::ManagedServiceAccount,
        dns_host_name: text(entry, "dNSHostName"),
        service_principal_names: texts(entry, "servicePrincipalName"),
        supported_encryption_types: number(entry, "msDS-SupportedEncryptionTypes"),
    })
}

async fn collect_security(
    client: &mut LdapClient,
    server: &DirectoryServerInfo,
) -> DirectorySection<DirectorySecuritySettings> {
    let mut settings = DirectorySecuritySettings {
        session_signing: true,
        session_sealing: true,
        ..DirectorySecuritySettings::default()
    };
    let mut referrals = Vec::new();
    let mut errors = Vec::new();
    match client
        .search_base(
            &server.default_naming_context,
            "(objectClass=domainDNS)",
            &[
                "minPwdLength",
                "pwdHistoryLength",
                "minPwdAge",
                "maxPwdAge",
                "pwdProperties",
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
                "ms-DS-MachineAccountQuota",
                "msDS-Behavior-Version",
            ],
        )
        .await
    {
        Ok(outcome) => {
            referrals.extend(outcome.referrals);
            if let Some(entry) = outcome.entries.first() {
                settings.minimum_password_length = number(entry, "minPwdLength");
                settings.password_history_length = number(entry, "pwdHistoryLength");
                settings.minimum_password_age_100ns = signed_i64(entry, "minPwdAge");
                settings.maximum_password_age_100ns = signed_i64(entry, "maxPwdAge");
                settings.password_properties = number(entry, "pwdProperties");
                settings.lockout_threshold = number(entry, "lockoutThreshold");
                settings.lockout_duration_100ns = signed_i64(entry, "lockoutDuration");
                settings.lockout_observation_window_100ns =
                    signed_i64(entry, "lockOutObservationWindow");
                settings.machine_account_quota = number(entry, "ms-DS-MachineAccountQuota");
                settings.domain_behavior_version = number(entry, "msDS-Behavior-Version");
            } else {
                errors.push("domain policy search returned no entry".to_owned());
            }
        }
        Err(error) => errors.push(error.to_string()),
    }

    let policy_dn = query_policy_dn(client, server).await;
    if let Some(policy_dn) = policy_dn {
        match client
            .search_base(
                &policy_dn,
                "(objectClass=queryPolicy)",
                &["lDAPAdminLimits"],
            )
            .await
        {
            Ok(outcome) => {
                referrals.extend(outcome.referrals);
                if let Some(entry) = outcome.entries.first() {
                    settings.ldap_admin_limits = parse_admin_limits(entry);
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }

    referrals.sort();
    referrals.dedup();
    DirectorySection {
        items: vec![settings],
        referrals,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

async fn query_policy_dn(client: &mut LdapClient, server: &DirectoryServerInfo) -> Option<String> {
    if let Some(service_name) = &server.service_name
        && let Ok(outcome) = client
            .search_base(
                service_name,
                "(objectClass=nTDSDSA)",
                &["queryPolicyObject"],
            )
            .await
        && let Some(policy) = outcome
            .entries
            .first()
            .and_then(|entry| text(entry, "queryPolicyObject"))
    {
        return Some(policy);
    }
    server.configuration_naming_context.as_ref().map(|configuration| {
        format!(
            "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,{configuration}"
        )
    })
}

fn parse_admin_limits(entry: &LdapEntry) -> BTreeMap<String, String> {
    texts(entry, "lDAPAdminLimits")
        .into_iter()
        .filter_map(|value| {
            let (name, value) = value.split_once('=')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

async fn collect_users(client: &mut LdapClient, base: &str) -> DirectorySection<DirectoryUser> {
    match client
        .search(
            base,
            "(sAMAccountType=805306368)",
            &[
                "sAMAccountName",
                "displayName",
                "userPrincipalName",
                "description",
                "objectSid",
                "memberOf",
                "primaryGroupID",
                "userAccountControl",
                "adminCount",
                "lastLogonTimestamp",
                "pwdLastSet",
                "whenCreated",
                "servicePrincipalName",
                "msDS-SupportedEncryptionTypes",
            ],
        )
        .await
    {
        Ok(outcome) => map_section(outcome, user_from_entry, |left, right| {
            compare_names(&left.name, &right.name)
        }),
        Err(error) => DirectorySection::failed(error.to_string()),
    }
}

async fn collect_groups(client: &mut LdapClient, base: &str) -> DirectorySection<DirectoryGroup> {
    match client
        .search(
            base,
            "(objectCategory=group)",
            &[
                "sAMAccountName",
                "cn",
                "description",
                "objectSid",
                "groupType",
                "member",
                "memberOf",
                "adminCount",
            ],
        )
        .await
    {
        Ok(outcome) => map_section(outcome, group_from_entry, |left, right| {
            compare_names(&left.name, &right.name)
        }),
        Err(error) => DirectorySection::failed(error.to_string()),
    }
}

async fn collect_computers(
    client: &mut LdapClient,
    base: &str,
) -> DirectorySection<DirectoryComputer> {
    match client
        .search(
            base,
            "(sAMAccountType=805306369)",
            &[
                "sAMAccountName",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "description",
                "objectSid",
                "memberOf",
                "primaryGroupID",
                "userAccountControl",
                "lastLogonTimestamp",
                "pwdLastSet",
                "servicePrincipalName",
                "msDS-SupportedEncryptionTypes",
            ],
        )
        .await
    {
        Ok(outcome) => map_section(outcome, computer_from_entry, |left, right| {
            compare_names(&left.name, &right.name)
        }),
        Err(error) => DirectorySection::failed(error.to_string()),
    }
}

async fn collect_organization(
    client: &mut LdapClient,
    base: &str,
) -> DirectorySection<DirectoryContainer> {
    match client
        .search(
            base,
            "(|(objectClass=organizationalUnit)(objectClass=container))",
            &[
                "objectClass",
                "ou",
                "cn",
                "name",
                "description",
                "gPLink",
                "gPOptions",
                "whenCreated",
            ],
        )
        .await
    {
        Ok(outcome) => map_section(outcome, container_from_entry, |left, right| {
            compare_names(&left.dn, &right.dn)
        }),
        Err(error) => DirectorySection::failed(error.to_string()),
    }
}

async fn collect_topology(
    client: &mut LdapClient,
    server: &DirectoryServerInfo,
) -> DirectorySection<DirectoryTopology> {
    let mut topology = DirectoryTopology::default();
    let mut referrals = Vec::new();
    let mut errors = Vec::new();
    let base = &server.default_naming_context;

    absorb(
        client
            .search(base, "(objectClass=domainDNS)", &["objectSid", "gPLink"])
            .await,
        &mut referrals,
        &mut errors,
        |entries| {
            topology
                .domains
                .extend(entries.iter().map(domain_object_from_entry));
        },
    );

    absorb(
        client
            .search(
                base,
                "(objectClass=trustedDomain)",
                &[
                    "trustPartner",
                    "flatName",
                    "trustDirection",
                    "trustType",
                    "trustAttributes",
                    "securityIdentifier",
                ],
            )
            .await,
        &mut referrals,
        &mut errors,
        |entries| topology.trusts.extend(entries.iter().map(trust_from_entry)),
    );

    if let Some(configuration) = &server.configuration_naming_context {
        absorb(
            client
                .search(
                    configuration,
                    "(&(objectClass=crossRef)(dnsRoot=*))",
                    &["dnsRoot", "nETBIOSName", "nCName"],
                )
                .await,
            &mut referrals,
            &mut errors,
            |entries| merge_cross_references(&mut topology.domains, entries),
        );
        let sites_base = format!("CN=Sites,{configuration}");
        absorb(
            client
                .search(
                    &sites_base,
                    "(objectClass=site)",
                    &["cn", "name", "description", "location"],
                )
                .await,
            &mut referrals,
            &mut errors,
            |entries| topology.sites.extend(entries.iter().map(site_from_entry)),
        );
        absorb(
            client
                .search(
                    &sites_base,
                    "(objectClass=subnet)",
                    &["cn", "name", "siteObject", "description", "location"],
                )
                .await,
            &mut referrals,
            &mut errors,
            |entries| {
                topology
                    .subnets
                    .extend(entries.iter().map(subnet_from_entry));
            },
        );
    }

    absorb(
        client
            .search(
                base,
                "(objectClass=groupPolicyContainer)",
                &[
                    "name",
                    "displayName",
                    "gPCFileSysPath",
                    "flags",
                    "versionNumber",
                ],
            )
            .await,
        &mut referrals,
        &mut errors,
        |entries| {
            topology
                .group_policies
                .extend(entries.iter().map(gpo_from_entry));
        },
    );

    topology
        .domains
        .sort_by(|left, right| compare_names(&left.dn, &right.dn));
    topology
        .trusts
        .sort_by(|left, right| compare_names(&left.partner, &right.partner));
    topology
        .sites
        .sort_by(|left, right| compare_names(&left.name, &right.name));
    topology
        .subnets
        .sort_by(|left, right| compare_names(&left.name, &right.name));
    topology
        .group_policies
        .sort_by(|left, right| compare_names(&left.id, &right.id));
    referrals.sort();
    referrals.dedup();
    DirectorySection {
        items: vec![topology],
        referrals,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn user_from_entry(entry: &LdapEntry) -> Option<DirectoryUser> {
    let name = text(entry, "sAMAccountName")?;
    let flags = number(entry, "userAccountControl").unwrap_or_default();
    Some(DirectoryUser {
        dn: entry.dn.clone(),
        name,
        display_name: text(entry, "displayName"),
        user_principal_name: text(entry, "userPrincipalName"),
        description: text(entry, "description"),
        object_sid: sid(entry, "objectSid"),
        member_of: texts(entry, "memberOf"),
        primary_group_id: number(entry, "primaryGroupID"),
        user_account_control: flags,
        admin_count: number(entry, "adminCount") == Some(1),
        disabled: flags & ACCOUNT_DISABLED != 0,
        locked: flags & ACCOUNT_LOCKED != 0,
        password_never_expires: flags & PASSWORD_NEVER_EXPIRES != 0,
        password_not_required: flags & PASSWORD_NOT_REQUIRED != 0,
        trusted_for_delegation: flags & TRUSTED_FOR_DELEGATION != 0,
        last_logon_timestamp: text(entry, "lastLogonTimestamp"),
        password_last_set: text(entry, "pwdLastSet"),
        when_created: text(entry, "whenCreated"),
        service_principal_names: texts(entry, "servicePrincipalName"),
        supported_encryption_types: number(entry, "msDS-SupportedEncryptionTypes"),
    })
}

fn group_from_entry(entry: &LdapEntry) -> Option<DirectoryGroup> {
    Some(DirectoryGroup {
        dn: entry.dn.clone(),
        name: text(entry, "sAMAccountName").or_else(|| text(entry, "cn"))?,
        description: text(entry, "description"),
        object_sid: sid(entry, "objectSid"),
        group_type: signed_number(entry, "groupType").unwrap_or_default(),
        members: texts_with_range(entry, "member"),
        member_of: texts(entry, "memberOf"),
        admin_count: number(entry, "adminCount") == Some(1),
    })
}

fn computer_from_entry(entry: &LdapEntry) -> Option<DirectoryComputer> {
    let flags = number(entry, "userAccountControl").unwrap_or_default();
    Some(DirectoryComputer {
        dn: entry.dn.clone(),
        name: text(entry, "sAMAccountName")?,
        dns_host_name: text(entry, "dNSHostName"),
        operating_system: text(entry, "operatingSystem"),
        operating_system_version: text(entry, "operatingSystemVersion"),
        description: text(entry, "description"),
        object_sid: sid(entry, "objectSid"),
        member_of: texts(entry, "memberOf"),
        primary_group_id: number(entry, "primaryGroupID"),
        user_account_control: flags,
        disabled: flags & ACCOUNT_DISABLED != 0,
        trusted_for_delegation: flags & TRUSTED_FOR_DELEGATION != 0,
        trusted_to_auth_for_delegation: flags & TRUSTED_TO_AUTH_FOR_DELEGATION != 0,
        last_logon_timestamp: text(entry, "lastLogonTimestamp"),
        password_last_set: text(entry, "pwdLastSet"),
        service_principal_names: texts(entry, "servicePrincipalName"),
        supported_encryption_types: number(entry, "msDS-SupportedEncryptionTypes"),
    })
}

fn container_from_entry(entry: &LdapEntry) -> Option<DirectoryContainer> {
    let classes = texts(entry, "objectClass");
    let is_organizational_unit = classes
        .iter()
        .any(|class| class.eq_ignore_ascii_case("organizationalUnit"));
    Some(DirectoryContainer {
        dn: entry.dn.clone(),
        name: text(entry, "ou")
            .or_else(|| text(entry, "cn"))
            .or_else(|| text(entry, "name"))?,
        parent_dn: parent_dn(&entry.dn),
        description: text(entry, "description"),
        is_organizational_unit,
        gpo_links: text(entry, "gPLink").map_or_else(Vec::new, |value| parse_gpo_links(&value)),
        gpo_options: number(entry, "gPOptions"),
        when_created: text(entry, "whenCreated"),
    })
}

fn domain_object_from_entry(entry: &LdapEntry) -> DirectoryDomain {
    DirectoryDomain {
        dn: entry.dn.clone(),
        naming_context: Some(entry.dn.clone()),
        object_sid: sid(entry, "objectSid"),
        gpo_links: text(entry, "gPLink").map_or_else(Vec::new, |value| parse_gpo_links(&value)),
        ..DirectoryDomain::default()
    }
}

fn merge_cross_references(domains: &mut Vec<DirectoryDomain>, entries: &[LdapEntry]) {
    for entry in entries {
        let naming_context = text(entry, "nCName");
        let existing = naming_context.as_ref().and_then(|context| {
            domains
                .iter_mut()
                .find(|domain| domain.dn.eq_ignore_ascii_case(context))
        });
        if let Some(domain) = existing {
            domain.dns_root = text(entry, "dnsRoot");
            domain.netbios_name = text(entry, "nETBIOSName");
            domain.naming_context = naming_context;
        } else {
            domains.push(DirectoryDomain {
                dn: naming_context.clone().unwrap_or_else(|| entry.dn.clone()),
                dns_root: text(entry, "dnsRoot"),
                netbios_name: text(entry, "nETBIOSName"),
                naming_context,
                ..DirectoryDomain::default()
            });
        }
    }
}

fn trust_from_entry(entry: &LdapEntry) -> DirectoryTrust {
    DirectoryTrust {
        dn: entry.dn.clone(),
        partner: text(entry, "trustPartner").unwrap_or_else(|| entry.dn.clone()),
        flat_name: text(entry, "flatName"),
        direction: number(entry, "trustDirection"),
        trust_type: number(entry, "trustType"),
        attributes: number(entry, "trustAttributes"),
        security_identifier: sid(entry, "securityIdentifier"),
    }
}

fn site_from_entry(entry: &LdapEntry) -> DirectorySite {
    DirectorySite {
        dn: entry.dn.clone(),
        name: text(entry, "cn")
            .or_else(|| text(entry, "name"))
            .unwrap_or_else(|| entry.dn.clone()),
        description: text(entry, "description"),
        location: text(entry, "location"),
    }
}

fn subnet_from_entry(entry: &LdapEntry) -> DirectorySubnet {
    DirectorySubnet {
        dn: entry.dn.clone(),
        name: text(entry, "cn")
            .or_else(|| text(entry, "name"))
            .unwrap_or_else(|| entry.dn.clone()),
        site_dn: text(entry, "siteObject"),
        description: text(entry, "description"),
        location: text(entry, "location"),
    }
}

fn gpo_from_entry(entry: &LdapEntry) -> GroupPolicy {
    GroupPolicy {
        dn: entry.dn.clone(),
        id: text(entry, "name").unwrap_or_else(|| entry.dn.clone()),
        display_name: text(entry, "displayName"),
        file_system_path: text(entry, "gPCFileSysPath"),
        flags: number(entry, "flags"),
        version_number: number(entry, "versionNumber"),
    }
}

fn map_section<T, F, S>(outcome: SearchOutcome, mapper: F, sorter: S) -> DirectorySection<T>
where
    F: Fn(&LdapEntry) -> Option<T>,
    S: FnMut(&T, &T) -> std::cmp::Ordering,
{
    let mut items = outcome
        .entries
        .iter()
        .filter_map(mapper)
        .collect::<Vec<_>>();
    items.sort_by(sorter);
    DirectorySection::success(items, outcome.referrals)
}

fn absorb<F>(
    result: Result<SearchOutcome, super::LdapError>,
    referrals: &mut Vec<String>,
    errors: &mut Vec<String>,
    mut consume: F,
) where
    F: FnMut(&[LdapEntry]),
{
    match result {
        Ok(outcome) => {
            referrals.extend(outcome.referrals);
            consume(&outcome.entries);
        }
        Err(error) => errors.push(error.to_string()),
    }
}

fn text(entry: &LdapEntry, attribute: &str) -> Option<String> {
    entry.first_utf8(attribute).map(str::to_owned)
}

fn texts(entry: &LdapEntry, attribute: &str) -> Vec<String> {
    entry
        .values(attribute)
        .into_iter()
        .flatten()
        .filter_map(|value| std::str::from_utf8(value).ok().map(str::to_owned))
        .collect()
}

fn texts_with_range(entry: &LdapEntry, attribute: &str) -> Vec<String> {
    let mut values = Vec::new();
    for (name, attribute_values) in &entry.attributes {
        if name.eq_ignore_ascii_case(attribute)
            || name
                .to_ascii_lowercase()
                .starts_with(&format!("{};range=", attribute.to_ascii_lowercase()))
        {
            values.extend(
                attribute_values
                    .iter()
                    .filter_map(|value| std::str::from_utf8(value).ok().map(str::to_owned)),
            );
        }
    }
    values
}

fn number(entry: &LdapEntry, attribute: &str) -> Option<u32> {
    entry.first_utf8(attribute)?.parse().ok()
}

fn signed_number(entry: &LdapEntry, attribute: &str) -> Option<i32> {
    entry.first_utf8(attribute)?.parse().ok()
}

fn signed_i64(entry: &LdapEntry, attribute: &str) -> Option<i64> {
    entry.first_utf8(attribute)?.parse().ok()
}

fn sid(entry: &LdapEntry, attribute: &str) -> Option<String> {
    parse_sid(entry.values(attribute)?.first()?)
}

fn parse_sid(value: &[u8]) -> Option<String> {
    if value.len() < 8 {
        return None;
    }
    let count = usize::from(value[1]);
    let required = 8_usize.checked_add(count.checked_mul(4)?)?;
    if value.len() < required {
        return None;
    }
    let authority = value[2..8].iter().fold(0_u64, |accumulator, byte| {
        (accumulator << 8) | u64::from(*byte)
    });
    let mut result = format!("S-{}-{authority}", value[0]);
    for index in 0..count {
        let offset = 8 + index * 4;
        let sub_authority = u32::from_le_bytes(value[offset..offset + 4].try_into().ok()?);
        result.push_str(&format!("-{sub_authority}"));
    }
    Some(result)
}

fn parent_dn(dn: &str) -> Option<String> {
    let mut escaped = false;
    for (index, character) in dn.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ',' {
            return Some(dn[index + character.len_utf8()..].trim_start().to_owned());
        }
    }
    None
}

fn parse_gpo_links(value: &str) -> Vec<GpoLink> {
    if value.len() > MAX_GPO_LINK_LENGTH {
        return Vec::new();
    }
    let mut links = Vec::new();
    let mut rest = value;
    while links.len() < MAX_GPO_LINKS {
        let Some(open) = rest.find('[') else {
            break;
        };
        let Some(close_relative) = rest[open + 1..].find(']') else {
            break;
        };
        let close = open + 1 + close_relative;
        let body = &rest[open + 1..close];
        if let Some((target, flags)) = body.rsplit_once(';')
            && let Ok(flags) = flags.parse::<u32>()
        {
            let target_dn = target
                .strip_prefix("LDAP://")
                .or_else(|| target.strip_prefix("ldap://"))
                .unwrap_or(target)
                .to_owned();
            links.push(GpoLink {
                target_dn,
                disabled: flags & 1 != 0,
                enforced: flags & 2 != 0,
            });
        }
        rest = &rest[close + 1..];
    }
    links
}

fn compare_names(left: &str, right: &str) -> std::cmp::Ordering {
    left.to_ascii_lowercase()
        .cmp(&right.to_ascii_lowercase())
        .then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn parses_binary_sid_with_little_endian_subauthorities() {
        let sid = [
            1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0,
        ];
        assert_eq!(parse_sid(&sid).as_deref(), Some("S-1-5-21-1-2-512"));
        assert!(parse_sid(&sid[..7]).is_none());
    }

    #[test]
    fn parent_dn_preserves_escaped_commas() {
        assert_eq!(
            parent_dn(r"OU=Blue\, Team,DC=example,DC=test").as_deref(),
            Some("DC=example,DC=test")
        );
    }

    #[test]
    fn parses_bounded_gpo_links_and_flags() {
        let links = parse_gpo_links(
            "[LDAP://CN={ONE},CN=Policies,CN=System,DC=example,DC=test;0]\
             [LDAP://CN={TWO},CN=Policies,CN=System,DC=example,DC=test;3]",
        );
        assert_eq!(links.len(), 2);
        assert!(!links[0].disabled);
        assert!(!links[0].enforced);
        assert!(links[1].disabled);
        assert!(links[1].enforced);
    }

    #[test]
    fn maps_user_flags_and_binary_attributes() {
        let entry = LdapEntry {
            dn: "CN=Alice,DC=example,DC=test".to_owned(),
            attributes: BTreeMap::from([
                ("sAMAccountName".to_owned(), vec![b"alice".to_vec()]),
                (
                    "userAccountControl".to_owned(),
                    vec![
                        (ACCOUNT_DISABLED | PASSWORD_NEVER_EXPIRES)
                            .to_string()
                            .into_bytes(),
                    ],
                ),
                (
                    "servicePrincipalName".to_owned(),
                    vec![b"HTTP/web.example.test".to_vec()],
                ),
            ]),
        };
        let user = user_from_entry(&entry).unwrap();
        assert!(user.disabled);
        assert!(user.password_never_expires);
        assert_eq!(user.service_principal_names, ["HTTP/web.example.test"]);
    }

    #[test]
    fn privilege_analysis_walks_nested_groups() {
        let domain_admins = DirectoryGroup {
            dn: "CN=Domain Admins,DC=example,DC=test".to_owned(),
            name: "Domain Admins".to_owned(),
            object_sid: Some("S-1-5-21-1-2-3-512".to_owned()),
            ..DirectoryGroup::default()
        };
        let helpdesk = DirectoryGroup {
            dn: "CN=Helpdesk,DC=example,DC=test".to_owned(),
            name: "Helpdesk".to_owned(),
            member_of: vec![domain_admins.dn.clone()],
            ..DirectoryGroup::default()
        };
        let user = DirectoryUser {
            dn: "CN=Alice,DC=example,DC=test".to_owned(),
            name: "alice".to_owned(),
            member_of: vec![helpdesk.dn.clone()],
            ..DirectoryUser::default()
        };
        let privileged = analyze_privileged(
            &DirectorySection::success(vec![user], Vec::new()),
            &DirectorySection::success(vec![domain_admins, helpdesk], Vec::new()),
            &DirectorySection::default(),
        );
        let alice = privileged
            .items
            .iter()
            .find(|principal| principal.name == "alice")
            .unwrap();
        assert!(
            alice
                .reasons
                .iter()
                .any(|reason| reason.contains("Domain Admins"))
        );
    }

    #[test]
    fn parses_query_policy_limits_without_guessing_unknown_values() {
        let entry = LdapEntry {
            dn: "CN=Default Query Policy".to_owned(),
            attributes: BTreeMap::from([(
                "lDAPAdminLimits".to_owned(),
                vec![b"MaxPageSize=1000".to_vec(), b"MaxValRange=1500".to_vec()],
            )]),
        };
        let limits = parse_admin_limits(&entry);
        assert_eq!(limits.get("MaxPageSize").map(String::as_str), Some("1000"));
        assert_eq!(limits.get("MaxValRange").map(String::as_str), Some("1500"));
    }
}
