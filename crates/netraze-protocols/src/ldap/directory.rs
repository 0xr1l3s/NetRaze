//! Read-only Active Directory collectors built on the bounded LDAP client.

use netraze_core::{
    DirectoryComputer, DirectoryContainer, DirectoryDomain, DirectoryGroup, DirectoryInventory,
    DirectorySection, DirectoryServerInfo, DirectorySite, DirectorySubnet, DirectoryTopology,
    DirectoryTrust, DirectoryUser, GpoLink, GroupPolicy,
};

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
    let groups = collect_groups(client, &base).await;
    let computers = collect_computers(client, &base).await;
    let organization = collect_organization(client, &base).await;
    let topology = collect_topology(client, &server).await;
    DirectoryInventory {
        server,
        users,
        groups,
        computers,
        organization,
        topology,
        ..DirectoryInventory::default()
    }
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
}
