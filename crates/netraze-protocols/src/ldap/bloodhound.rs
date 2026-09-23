//! BloodHound Community Edition collection over NetRaze's LDAP transport.
//!
//! RustHound-CE owns the CE object model and relationship parser. NetRaze owns
//! connection establishment, NTLM SASL protection, LDAP framing, paging, and
//! referral policy. This module is the narrow adapter between those layers.

use std::collections::HashMap;

use rusthound_ce::transport::ldap::LdapSearchEntry;

use super::controls::{security_descriptor_flags_control, show_deleted_control};
use super::{LdapClient, LdapEntry, LdapError};

const BLOODHOUND_ATTRIBUTES: &[&str] = &[
    "*",
    "nTSecurityDescriptor",
    "msDS-User-Account-Control-Computed",
];
const SCHEMA_ATTRIBUTES: &[&str] = &["objectClass", "name", "schemaIDGUID"];

/// Ordered LDAP records ready for the RustHound-CE parser.
///
/// Schema records precede the domain object because ACE parsing resolves
/// property GUIDs through the schema map and principal parsing needs the
/// domain SID before processing other objects.
#[doc(hidden)]
pub struct EntryCollection {
    pub entries: Vec<LdapSearchEntry>,
    pub referrals: Vec<String>,
    pub domain: String,
}

/// Collect the schema and default domain naming contexts in parser-safe order.
#[doc(hidden)]
pub async fn collect_entries(client: &mut LdapClient) -> Result<EntryCollection, LdapError> {
    let root = client.root_dse().await?;
    let default_context = required_root_attribute(&root, "defaultNamingContext")?;
    let schema_context = required_root_attribute(&root, "schemaNamingContext")?;
    let controls = [security_descriptor_flags_control(), show_deleted_control()];

    let schema = client
        .search_with_controls(
            &schema_context,
            "(|(objectClass=attributeSchema)(objectClass=classSchema))",
            SCHEMA_ATTRIBUTES,
            &controls,
        )
        .await?;
    let directory = client
        .search_with_controls(
            &default_context,
            "(objectClass=*)",
            BLOODHOUND_ATTRIBUTES,
            &controls,
        )
        .await?;

    let mut domain_entry = None;
    let mut remaining = Vec::with_capacity(directory.entries.len().saturating_sub(1));
    for entry in directory.entries {
        if domain_entry.is_none() && entry.dn.eq_ignore_ascii_case(&default_context) {
            domain_entry = Some(entry);
        } else {
            remaining.push(entry);
        }
    }
    let domain_entry = domain_entry.ok_or_else(|| {
        LdapError::UnexpectedOperation(format!(
            "BloodHound collection omitted the domain root {default_context}"
        ))
    })?;

    let mut entries = Vec::with_capacity(schema.entries.len() + remaining.len() + 1);
    entries.extend(schema.entries.into_iter().map(adapt_entry));
    entries.push(adapt_entry(domain_entry));
    entries.extend(remaining.into_iter().map(adapt_entry));

    let mut referrals = schema.referrals;
    referrals.extend(directory.referrals);
    referrals.sort();
    referrals.dedup();

    Ok(EntryCollection {
        entries,
        referrals,
        domain: domain_from_naming_context(&default_context)?,
    })
}

fn required_root_attribute(root: &LdapEntry, name: &str) -> Result<String, LdapError> {
    root.first_utf8(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| LdapError::UnexpectedOperation(format!("RootDSE omitted required {name}")))
}

fn domain_from_naming_context(context: &str) -> Result<String, LdapError> {
    let labels = context
        .split(',')
        .filter_map(|component| {
            let (kind, value) = component.trim().split_once('=')?;
            kind.eq_ignore_ascii_case("DC")
                .then(|| value.trim().to_owned())
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.is_empty() {
        return Err(LdapError::UnexpectedOperation(format!(
            "cannot derive a DNS domain from naming context {context}"
        )));
    }
    Ok(labels.join("."))
}

fn adapt_entry(entry: LdapEntry) -> LdapSearchEntry {
    let mut attrs = HashMap::new();
    let mut bin_attrs = HashMap::new();
    for (name, values) in entry.attributes {
        if is_binary_attribute(&name) {
            bin_attrs.insert(name, values);
            continue;
        }

        let mut text = Vec::with_capacity(values.len());
        let mut binary = Vec::new();
        for value in values {
            match String::from_utf8(value) {
                Ok(value) => text.push(value),
                Err(error) => binary.push(error.into_bytes()),
            }
        }
        if !text.is_empty() {
            attrs.insert(name.clone(), text);
        }
        if !binary.is_empty() {
            bin_attrs.insert(name, binary);
        }
    }
    LdapSearchEntry {
        dn: entry.dn,
        attrs,
        bin_attrs,
    }
}

fn is_binary_attribute(name: &str) -> bool {
    [
        "objectGUID",
        "objectSid",
        "nTSecurityDescriptor",
        "sIDHistory",
        "securityIdentifier",
        "schemaIDGUID",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-GroupMSAMembership",
        "userCertificate",
        "cACertificate",
    ]
    .iter()
    .any(|binary| name.eq_ignore_ascii_case(binary))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn derives_dns_domain_from_default_naming_context() {
        assert_eq!(
            domain_from_naming_context("DC=example,DC=test").unwrap(),
            "example.test"
        );
        assert!(domain_from_naming_context("CN=Configuration").is_err());
    }

    #[test]
    fn adapter_preserves_required_binary_attributes() {
        let entry = LdapEntry {
            dn: "CN=Alice,DC=example,DC=test".to_owned(),
            attributes: BTreeMap::from([
                ("sAMAccountName".to_owned(), vec![b"alice".to_vec()]),
                ("objectSid".to_owned(), vec![vec![1, 2, 3, 4]]),
                ("objectGUID".to_owned(), vec![b"valid utf8 bytes".to_vec()]),
            ]),
        };
        let adapted = adapt_entry(entry);
        assert_eq!(adapted.attrs["sAMAccountName"], ["alice"]);
        assert_eq!(adapted.bin_attrs["objectSid"], [vec![1, 2, 3, 4]]);
        assert_eq!(
            adapted.bin_attrs["objectGUID"],
            [b"valid utf8 bytes".to_vec()]
        );
    }

    #[test]
    fn invalid_unknown_values_remain_binary() {
        let entry = LdapEntry {
            dn: String::new(),
            attributes: BTreeMap::from([("custom".to_owned(), vec![vec![0xff, 0x00]])]),
        };
        let adapted = adapt_entry(entry);
        assert!(!adapted.attrs.contains_key("custom"));
        assert_eq!(adapted.bin_attrs["custom"], [vec![0xff, 0x00]]);
    }
}
