//! Active Directory discovery and read-only user enumeration.

use netraze_core::{UserEnumerationSource, UserInfo};

use crate::{LdapClient, LdapEntry, LdapError};

const NORMAL_ACCOUNT_FILTER: &str = "(sAMAccountType=805306368)";
const ACCOUNT_DISABLED: u32 = 0x0000_0002;
const ACCOUNT_LOCKED: u32 = 0x0000_0010;

impl LdapClient {
    /// Discover the domain naming context through RootDSE and enumerate AD users.
    pub async fn enumerate_ad_users(&mut self) -> Result<Vec<UserInfo>, LdapError> {
        let root_dse = self.root_dse().await?;
        let naming_context = root_dse
            .first_utf8("defaultNamingContext")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                LdapError::UnexpectedOperation("RootDSE omitted defaultNamingContext".to_owned())
            })?
            .to_owned();
        let outcome = self
            .search(
                &naming_context,
                NORMAL_ACCOUNT_FILTER,
                &["sAMAccountName", "userAccountControl", "adminCount"],
            )
            .await?;
        let mut users = outcome
            .entries
            .iter()
            .filter_map(entry_to_user)
            .collect::<Vec<_>>();
        users.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(users)
    }
}

fn entry_to_user(entry: &LdapEntry) -> Option<UserInfo> {
    let name = entry.first_utf8("sAMAccountName")?.to_owned();
    let flags = parse_u32(entry.first_utf8("userAccountControl"));
    let admin = parse_u32(entry.first_utf8("adminCount")) == 1;
    Some(UserInfo {
        name,
        privilege_level: if admin { 2 } else { 1 },
        flags,
        disabled: flags & ACCOUNT_DISABLED != 0,
        locked: flags & ACCOUNT_LOCKED != 0,
        source: UserEnumerationSource::Ldap,
    })
}

fn parse_u32(value: Option<&str>) -> u32 {
    value.and_then(|text| text.parse().ok()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn maps_ad_account_flags_and_admin_count() {
        let entry = entry(
            "Alice",
            Some((ACCOUNT_DISABLED | ACCOUNT_LOCKED).to_string()),
            Some("1"),
        );
        let user = entry_to_user(&entry).unwrap();
        assert_eq!(user.name, "Alice");
        assert!(user.disabled);
        assert!(user.locked);
        assert_eq!(user.privilege_level, 2);
        assert_eq!(user.source, UserEnumerationSource::Ldap);
    }

    #[test]
    fn missing_optional_attributes_use_safe_defaults() {
        let user = entry_to_user(&entry("bob", None, None)).unwrap();
        assert_eq!(user.flags, 0);
        assert!(!user.disabled);
        assert!(!user.locked);
        assert_eq!(user.privilege_level, 1);
    }

    #[test]
    fn entries_without_account_names_are_ignored() {
        assert!(
            entry_to_user(&LdapEntry {
                dn: "CN=missing".into(),
                attributes: BTreeMap::new(),
            })
            .is_none()
        );
    }

    fn entry(name: &str, flags: Option<String>, admin_count: Option<&str>) -> LdapEntry {
        let mut attributes =
            BTreeMap::from([("sAMAccountName".to_owned(), vec![name.as_bytes().to_vec()])]);
        if let Some(flags) = flags {
            attributes.insert("userAccountControl".to_owned(), vec![flags.into_bytes()]);
        }
        if let Some(admin_count) = admin_count {
            attributes.insert(
                "adminCount".to_owned(),
                vec![admin_count.as_bytes().to_vec()],
            );
        }
        LdapEntry {
            dn: format!("CN={name},DC=example,DC=test"),
            attributes,
        }
    }
}
