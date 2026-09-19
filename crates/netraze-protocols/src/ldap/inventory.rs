//! High-level Active Directory inventory workflow.

use netraze_core::{DirectoryInventory, DirectoryServerInfo};

use crate::ntlm::NtlmCredential;

use super::{LdapClient, LdapClientConfig, LdapEntry, LdapError};

/// Authentication choices for a read-only LDAP inventory.
#[derive(Debug, Clone)]
pub enum LdapAuthentication {
    Anonymous,
    Ntlm {
        username: String,
        domain: String,
        credential: NtlmCredential,
    },
}

/// Connect, bind, discover RootDSE, collect read-only inventory, and unbind.
pub async fn inventory(
    config: LdapClientConfig,
    username: &str,
    domain: &str,
    credential: NtlmCredential,
) -> Result<DirectoryInventory, LdapError> {
    inventory_with_authentication(
        config,
        LdapAuthentication::Ntlm {
            username: username.to_owned(),
            domain: domain.to_owned(),
            credential,
        },
    )
    .await
}

/// Anonymous bind sends an empty name and empty password; it does not request
/// the server's Guest account or establish NTLM sign-and-seal protection.
pub async fn inventory_anonymous(
    config: LdapClientConfig,
) -> Result<DirectoryInventory, LdapError> {
    inventory_with_authentication(config, LdapAuthentication::Anonymous).await
}

pub async fn inventory_with_authentication(
    config: LdapClientConfig,
    authentication: LdapAuthentication,
) -> Result<DirectoryInventory, LdapError> {
    let endpoint = config.endpoint.clone();
    let mut client = LdapClient::connect(config).await?;
    let bind_result = match authentication {
        LdapAuthentication::Anonymous => client.bind_anonymous().await,
        LdapAuthentication::Ntlm {
            username,
            domain,
            credential,
        } => client.bind_ntlm(&username, &domain, credential).await,
    };
    if let Err(error) = bind_result {
        let _ = client.unbind().await;
        return Err(error);
    }
    let result = match client.root_dse().await {
        Ok(entry) => match server_info(endpoint, &entry) {
            Ok(server) => Ok(super::directory::collect(&mut client, server).await),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let _ = client.unbind().await;
    result
}

fn server_info(endpoint: String, entry: &LdapEntry) -> Result<DirectoryServerInfo, LdapError> {
    let default_naming_context = entry
        .first_utf8("defaultNamingContext")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            LdapError::UnexpectedOperation("RootDSE omitted defaultNamingContext".to_owned())
        })?
        .to_owned();
    Ok(DirectoryServerInfo {
        endpoint,
        dns_host_name: text(entry, "dnsHostName"),
        server_name: text(entry, "serverName"),
        service_name: text(entry, "dsServiceName"),
        default_naming_context,
        root_domain_naming_context: text(entry, "rootDomainNamingContext"),
        configuration_naming_context: text(entry, "configurationNamingContext"),
        schema_naming_context: text(entry, "schemaNamingContext"),
        naming_contexts: texts(entry, "namingContexts"),
        supported_ldap_versions: texts(entry, "supportedLDAPVersion"),
        supported_sasl_mechanisms: texts(entry, "supportedSASLMechanisms"),
        supported_controls: texts(entry, "supportedControl"),
        supported_extensions: texts(entry, "supportedExtension"),
        supported_capabilities: texts(entry, "supportedCapabilities"),
        domain_controller_functionality: number(entry, "domainControllerFunctionality"),
        domain_functionality: number(entry, "domainFunctionality"),
        forest_functionality: number(entry, "forestFunctionality"),
        global_catalog_ready: boolean(entry, "isGlobalCatalogReady"),
        synchronized: boolean(entry, "isSynchronized"),
    })
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

fn number(entry: &LdapEntry, attribute: &str) -> Option<u32> {
    entry.first_utf8(attribute)?.parse().ok()
}

fn boolean(entry: &LdapEntry, attribute: &str) -> Option<bool> {
    match entry.first_utf8(attribute)?.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn maps_root_dse_without_exposing_wire_types() {
        let entry = LdapEntry {
            dn: String::new(),
            attributes: BTreeMap::from([
                (
                    "defaultNamingContext".to_owned(),
                    vec![b"DC=example,DC=test".to_vec()],
                ),
                ("dnsHostName".to_owned(), vec![b"dc.example.test".to_vec()]),
                ("supportedLDAPVersion".to_owned(), vec![b"3".to_vec()]),
                ("isSynchronized".to_owned(), vec![b"TRUE".to_vec()]),
            ]),
        };
        let info = server_info("dc.example.test:389".to_owned(), &entry).unwrap();
        assert_eq!(info.default_naming_context, "DC=example,DC=test");
        assert_eq!(info.dns_host_name.as_deref(), Some("dc.example.test"));
        assert_eq!(info.supported_ldap_versions, ["3"]);
        assert_eq!(info.synchronized, Some(true));
    }
}
