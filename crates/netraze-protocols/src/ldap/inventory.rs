//! High-level authenticated Active Directory inventory workflow.

use netraze_core::{DirectoryInventory, DirectoryServerInfo};

use crate::ntlm::NtlmCredential;

use super::{LdapClient, LdapClientConfig, LdapEntry, LdapError};

/// Connect, establish an NTLMv2 sign-and-seal context, discover RootDSE, and
/// close the LDAP session. Enumeration sections are populated by the focused
/// collectors in this module as they become available.
pub async fn inventory(
    config: LdapClientConfig,
    username: &str,
    domain: &str,
    credential: NtlmCredential,
) -> Result<DirectoryInventory, LdapError> {
    let endpoint = config.endpoint.clone();
    let mut client = LdapClient::connect(config).await?;
    if let Err(error) = client.bind_ntlm(username, domain, credential).await {
        let _ = client.unbind().await;
        return Err(error);
    }
    let result = client
        .root_dse()
        .await
        .and_then(|entry| server_info(endpoint, &entry))
        .map(|server| DirectoryInventory {
            server,
            ..DirectoryInventory::default()
        });
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
