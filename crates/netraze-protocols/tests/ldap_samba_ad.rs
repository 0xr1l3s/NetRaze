use netraze_core::UserEnumerationSource;
use netraze_protocols::{
    ldap::{self, LdapClient, LdapClientConfig},
    ntlm::{NtlmCredential, nt_hash_from_password},
};

const LDAP_ENDPOINT: &str = "127.0.0.1:1389";
const TEST_DOMAIN: &str = "NETRAZE";
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "[REMOVED_TEST_PASSWORD]";

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn password_bind_discovers_root_dse_and_enumerates_users() {
    let mut client = connect(NtlmCredential::Password(TEST_PASSWORD.into()), 1000).await;

    let root_dse = client.root_dse().await.expect("RootDSE search failed");
    assert_eq!(
        root_dse.first_utf8("defaultNamingContext"),
        Some("DC=netraze,DC=test")
    );

    let users = client
        .enumerate_ad_users()
        .await
        .expect("AD user enumeration failed");
    let alice = users
        .iter()
        .find(|user| user.name.eq_ignore_ascii_case(TEST_USER))
        .expect("the provisioned alice account was not returned");
    assert_eq!(alice.source, UserEnumerationSource::Ldap);
    assert!(!alice.disabled);
    assert!(!alice.locked);

    client.unbind().await.expect("LDAP unbind failed");
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn nt_hash_bind_enumerates_multiple_pages_in_stable_order() {
    let hash = nt_hash_from_password(TEST_PASSWORD);
    let mut client = connect(NtlmCredential::NtHash(hash), 2).await;

    let users = client
        .enumerate_ad_users()
        .await
        .expect("paged AD user enumeration failed");
    assert!(users.len() > 2, "fixture must require more than one page");
    for expected in ["alice", "bob", "carol"] {
        assert!(
            users
                .iter()
                .any(|user| user.name.eq_ignore_ascii_case(expected)),
            "missing provisioned account {expected}"
        );
    }
    assert!(
        users
            .windows(2)
            .all(|pair| { pair[0].name.to_ascii_lowercase() <= pair[1].name.to_ascii_lowercase() })
    );

    client.unbind().await.expect("LDAP unbind failed");
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn full_inventory_covers_directory_structure_and_security_sections() {
    let mut config = LdapClientConfig::new(LDAP_ENDPOINT);
    config.page_size = 2;
    let inventory = ldap::inventory(
        config,
        TEST_USER,
        TEST_DOMAIN,
        NtlmCredential::Password(TEST_PASSWORD.into()),
    )
    .await
    .expect("full local AD inventory failed");

    assert_eq!(
        inventory.server.default_naming_context,
        "DC=netraze,DC=test"
    );
    assert!(
        inventory
            .users
            .items
            .iter()
            .any(|user| user.name.eq_ignore_ascii_case("alice"))
    );
    for expected in ["interns", "operators"] {
        assert!(
            inventory
                .groups
                .items
                .iter()
                .any(|group| group.name.eq_ignore_ascii_case(expected)),
            "missing provisioned group {expected}"
        );
    }
    assert!(
        inventory
            .computers
            .items
            .iter()
            .any(|computer| computer.name.eq_ignore_ascii_case("DC1$"))
    );
    assert!(
        inventory
            .organization
            .items
            .iter()
            .any(|container| container.is_organizational_unit)
    );

    let topology = inventory
        .topology
        .items
        .first()
        .expect("topology collector returned no snapshot");
    assert!(!topology.domains.is_empty());
    assert!(!topology.sites.is_empty());
    assert!(!topology.group_policies.is_empty());
    assert!(!inventory.privileged.items.is_empty());
    assert!(
        inventory
            .services
            .items
            .iter()
            .any(|principal| !principal.service_principal_names.is_empty())
    );

    let security = inventory
        .security
        .items
        .first()
        .expect("security collector returned no snapshot");
    assert!(security.session_signing);
    assert!(security.session_sealing);
    assert!(security.minimum_password_length.is_some());
    assert!(security.machine_account_quota.is_some());

    for (name, error) in [
        ("users", inventory.users.error.as_deref()),
        ("groups", inventory.groups.error.as_deref()),
        ("computers", inventory.computers.error.as_deref()),
        ("organization", inventory.organization.error.as_deref()),
        ("topology", inventory.topology.error.as_deref()),
        ("privileged", inventory.privileged.error.as_deref()),
        ("services", inventory.services.error.as_deref()),
        ("security", inventory.security.error.as_deref()),
    ] {
        assert!(error.is_none(), "{name} inventory was partial: {error:?}");
    }
}

async fn connect(credential: NtlmCredential, page_size: u32) -> LdapClient {
    let mut config = LdapClientConfig::new(LDAP_ENDPOINT);
    config.page_size = page_size;
    let mut client = LdapClient::connect(config)
        .await
        .expect("failed to connect to the local Samba AD LDAP endpoint");
    client
        .bind_ntlm(TEST_USER, TEST_DOMAIN, credential)
        .await
        .expect("GSS-SPNEGO/NTLM LDAP bind failed");
    client
}
