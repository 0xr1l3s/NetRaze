use netraze_core::UserEnumerationSource;
use netraze_protocols::{
    ldap::{LdapClient, LdapClientConfig},
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
