use std::time::Duration;

use netraze_ldap::LdapClientConfig;

#[test]
fn client_defaults_are_bounded() {
    let config = LdapClientConfig::new("dc.example.test");
    assert_eq!(config.connect_timeout, Duration::from_secs(5));
    assert_eq!(config.operation_timeout, Duration::from_secs(20));
    assert_eq!(config.max_pdu_size, 16 * 1024 * 1024);
    assert_eq!(config.page_size, 1000);
}
