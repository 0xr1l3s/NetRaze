use netraze_protocols::ntlm::{NtlmCredential, NtlmSecurityContext, nt_hash_from_password};

#[test]
fn password_credentials_derive_the_known_nt_hash() {
    let credential = NtlmCredential::Password("Password".to_owned());
    assert_eq!(
        credential.nt_hash().unwrap(),
        [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
            0xd8, 0x52,
        ]
    );
    assert_eq!(
        credential.nt_hash().unwrap(),
        nt_hash_from_password("Password")
    );
}

#[test]
fn sasl_context_keeps_independent_directional_state() {
    let key = [0x55; 16];
    let mut client = NtlmSecurityContext::new(key);
    let mut server = NtlmSecurityContext::new_server(key);

    let first = client.wrap(b"first LDAP message").unwrap();
    let second = client.wrap(b"second LDAP message").unwrap();

    assert_eq!(server.unwrap(&first).unwrap(), b"first LDAP message");
    assert_eq!(server.unwrap(&second).unwrap(), b"second LDAP message");
    assert_eq!(client.send_sequence(), 2);
    assert_eq!(server.receive_sequence(), 2);
}

#[test]
fn sasl_context_rejects_tampered_signatures() {
    let key = [0x42; 16];
    let mut client = NtlmSecurityContext::new(key);
    let mut server = NtlmSecurityContext::new_server(key);
    let mut wrapped = client.wrap(b"protected").unwrap();
    wrapped[4] ^= 0x80;

    assert!(server.unwrap(&wrapped).is_err());
    assert_eq!(server.receive_sequence(), 0);
}
