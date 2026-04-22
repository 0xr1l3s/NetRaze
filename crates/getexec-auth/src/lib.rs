use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    NtHash,
    AesKey,
    Ticket,
    Certificate,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    Plaintext,
    PassTheHash,
    Kerberos,
    Certificate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMaterial {
    pub kind: SecretKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSet {
    pub domain: Option<String>,
    pub username: String,
    pub secrets: Vec<SecretMaterial>,
    pub preferred_methods: Vec<AuthMethod>,
}
