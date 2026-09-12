//! SMB credential type — portable, no platform dependency.
//!
//! Historically this module carried a Windows-only WNet IPC$ mount (used
//! for anonymous connects) plus a Linux `NOT_PORTED` stub. Both are
//! retired: `Smb2Session::connect_anonymous` covers null sessions on the
//! pure-Rust stack on every platform, so what remains is the credential
//! type every consumer shares.

/// Credentials for SMB authentication.
///
/// The shape carries the auth intent — `connect_session` and
/// `SmbClient::connect` dispatch on it:
///
/// - empty username → anonymous (null session)
/// - username without secret (no `nt_hash`, empty password) → guest
/// - otherwise → strict password / pass-the-hash authentication
#[derive(Debug, Clone)]
pub struct SmbCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    /// NT hash (16 bytes) for pass-the-hash.
    pub nt_hash: Option<[u8; 16]>,
}

impl SmbCredential {
    pub fn new(username: &str, domain: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            domain: domain.to_owned(),
            password: password.to_owned(),
            nt_hash: None,
        }
    }

    /// Create a credential for pass-the-hash from hex NT hash string.
    pub fn with_hash(username: &str, domain: &str, hash_hex: &str) -> Result<Self, String> {
        let hash_hex = hash_hex.trim();
        if hash_hex.len() != 32 {
            return Err(format!(
                "NT hash must be 32 hex chars, got {}",
                hash_hex.len()
            ));
        }
        let mut hash = [0u8; 16];
        for i in 0..16 {
            hash[i] = u8::from_str_radix(&hash_hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 2))?;
        }
        Ok(Self {
            username: username.to_owned(),
            domain: domain.to_owned(),
            password: String::new(),
            nt_hash: Some(hash),
        })
    }
}

/// Test if we can connect to a target TCP port.
///
/// `target` may carry its own port (`"host:1445"`, `"[ipv6]:445"`); an
/// explicit port wins over `port` so the pre-scan works against hosts
/// published on non-445 ports.
pub fn is_port_open(target: &str, port: u16, timeout_ms: u64) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = crate::targets::with_default_port(target, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sock_addr) = addrs.next() {
            return TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms))
                .is_ok();
        }
    }
    false
}
