//! Non-Windows stub for `smb::connection`.
//!
//! Mirrors the public API of the Windows implementation so the rest of the
//! workspace (including `netraze-desktop`) compiles on Linux. Every
//! platform-gated call returns an error flagged as "not yet ported" — the
//! real pure-Rust SMB2 session path lands in Phase 3 of the portage plan.

/// Credentials for SMB authentication. Portable — no platform dependency.
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

pub fn connect_ipc(_target: &str, _credential: Option<&SmbCredential>) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn disconnect_ipc(_target: &str) -> Result<(), String> {
    // Idempotent: calling disconnect on a never-connected session is fine.
    Ok(())
}

/// Test if we can connect to a target TCP port. Portable — uses `std::net`.
pub fn is_port_open(target: &str, port: u16, timeout_ms: u64) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = format!("{target}:{port}");
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sock_addr) = addrs.next() {
            return TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms))
                .is_ok();
        }
    }
    false
}
