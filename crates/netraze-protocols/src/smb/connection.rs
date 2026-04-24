use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::WNet::{
    CONNECT_TEMPORARY, NET_CONNECT_FLAGS, NETRESOURCEW, WNetAddConnection2W, WNetCancelConnection2W,
};
use windows::core::{PCWSTR, PWSTR};

/// Credentials for SMB authentication.
#[derive(Debug, Clone)]
pub struct SmbCredential {
    pub username: String,
    pub domain: String,
    pub password: String,
    /// NT hash (16 bytes) for pass-the-hash. If set, raw SMB2 is used instead of WNet.
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

    /// Build "DOMAIN\username" for WNet authentication.
    /// "." is treated as local (no domain prefix) since WNet doesn't understand ".".
    fn qualified_username(&self) -> String {
        if self.domain.is_empty() || self.domain == "." {
            self.username.clone()
        } else {
            format!("{}\\{}", self.domain, self.username)
        }
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Connect to \\target\IPC$ using WNetAddConnection2W.
pub fn connect_ipc(target: &str, credential: Option<&SmbCredential>) -> Result<(), String> {
    let remote_name = format!("\\\\{}\\IPC$", target);
    let mut remote_wide = to_wide_null(&remote_name);

    let nr = NETRESOURCEW {
        lpRemoteName: PWSTR(remote_wide.as_mut_ptr()),
        ..Default::default()
    };

    let (user_wide, pass_wide);
    let (user_ptr, pass_ptr) = match credential {
        Some(cred) => {
            user_wide = to_wide_null(&cred.qualified_username());
            pass_wide = to_wide_null(&cred.password);
            (PCWSTR(user_wide.as_ptr()), PCWSTR(pass_wide.as_ptr()))
        }
        None => (PCWSTR::null(), PCWSTR::null()),
    };

    let result = unsafe { WNetAddConnection2W(&nr, pass_ptr, user_ptr, CONNECT_TEMPORARY) };

    match result {
        WIN32_ERROR(0) => Ok(()),
        WIN32_ERROR(1219) => {
            // ERROR_SESSION_CREDENTIAL_CONFLICT — already connected with different creds.
            // Must clear ALL cached connections to this server before reconnecting.
            disconnect_all(target);
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Rebuild NETRESOURCEW since we need a fresh call
            let mut remote_wide2 = to_wide_null(&remote_name);
            let nr2 = NETRESOURCEW {
                lpRemoteName: PWSTR(remote_wide2.as_mut_ptr()),
                ..Default::default()
            };
            let retry = unsafe { WNetAddConnection2W(&nr2, pass_ptr, user_ptr, CONNECT_TEMPORARY) };
            match retry {
                WIN32_ERROR(0) => Ok(()),
                err => Err(format!(
                    "WNetAddConnection2W retry to {} failed with error code {}",
                    remote_name, err.0
                )),
            }
        }
        err => Err(format!(
            "WNetAddConnection2W to {} failed with error code {}",
            remote_name, err.0
        )),
    }
}

/// Force-disconnect ALL known connections to a server (IPC$, ADMIN$, C$, etc.).
fn disconnect_all(target: &str) {
    let shares = ["IPC$", "ADMIN$", "C$", "PRINT$"];
    for share in &shares {
        let name = format!("\\\\{}\\{}", target, share);
        let wide = to_wide_null(&name);
        unsafe {
            let _ = WNetCancelConnection2W(
                PCWSTR(wide.as_ptr()),
                NET_CONNECT_FLAGS(0),
                true, // force
            );
        }
    }
}

/// Disconnect from \\target\IPC$.
pub fn disconnect_ipc(target: &str) -> Result<(), String> {
    let remote_name = format!("\\\\{}\\IPC$", target);
    let remote_wide = to_wide_null(&remote_name);

    let result =
        unsafe { WNetCancelConnection2W(PCWSTR(remote_wide.as_ptr()), NET_CONNECT_FLAGS(0), true) };

    match result {
        WIN32_ERROR(0) | WIN32_ERROR(2250) => Ok(()), // 2250 = not connected
        err => Err(format!(
            "WNetCancelConnection2W for {} failed with error code {}",
            remote_name, err.0
        )),
    }
}

/// Test if we can connect to a target on port 445.
pub fn is_port_open(target: &str, port: u16, timeout_ms: u64) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = format!("{}:{}", target, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sock_addr) = addrs.next() {
            return TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms))
                .is_ok();
        }
    }
    false
}
