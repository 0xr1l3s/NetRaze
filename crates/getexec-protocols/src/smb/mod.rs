pub mod connection;
pub mod browser;
mod shares;
mod info;
pub mod users;
pub mod crypto;
pub mod hive;
pub mod sam;
pub mod dump;
pub mod enum_av;
pub mod ntlm;
pub mod smb2;
pub mod fingerprint;
pub mod exec;

pub use connection::SmbCredential;
pub use exec::{execute_command, execute_command_live, execute_command_traced};
pub use shares::{ShareInfo, ShareAccess};
pub use browser::{RemoteEntry, list_directory, format_size, download_file, upload_file, create_directory, delete_remote_file, delete_remote_directory};
pub use info::ServerInfo;
pub use users::UserInfo;
pub use sam::SamHash;
pub use dump::{SamDumpResult, LsaDumpResult, remote_dump_sam, remote_dump_lsa};
pub use enum_av::{AvProduct, EnumAvResult, enum_av};
pub use fingerprint::{SmbFingerprint, fingerprint as smb_fingerprint};

use crate::StaticProtocolFactory;
use getexec_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "smb",
        "SMB",
        445,
        vec![
            Capability::Authentication,
            Capability::CommandExecution,
            Capability::Enumeration,
            Capability::FileTransfer,
            Capability::SecretDump,
            Capability::ModuleHooks,
        ],
    )
}

/// High-level async SMB client wrapping Windows native APIs.
/// Supports pass-the-hash via raw SMB2 + NTLMv2 when NT hash is set.
pub struct SmbClient {
    target: String,
    credential: Option<SmbCredential>,
    connected: bool,
    /// Raw SMB2 session for pass-the-hash connections.
    raw_session: Option<smb2::Smb2Session>,
}

#[derive(Debug, Clone)]
pub struct SmbScanResult {
    pub target: String,
    pub hostname: Option<String>,
    pub os_info: Option<String>,
    pub signing: Option<bool>,
    pub smb_version: Option<String>,
    pub shares: Vec<ShareInfo>,
    pub users: Vec<UserInfo>,
    pub admin: bool,
    pub error: Option<String>,
}

impl SmbClient {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_owned(),
            credential: None,
            connected: false,
            raw_session: None,
        }
    }

    pub fn with_credential(mut self, cred: SmbCredential) -> Self {
        self.credential = Some(cred);
        self
    }

    /// Connect to the target. Uses raw SMB2 for hash creds, WNet for passwords.
    pub async fn connect(&mut self) -> Result<(), String> {
        let target = self.target.clone();
        let cred = self.credential.clone();

        // Check if this is a PtH credential
        if let Some(ref c) = cred {
            if let Some(ref nt_hash) = c.nt_hash {
                let hash = *nt_hash;
                let user = c.username.clone();
                let domain = c.domain.clone();
                let tgt = target.clone();

                let session = tokio::task::spawn_blocking(move || {
                    smb2::Smb2Session::connect(&tgt, &hash, &user, &domain)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed: {e}"))??;

                self.raw_session = Some(session);
                self.connected = true;
                return Ok(());
            }
        }

        // Standard WNet path for password-based auth
        let result = tokio::task::spawn_blocking(move || {
            connection::connect_ipc(&target, cred.as_ref())
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?;

        match result {
            Ok(()) => {
                self.connected = true;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Disconnect.
    pub async fn disconnect(&mut self) {
        if let Some(mut session) = self.raw_session.take() {
            let _ = tokio::task::spawn_blocking(move || {
                session.logoff();
            })
            .await;
        }
        if self.connected {
            let target = self.target.clone();
            let _ = tokio::task::spawn_blocking(move || {
                connection::disconnect_ipc(&target)
            })
            .await;
            self.connected = false;
        }
    }

    /// Enumerate shares on the target.
    pub async fn enum_shares(&self) -> Result<Vec<ShareInfo>, String> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || shares::enum_shares(&target))
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?
    }

    /// Enumerate shares on the target with access level checks.
    pub async fn enum_shares_with_access(&self) -> Result<Vec<ShareInfo>, String> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || shares::enum_shares_with_access(&target))
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?
    }

    /// Get server information.
    pub async fn server_info(&self) -> Result<ServerInfo, String> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || info::get_server_info(&target))
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?
    }

    /// Enumerate users (requires admin).
    pub async fn enum_users(&self) -> Result<Vec<UserInfo>, String> {
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || users::enum_users(&target))
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))?
    }

    /// Check if current credentials grant admin access.
    pub async fn check_admin(&mut self) -> bool {
        // Use raw SMB2 session for PtH
        if let Some(ref mut session) = self.raw_session {
            let target = self.target.clone();
            // Can't move &mut through spawn_blocking easily, check inline
            return session.check_admin(&target);
        }
        // WNet path
        let target = self.target.clone();
        tokio::task::spawn_blocking(move || shares::can_access_admin_share(&target))
            .await
            .unwrap_or(false)
    }

    /// Full scan: connect, gather info, enum shares/users, check admin.
    pub async fn full_scan(&mut self) -> SmbScanResult {
        let mut result = SmbScanResult {
            target: self.target.clone(),
            hostname: None,
            os_info: None,
            signing: None,
            smb_version: None,
            shares: Vec::new(),
            users: Vec::new(),
            admin: false,
            error: None,
        };

        // Connect
        if let Err(e) = self.connect().await {
            result.error = Some(e);
            return result;
        }

        // Server info
        if let Ok(si) = self.server_info().await {
            result.hostname = Some(si.name.clone());
            result.os_info = Some(si.os_version.clone());
            result.smb_version = Some(si.platform_id.to_string());
        }

        // Shares
        if let Ok(sh) = self.enum_shares().await {
            result.shares = sh;
        }

        // Admin check
        result.admin = self.check_admin().await;

        // Users (only if admin)
        if result.admin {
            if let Ok(u) = self.enum_users().await {
                result.users = u;
            }
        }

        self.disconnect().await;
        result
    }
}
