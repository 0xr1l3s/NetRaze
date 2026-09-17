// Portable modules — pure-Rust, compile on every platform.
pub mod connection;
pub mod crypto;
pub mod fingerprint;
pub mod hive;
pub mod lsa;
pub mod ntlm;
pub mod rpc;
pub mod sam;
pub mod smb2;

// Phase D — portable share file browser: raw SMB2 file operations (list /
// upload / download / mkdir / delete) on the pure-Rust stack. Single
// backend; the Windows-only FindFirstFileW/CopyFileW implementation and the
// Linux NOT_PORTED stub are retired. `pub mod` so integration tests under
// `tests/` can reach `browser::*` directly (same pattern as `shares`).
#[path = "browser_rpc.rs"]
pub mod browser;

// Phase B.2 — SRVSVC NetrShareEnum over a sealed DCE/RPC channel + per-share
// write probing via raw SMB2 CREATE. Replaces the Windows-only NetShareEnum
// path and its NOT_PORTED stub. `pub mod` so integration tests can reach
// `shares::enum_shares` directly (same pattern as `info`, `users`, …).
#[path = "shares_rpc.rs"]
pub mod shares;

// Phase B.1 — SRVSVC NetrServerGetInfo over a sealed DCE/RPC channel.
// Single backend now; the Windows-only NetServerGetInfo path and the
// Linux NOT_PORTED stub were both retired in favour of `info_rpc` so we
// don't carry two divergent implementations long-term. `pub mod` so
// integration tests under `tests/` can reach `info::get_server_info`
// directly (same pattern as `users`, `dump`, `exec`, etc.).
#[path = "info_rpc.rs"]
pub mod info;

// Phase B.3 -- SAMR user enumeration over a sealed DCE/RPC channel.
// Single backend; the Windows-only NetUserEnum path and the Linux
// NOT_PORTED stub are retired.
#[path = "users_rpc.rs"]
pub mod users;

// Phase C -- WINREG BaseRegSaveKey + Hive parser for SAM dump.
// Single backend; the Windows-only RegSaveKey path and the Linux
// NOT_PORTED stub are retired.
#[path = "dump_rpc.rs"]
pub mod dump;

// Phase F -- AV/EDR enumeration over SCMR probes + IPC$ pipe listing on
// the pure-Rust SMB2 stack. Single backend; the Windows-only SCM/FindFirst
// path and the Linux NOT_PORTED stub are retired.
#[path = "enum_av_rpc.rs"]
pub mod enum_av;

// Phase E -- smbexec over DCE/RPC SCMR on the pure-Rust SMB2 stack.
// Single backend; the Windows-only OpenSCManagerW path and the Linux
// NOT_PORTED stub are retired.
#[path = "exec_rpc.rs"]
pub mod exec;

// NanoDump — remote LSASS minidump via SMB upload + smbexec + SMB download.
// Uses direct syscalls (no NTAPI) to stay under EDR radar.
#[path = "nanodump_rpc.rs"]
pub mod nanodump;

pub use browser::{
    RemoteEntry, create_directory, delete_remote_directory, delete_remote_file, download_file,
    format_size, list_directory, upload_file,
};
pub use connection::SmbCredential;
pub use dump::{
    RemoteRegistryHandle, SamDumpResult, dump_lsa, dump_sam, remote_dump_lsa, remote_dump_sam,
    secrets_dump, secrets_dump_nanodump,
};
pub use enum_av::{AvProduct, EnumAvResult, enum_av};
pub use exec::{execute_command, execute_command_live, execute_command_traced};
pub use nanodump::{LsassDumpResult as NanoDumpResult, remote_lsass_dump};
pub use fingerprint::{SmbFingerprint, fingerprint as smb_fingerprint};
pub use info::ServerInfo;
pub use lsa::LsaDumpResult;
pub use sam::SamHash;
pub use shares::{ShareAccess, ShareInfo};
pub use users::UserInfo;

use crate::StaticProtocolFactory;
use netraze_core::Capability;

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

    /// Connect to the target via the pure-Rust SMB2 + NTLMv2 stack.
    ///
    /// The auth mode follows the credential shape: pass-the-hash and
    /// password credentials authenticate strictly (a GUEST/NULL downgrade
    /// is an error); a username without a secret maps to guest access; no
    /// username (or no credential at all) opens an anonymous null session.
    pub async fn connect(&mut self) -> Result<(), String> {
        let target = self.target.clone();

        // Anonymous when no credential (or an empty-username credential)
        // was configured — the null session rides the pure-Rust stack on
        // every platform.
        let anonymous = self
            .credential
            .as_ref()
            .map(|cred| cred.username.is_empty())
            .unwrap_or(true);
        if anonymous {
            let tgt = target.clone();
            let session =
                tokio::task::spawn_blocking(move || smb2::Smb2Session::connect_anonymous(&tgt))
                    .await
                    .map_err(|e| format!("spawn_blocking failed: {e}"))??;
            self.raw_session = Some(session);
            self.connected = true;
            return Ok(());
        }

        let cred = self.credential.clone().expect("checked anonymous above");
        let user = cred.username.clone();
        let domain = cred.domain.clone();
        let tgt = target.clone();

        let session = match cred.nt_hash {
            Some(hash) => tokio::task::spawn_blocking(move || {
                smb2::Smb2Session::connect(&tgt, &hash, &user, &domain)
            })
            .await
            .map_err(|e| format!("spawn_blocking failed: {e}"))??,
            None if cred.password.is_empty() => {
                // Username without secret — guest access.
                tokio::task::spawn_blocking(move || {
                    smb2::Smb2Session::connect_guest(&tgt, &user, &domain)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed: {e}"))??
            }
            None => {
                let password = cred.password.clone();
                tokio::task::spawn_blocking(move || {
                    smb2::Smb2Session::connect_with_password(&tgt, &user, &domain, &password)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed: {e}"))??
            }
        };

        self.raw_session = Some(session);
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub async fn disconnect(&mut self) {
        if let Some(mut session) = self.raw_session.take() {
            let _ = tokio::task::spawn_blocking(move || {
                session.logoff();
            })
            .await;
        }
        self.connected = false;
    }

    /// The credential to hand to the `*_rpc` orchestrators. Falls back to
    /// an anonymous (empty-username) credential when none was configured —
    /// `connect_session` dispatches on the shape, so "no user provided"
    /// means a null session, matching the `connect` behaviour.
    fn cred_or_anonymous(&self) -> SmbCredential {
        self.credential
            .clone()
            .unwrap_or_else(|| SmbCredential::new("", "", ""))
    }

    /// Enumerate shares on the target via SRVSVC `NetrShareEnum`. With a
    /// real credential the DCE/RPC bind is sealed with NTLMSSP; with no
    /// user provided it falls back to an anonymous bind — whether the
    /// server answers that is its `RestrictAnonymous` policy.
    pub async fn enum_shares(&self) -> Result<Vec<ShareInfo>, String> {
        shares::enum_shares(&self.target, &self.cred_or_anonymous()).await
    }

    /// Enumerate shares on the target with per-share read/write access
    /// classification. Same authentication behaviour as
    /// [`SmbClient::enum_shares`].
    pub async fn enum_shares_with_access(&self) -> Result<Vec<ShareInfo>, String> {
        shares::enum_shares_with_access(&self.target, &self.cred_or_anonymous()).await
    }

    /// Get server information via SRVSVC `NetrServerGetInfo` (opnum 21).
    /// Same authentication behaviour as [`SmbClient::enum_shares`] —
    /// anonymous callers get whatever the server's policy allows.
    pub async fn server_info(&self) -> Result<ServerInfo, String> {
        info::get_server_info(&self.target, &self.cred_or_anonymous()).await
    }

    /// Enumerate users through LDAP first for password/hash credentials,
    /// with automatic SAMR fallback. Anonymous and guest sessions use SAMR.
    pub async fn enum_users(&self) -> Result<Vec<UserInfo>, String> {
        crate::users::enum_users(&self.target, &self.cred_or_anonymous()).await
    }

    /// Check if current credentials grant admin access.
    pub async fn check_admin(&mut self) -> bool {
        // Use raw SMB2 session for PtH
        if let Some(ref mut session) = self.raw_session {
            let target = self.target.clone();
            // Can't move &mut through spawn_blocking easily, check inline
            return session.check_admin(&target);
        }
        // Password / hash path: open a fresh session and probe ADMIN$.
        // Anonymous / guest credentials can never open ADMIN$ — but probe
        // anyway so the answer reflects the server, not a client-side
        // shortcut (`false` for a credential-less client stays).
        let Some(cred) = self.credential.as_ref() else {
            return false;
        };
        shares::can_access_admin_share(&self.target, cred).await
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
