//! Non-Windows stub for `smb::shares`. See sibling `connection.rs` for rationale.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareAccess {
    ReadWrite,
    Read,
    NoAccess,
}

impl ShareAccess {
    pub fn display_str(&self) -> &str {
        match self {
            ShareAccess::ReadWrite => "RW",
            ShareAccess::Read => "R",
            ShareAccess::NoAccess => "NO ACCESS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareType {
    Disk,
    Printer,
    Device,
    Ipc,
    Special,
    Unknown(u32),
}

impl ShareType {
    pub fn display_str(&self) -> &str {
        match self {
            ShareType::Disk => "DISK",
            ShareType::Printer => "PRINTER",
            ShareType::Device => "DEVICE",
            ShareType::Ipc => "IPC",
            ShareType::Special => "SPECIAL",
            ShareType::Unknown(_) => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    pub remark: String,
    pub access: ShareAccess,
}

pub fn enum_shares(_target: &str) -> Result<Vec<ShareInfo>, String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn enum_shares_with_access(_target: &str) -> Result<Vec<ShareInfo>, String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn can_access_admin_share(_target: &str) -> bool {
    false
}

#[allow(dead_code)] // API mirror of the Windows impl; kept so callers gated on `cfg(windows)` still resolve.
pub fn check_share_access(_target: &str, _share_name: &str) -> ShareAccess {
    ShareAccess::NoAccess
}
