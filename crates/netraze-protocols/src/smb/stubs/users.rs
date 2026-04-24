//! Non-Windows stub for `smb::users`.

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub privilege_level: u32,
    pub flags: u32,
    pub disabled: bool,
    pub locked: bool,
}

pub fn enum_users(_target: &str) -> Result<Vec<UserInfo>, String> {
    Err(crate::smb::NOT_PORTED.into())
}
