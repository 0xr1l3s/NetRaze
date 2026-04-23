//! Non-Windows stub for `smb::info`.

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub os_version: String,
    pub platform_id: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub server_type: u32,
    pub comment: String,
}

pub fn get_server_info(_target: &str) -> Result<ServerInfo, String> {
    Err(crate::smb::NOT_PORTED.into())
}
