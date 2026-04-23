//! Non-Windows stub for `smb::browser`. Full SMB2 rewrite lands in Phase 4.

#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub fn list_directory(_unc_path: &str) -> Result<Vec<RemoteEntry>, String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn format_size(size: u64) -> String {
    // Portable — keep the real formatter so callers still show sensible values
    // once real listings land.
    const K: u64 = 1024;
    if size < K {
        format!("{size} B")
    } else if size < K * K {
        format!("{:.1} KB", size as f64 / K as f64)
    } else if size < K * K * K {
        format!("{:.1} MB", size as f64 / (K * K) as f64)
    } else {
        format!("{:.2} GB", size as f64 / (K * K * K) as f64)
    }
}

pub fn download_file(_remote_path: &str, _local_path: &str) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn upload_file(_local_path: &str, _remote_path: &str) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn create_directory(_unc_path: &str) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn delete_remote_file(_unc_path: &str) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}

pub fn delete_remote_directory(_unc_path: &str) -> Result<(), String> {
    Err(crate::smb::NOT_PORTED.into())
}
