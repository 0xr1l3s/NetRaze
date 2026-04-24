use windows::Win32::Storage::FileSystem::{
    CopyFileW, CreateDirectoryW, DeleteFileW, FILE_ATTRIBUTE_DIRECTORY, FindClose, FindFirstFileW,
    FindNextFileW, RemoveDirectoryW, WIN32_FIND_DATAW,
};
use windows::core::PCWSTR;

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A single entry in a remote directory listing.
#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// List files and directories at a UNC path.
/// `unc_path` should be like `\\192.168.1.1\Share\subfolder`
pub fn list_directory(unc_path: &str) -> Result<Vec<RemoteEntry>, String> {
    let search = format!("{}\\*", unc_path.trim_end_matches('\\'));
    let wide = to_wide_null(&search);

    let mut find_data = WIN32_FIND_DATAW::default();
    let handle = unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut find_data) };

    let handle = match handle {
        Ok(h) => h,
        Err(e) => return Err(format!("FindFirstFileW failed: {e}")),
    };

    let mut entries = Vec::new();

    loop {
        let name = wide_to_string(&find_data.cFileName);
        if name != "." && name != ".." {
            let is_dir = find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
            let size = ((find_data.nFileSizeHigh as u64) << 32) | find_data.nFileSizeLow as u64;
            entries.push(RemoteEntry { name, is_dir, size });
        }

        find_data = WIN32_FIND_DATAW::default();
        let ok = unsafe { FindNextFileW(handle, &mut find_data) };
        if ok.is_err() {
            break;
        }
    }

    unsafe {
        let _ = FindClose(handle);
    }

    // Sort: directories first, then alphabetical
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(entries)
}

fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Format a file size for display.
pub fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Download a remote file to a local path using CopyFileW.
pub fn download_file(remote_path: &str, local_path: &str) -> Result<(), String> {
    let wide_src = to_wide_null(remote_path);
    let wide_dst = to_wide_null(local_path);
    let ok = unsafe {
        CopyFileW(
            PCWSTR(wide_src.as_ptr()),
            PCWSTR(wide_dst.as_ptr()),
            false, // overwrite if exists
        )
    };
    match ok {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Download failed: {e}")),
    }
}

/// Upload a local file to a remote path using CopyFileW.
pub fn upload_file(local_path: &str, remote_path: &str) -> Result<(), String> {
    let wide_src = to_wide_null(local_path);
    let wide_dst = to_wide_null(remote_path);
    let ok = unsafe { CopyFileW(PCWSTR(wide_src.as_ptr()), PCWSTR(wide_dst.as_ptr()), false) };
    match ok {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Upload failed: {e}")),
    }
}

/// Create a directory at a remote UNC path.
pub fn create_directory(unc_path: &str) -> Result<(), String> {
    let wide = to_wide_null(unc_path);
    let ok = unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), None) };
    match ok {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("CreateDirectory failed: {e}")),
    }
}

/// Delete a remote file.
pub fn delete_remote_file(unc_path: &str) -> Result<(), String> {
    let wide = to_wide_null(unc_path);
    let ok = unsafe { DeleteFileW(PCWSTR(wide.as_ptr())) };
    match ok {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("DeleteFile failed: {e}")),
    }
}

/// Delete a remote directory (must be empty).
pub fn delete_remote_directory(unc_path: &str) -> Result<(), String> {
    let wide = to_wide_null(unc_path);
    let ok = unsafe { RemoveDirectoryW(PCWSTR(wide.as_ptr())) };
    match ok {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("RemoveDirectory failed: {e}")),
    }
}
