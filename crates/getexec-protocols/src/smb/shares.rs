use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, NetShareEnum, SHARE_INFO_1, SHARE_TYPE,
    STYPE_DEVICE, STYPE_DISKTREE, STYPE_IPC, STYPE_PRINTQ, STYPE_SPECIAL,
};

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide_pwstr(ptr: PWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    unsafe { ptr.to_string().unwrap_or_default() }
}

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

#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    pub remark: String,
    pub access: ShareAccess,
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
    fn from_raw(val: SHARE_TYPE) -> Self {
        let base = SHARE_TYPE(val.0 & 0x0FFF_FFFF);
        let special = val.0 & STYPE_SPECIAL.0 != 0;
        if base == STYPE_DISKTREE && !special {
            ShareType::Disk
        } else if base == STYPE_DISKTREE && special {
            ShareType::Special
        } else if base == STYPE_PRINTQ {
            ShareType::Printer
        } else if base == STYPE_DEVICE {
            ShareType::Device
        } else if base == STYPE_IPC {
            ShareType::Ipc
        } else {
            ShareType::Unknown(val.0)
        }
    }

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

/// Enumerate SMB shares on a remote host using NetShareEnum (level 1).
pub fn enum_shares(target: &str) -> Result<Vec<ShareInfo>, String> {
    let server_wide = to_wide_null(target);
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let status = unsafe {
        NetShareEnum(
            PCWSTR(server_wide.as_ptr()),
            1,
            &mut buf_ptr,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            None,
        )
    };

    if status != 0 {
        return Err(format!("NetShareEnum failed with error code {status}"));
    }

    let mut shares = Vec::new();

    if !buf_ptr.is_null() && entries_read > 0 {
        let array = buf_ptr as *const SHARE_INFO_1;
        for i in 0..entries_read as isize {
            let si = unsafe { &*array.offset(i) };
            shares.push(ShareInfo {
                name: from_wide_pwstr(si.shi1_netname),
                share_type: ShareType::from_raw(si.shi1_type),
                remark: from_wide_pwstr(si.shi1_remark),
                access: ShareAccess::NoAccess,
            });
        }
        unsafe {
            NetApiBufferFree(Some(buf_ptr.cast()));
        }
    }

    Ok(shares)
}

/// Check if the current session can access ADMIN$ share.
pub fn can_access_admin_share(target: &str) -> bool {
    let path = format!("\\\\{}\\ADMIN$", target);
    let wide = to_wide_null(&path);
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    attrs != u32::MAX
}

/// Check access level for a specific share on the target.
pub fn check_share_access(target: &str, share_name: &str) -> ShareAccess {
    let unc = format!("\\\\{}\\{}", target, share_name);
    let wide = to_wide_null(&unc);
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == u32::MAX {
        return ShareAccess::NoAccess;
    }
    // We can read. Try to probe write by checking directory attributes.
    // CreateFileW with GENERIC_WRITE | OPEN_EXISTING on a directory checks write perms
    // without modifying anything.
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_ATTRIBUTE_DIRECTORY,
    };
    use windows::Win32::Foundation::CloseHandle;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            0x40000000, // GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
            None,
        )
    };
    match handle {
        Ok(h) => {
            unsafe { let _ = CloseHandle(h); }
            ShareAccess::ReadWrite
        }
        Err(_) => ShareAccess::Read,
    }
}

/// Enumerate shares and check access for each one.
pub fn enum_shares_with_access(target: &str) -> Result<Vec<ShareInfo>, String> {
    let mut shares = enum_shares(target)?;
    for share in &mut shares {
        share.access = check_share_access(target, &share.name);
    }
    Ok(shares)
}
