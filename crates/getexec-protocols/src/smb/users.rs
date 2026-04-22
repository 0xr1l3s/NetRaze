use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserEnum, NetApiBufferFree, USER_INFO_1, FILTER_NORMAL_ACCOUNT,
    UF_ACCOUNTDISABLE, UF_LOCKOUT,
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

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub privilege_level: u32,
    pub flags: u32,
    pub disabled: bool,
    pub locked: bool,
}

/// Enumerate local users on a remote host using NetUserEnum (level 1).
pub fn enum_users(target: &str) -> Result<Vec<UserInfo>, String> {
    let server_wide = to_wide_null(target);
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let status = unsafe {
        NetUserEnum(
            PCWSTR(server_wide.as_ptr()),
            1,
            FILTER_NORMAL_ACCOUNT,
            &mut buf_ptr,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            None,
        )
    };

    if status != 0 {
        return Err(format!("NetUserEnum failed with error code {status}"));
    }

    let mut users = Vec::new();

    if !buf_ptr.is_null() && entries_read > 0 {
        let array = buf_ptr as *const USER_INFO_1;
        for i in 0..entries_read as isize {
            let ui = unsafe { &*array.offset(i) };
            let flags = ui.usri1_flags;
            users.push(UserInfo {
                name: from_wide_pwstr(ui.usri1_name),
                privilege_level: ui.usri1_priv.0,
                flags: flags.0,
                disabled: flags.contains(UF_ACCOUNTDISABLE),
                locked: flags.contains(UF_LOCKOUT),
            });
        }
        unsafe {
            NetApiBufferFree(Some(buf_ptr.cast()));
        }
    }

    Ok(users)
}
