use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::NetManagement::{
    NetServerGetInfo, NetApiBufferFree, SERVER_INFO_101,
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
pub struct ServerInfo {
    pub name: String,
    pub os_version: String,
    pub platform_id: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub server_type: u32,
    pub comment: String,
}

/// Get server information using NetServerGetInfo (level 101).
pub fn get_server_info(target: &str) -> Result<ServerInfo, String> {
    let server_wide = to_wide_null(target);
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();

    let status = unsafe {
        NetServerGetInfo(
            PCWSTR(server_wide.as_ptr()),
            101,
            &mut buf_ptr,
        )
    };

    if status != 0 {
        return Err(format!("NetServerGetInfo failed with error code {status}"));
    }

    if buf_ptr.is_null() {
        return Err("NetServerGetInfo returned null buffer".to_owned());
    }

    let si = unsafe { &*(buf_ptr as *const SERVER_INFO_101) };

    let info = ServerInfo {
        name: from_wide_pwstr(si.sv101_name),
        os_version: format!(
            "Windows {}.{}",
            si.sv101_version_major & 0x0F,
            si.sv101_version_minor
        ),
        platform_id: si.sv101_platform_id,
        version_major: si.sv101_version_major,
        version_minor: si.sv101_version_minor,
        server_type: si.sv101_type.0,
        comment: from_wide_pwstr(si.sv101_comment),
    };

    unsafe {
        NetApiBufferFree(Some(buf_ptr.cast()));
    }

    Ok(info)
}
