//! Pure-Rust user enumeration via MS-SAMR over SMB2 named pipes.
//!
//! Phase B.3 of the cross-platform portage. Replaces the Windows-only
//! `NetUserEnum` path and the Linux `NOT_PORTED` stub with a DCE/RPC
//! sequence over `\PIPE\samr`:
//!
//! 1. `SamrConnect2` (opnum 62) → server_handle
//! 2. `SamrEnumerateDomainsInSamServer` (opnum 6) → pick first ≠ "Builtin"
//! 3. `SamrLookupDomain` (opnum 5) → domain SID
//! 4. `SamrOpenDomain` (opnum 7) → domain_handle
//! 5. `SamrEnumerateUsersInDomain` (opnum 13, loop resume) → RIDs + names
//! 6. `SamrCloseHandle` ×2 → cleanup
//!
//! v1 does **not** call `SamrOpenUser`/`SamrQueryInformationUser`; per-user
//! flags (disabled, locked, privilege_level) are left at defaults. That
//! enrichment is tracked for a v1.1 follow-up.

use std::sync::{Arc, Mutex};

use netraze_dcerpc::channel::RpcChannel;
use netraze_dcerpc::interfaces::samr;

use super::connection::SmbCredential;
use super::rpc::{SmbPipeTransport, build_binder, connect_session};

/// Re-export so `mod.rs` can re-export it as `users::UserInfo`.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub privilege_level: u32,
    pub flags: u32,
    pub disabled: bool,
    pub locked: bool,
}

/// NTSTATUS `STATUS_MORE_ENTRIES` — resume handle is valid, call again.
const STATUS_MORE_ENTRIES: u32 = 0x0000_0105;

/// Enumerate local/domain users via SAMR.
///
/// `target` may be a bare host or `host:port` (same shapes accepted by
/// `Smb2Session::connect`).
pub async fn enum_users(target: &str, cred: &SmbCredential) -> Result<Vec<UserInfo>, String> {
    // 1. SMB2 session + IPC$ tree + SAMR pipe.
    let session = Arc::new(Mutex::new(
        connect_session(target, cred).map_err(|e| format!("connect_session: {e}"))?,
    ));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(target, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;

    let pipe = Arc::new(
        SmbPipeTransport::open(session.clone(), ipc, "samr")
            .map_err(|e| format!("open samr pipe: {e}"))?,
    );

    let binder = build_binder(cred, 0);
    let mut ch = RpcChannel::bind_authenticated(pipe, samr::uuid(), (1, 0), binder)
        .await
        .map_err(|e| format!("SAMR bind_authenticated: {e}"))?;

    // 2. SamrConnect2
    // Windows SAMR expects a NULL server name; passing an IP or hostname
    // yields RPC_X_BAD_STUB_DATA on most targets.
    let stub_conn = samr::encode_samr_connect2_request(None, samr::MAXIMUM_ALLOWED);
    let resp_conn = ch
        .call(samr::Opnum::SamrConnect2 as u16, &stub_conn)
        .await
        .map_err(|e| format!("SamrConnect2: {e}"))?;
    let (server_handle, status) =
        samr::decode_samr_connect2_response(&resp_conn).map_err(|e| e.to_string())?;
    if status != 0 {
        return Err(format!("SamrConnect2 failed with status 0x{status:08x}"));
    }

    // 3. SamrEnumerateDomainsInSamServer
    let mut domain_name = String::new();
    let mut resume = 0u32;
    loop {
        let stub_enum = samr::encode_samr_enumerate_domains_request(&server_handle, resume, 0x1000);
        let resp_enum = ch
            .call(
                samr::Opnum::SamrEnumerateDomainsInSamServer as u16,
                &stub_enum,
            )
            .await
            .map_err(|e| format!("SamrEnumerateDomains: {e}"))?;
        let dom_resp =
            samr::decode_samr_enumerate_domains_response(&resp_enum).map_err(|e| e.to_string())?;

        for entry in &dom_resp.entries {
            if !entry.name.eq_ignore_ascii_case("Builtin") {
                domain_name = entry.name.clone();
                break;
            }
        }

        if !domain_name.is_empty() {
            break;
        }

        if dom_resp.status == STATUS_MORE_ENTRIES && dom_resp.resume_handle != 0 {
            resume = dom_resp.resume_handle;
        } else {
            break;
        }
    }

    if domain_name.is_empty() {
        // Nothing useful found — close server handle and bail.
        let _ = close_handle(&mut ch, &server_handle).await;
        return Ok(Vec::new());
    }

    // 4. SamrLookupDomain
    let stub_lookup = samr::encode_samr_lookup_domain_request(&server_handle, &domain_name);
    let resp_lookup = ch
        .call(samr::Opnum::SamrLookupDomain as u16, &stub_lookup)
        .await
        .map_err(|e| format!("SamrLookupDomain: {e}"))?;
    let (domain_sid, status) =
        samr::decode_samr_lookup_domain_response(&resp_lookup).map_err(|e| e.to_string())?;
    if status != 0 {
        let _ = close_handle(&mut ch, &server_handle).await;
        return Err(format!(
            "SamrLookupDomain failed with status 0x{status:08x}"
        ));
    }

    // 5. SamrOpenDomain
    let stub_open =
        samr::encode_samr_open_domain_request(&server_handle, samr::MAXIMUM_ALLOWED, &domain_sid);
    let resp_open = ch
        .call(samr::Opnum::SamrOpenDomain as u16, &stub_open)
        .await
        .map_err(|e| format!("SamrOpenDomain: {e}"))?;
    let (domain_handle, status) =
        samr::decode_samr_open_domain_response(&resp_open).map_err(|e| e.to_string())?;
    if status != 0 {
        let _ = close_handle(&mut ch, &server_handle).await;
        return Err(format!("SamrOpenDomain failed with status 0x{status:08x}"));
    }

    // 6. SamrEnumerateUsersInDomain (loop resume)
    let mut users = Vec::new();
    resume = 0;
    loop {
        let stub_users = samr::encode_samr_enumerate_users_request(
            &domain_handle,
            resume,
            samr::USER_NORMAL_ACCOUNT,
            0x1000,
        );
        let resp_users = ch
            .call(samr::Opnum::SamrEnumerateUsersInDomain as u16, &stub_users)
            .await
            .map_err(|e| format!("SamrEnumerateUsersInDomain: {e}"))?;
        let user_resp =
            samr::decode_samr_enumerate_users_response(&resp_users).map_err(|e| e.to_string())?;

        for entry in user_resp.entries {
            let mut info = UserInfo {
                name: entry.name,
                privilege_level: 1, // default: normal user
                flags: 0,
                disabled: false,
                locked: false,
            };

            // Enrich with real account flags via SamrOpenUser + SamrQueryInformationUser
            let stub_open = samr::encode_samr_open_user_request(
                &domain_handle,
                samr::MAXIMUM_ALLOWED,
                entry.relative_id,
            );
            if let Ok(resp_open) = ch
                .call(samr::Opnum::SamrOpenUser as u16, &stub_open)
                .await
            {
                if let Ok((user_handle, status)) = samr::decode_samr_open_user_response(&resp_open) {
                    if status == 0 {
                        let stub_query = samr::encode_samr_query_information_user_request(
                            &user_handle,
                            samr::USER_CONTROL_INFORMATION,
                        );
                        if let Ok(resp_query) = ch
                            .call(samr::Opnum::SamrQueryInformationUser as u16, &stub_query)
                            .await
                        {
                            if let Ok((Some(uac), qstatus)) =
                                samr::decode_samr_query_information_user_response(&resp_query)
                            {
                                if qstatus == 0 {
                                    info.flags = uac;
                                    info.disabled = (uac & 0x0000_0001) != 0;
                                    info.locked = (uac & 0x0000_0400) != 0;
                                    // Privilege heuristic
                                    info.privilege_level = match entry.relative_id {
                                        500 => 2, // Administrator
                                        501 => 0, // Guest
                                        _ => 1,   // Normal user
                                    };
                                }
                            }
                        }
                        let _ = close_handle(&mut ch, &user_handle).await;
                    }
                }
            }

            users.push(info);
        }

        if user_resp.status == STATUS_MORE_ENTRIES && user_resp.resume_handle != 0 {
            resume = user_resp.resume_handle;
        } else {
            break;
        }
    }

    // 7. Cleanup
    let _ = close_handle(&mut ch, &domain_handle).await;
    let _ = close_handle(&mut ch, &server_handle).await;

    Ok(users)
}

/// Helper: close a SAMR handle, ignoring errors (best-effort cleanup).
async fn close_handle(ch: &mut RpcChannel, handle: &samr::SamprHandle) {
    let stub = samr::encode_samr_close_handle_request(handle);
    // We ignore the response — if the server already closed it, so be it.
    let _ = ch.call(samr::Opnum::SamrCloseHandle as u16, &stub).await;
}
