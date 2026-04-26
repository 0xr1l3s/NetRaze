//! Cross-platform `get_server_info` — SRVSVC `NetrServerGetInfo` (opnum 21)
//! over a sealed DCE/RPC channel on `\PIPE\srvsvc`.
//!
//! Phase B.1 of the cross-platform portage plan. Replaces the Windows-only
//! `NetServerGetInfo` NetAPI call (and its `stubs/info.rs` `NOT_PORTED`
//! stub) with a single implementation that runs identically on every host
//! the rest of the workspace already builds for.
//!
//! The public API mirrors what the Windows version exposed (one
//! `ServerInfo` struct, one async `get_server_info` function) so
//! callers — `SmbClient::server_info` and indirectly the desktop's
//! `runtime.rs` — don't need to know the backend changed.

use std::sync::{Arc, Mutex};

use netraze_dcerpc::interfaces::srvsvc;
use netraze_dcerpc::{RpcChannel, RpcTransport};

use super::connection::SmbCredential;
use super::rpc::{SmbPipeTransport, build_binder, connect_session};
use super::smb2::Smb2Session;

/// Subset of `SERVER_INFO_101` we surface to the rest of the workspace.
///
/// The shape is bit-for-bit compatible with the Windows-native
/// `NetServerGetInfo` wrapper that lived in `info.rs` before this
/// module existed — `SmbClient::server_info` callers (notably the
/// desktop `runtime.rs`) didn't change.
///
/// `os_version` is a pre-formatted human string (`"Windows 10.0"`,
/// `"Windows 6.1"`, …) computed from `version_major & 0x0F` so the high
/// reserved bits don't leak into UI. `version_major` and `version_minor`
/// are the raw NDR fields — kept around for callers that want to do
/// their own classification.
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

/// Drive a `NetrServerGetInfo(level=101)` call against `target` using
/// `cred` for both the SMB session and the DCE/RPC bind.
///
/// Pipeline:
///
/// 1. Open SMB2 session (`Smb2Session::connect{,_with_password}`)
/// 2. Tree connect `\\target\IPC$`
/// 3. Open `\PIPE\srvsvc`
/// 4. 3-leg NTLMSSP bind for SRVSVC v3.0 (PKT_PRIVACY)
/// 5. `RpcChannel::call(opnum=21, encode_netr_server_get_info_request("", 101))`
/// 6. Decode response, surface `Status != 0` as an error
///
/// Steps 1–3 are synchronous and run inside a single `spawn_blocking` so
/// the tokio runtime isn't pinned during DNS / TCP / NTLM compute.
/// Steps 4–6 are async and ride on top of [`SmbPipeTransport`], which
/// itself defers each IOCTL to a `spawn_blocking` internally — meaning
/// no `.await` ever holds the SMB2 session mutex.
pub async fn get_server_info(target: &str, cred: &SmbCredential) -> Result<ServerInfo, String> {
    // ── Stage 1-2: SMB2 session + IPC$ tree connect.
    let target_owned = target.to_owned();
    let cred_for_session = cred.clone();
    let (session, ipc_tid) =
        tokio::task::spawn_blocking(move || -> Result<(Smb2Session, u32), String> {
            let mut s = connect_session(&target_owned, &cred_for_session)?;
            // tree_connect builds a UNC path internally; strip any `:port`
            // suffix because UNC doesn't accept ports (would survive Samba
            // but Windows refuses).
            let host_only = target_owned
                .split(':')
                .next()
                .unwrap_or(&target_owned)
                .to_owned();
            let tid = s.tree_connect(&host_only, "IPC$")?;
            Ok((s, tid))
        })
        .await
        .map_err(|e| format!("spawn_blocking(connect+tree): {e}"))??;

    let session = Arc::new(Mutex::new(session));

    // ── Stage 3: open \PIPE\srvsvc on the IPC$ tree.
    let session_for_pipe = Arc::clone(&session);
    let pipe = tokio::task::spawn_blocking(move || -> Result<SmbPipeTransport, String> {
        SmbPipeTransport::open(session_for_pipe, ipc_tid, "srvsvc")
    })
    .await
    .map_err(|e| format!("spawn_blocking(pipe_open): {e}"))??;
    let transport: Arc<dyn RpcTransport> = Arc::new(pipe);

    // ── Stage 4: NTLMSSP bind to SRVSVC v3.0 with PKT_PRIVACY sealing.
    // Microsoft DCE/RPC over named pipes always runs its own NTLMSSP
    // dance inside the bind PDUs — `build_binder` builds the binder
    // from the same credential the SMB layer used.
    let binder = build_binder(cred, 0);
    let mut channel = RpcChannel::bind_authenticated(
        transport,
        srvsvc::uuid(),
        (srvsvc::VERSION_MAJOR, srvsvc::VERSION_MINOR),
        binder,
    )
    .await
    .map_err(|e| format!("RpcChannel::bind_authenticated(srvsvc): {e}"))?;

    // ── Stage 5: opnum 21 round-trip.
    let stub = srvsvc::encode_netr_server_get_info_request("", 101);
    let response_stub = channel
        .call(srvsvc::Opnum::NetrServerGetInfo as u16, &stub)
        .await
        .map_err(|e| format!("call(NetrServerGetInfo): {e}"))?;
    let info = srvsvc::decode_netr_server_get_info_response(&response_stub)
        .map_err(|e| format!("decode(NetrServerGetInfo): {e}"))?;

    // ── Stage 6: cleanup + result mapping.
    {
        // Best-effort logoff. We don't propagate failures — the test
        // suite tears the container down between runs anyway, and
        // production callers care about the ServerInfo, not whether
        // the server politely acknowledged our farewell.
        let session_for_close = Arc::clone(&session);
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut s) = session_for_close.lock() {
                let _ = s.tree_disconnect(ipc_tid);
                s.logoff();
            }
        })
        .await;
    }

    if info.status != 0 {
        return Err(format!(
            "NetrServerGetInfo returned Win32 status 0x{:08x}",
            info.status
        ));
    }

    Ok(ServerInfo {
        // Mask high 4 bits — they're reserved per MS-SRVS and we don't
        // want them surfacing in the user-facing OS string.
        os_version: format!(
            "Windows {}.{}",
            info.version_major & 0x0F,
            info.version_minor
        ),
        name: info.name,
        platform_id: info.platform_id,
        version_major: info.version_major,
        version_minor: info.version_minor,
        server_type: info.server_type,
        comment: info.comment,
    })
}
