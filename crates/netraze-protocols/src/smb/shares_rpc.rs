//! Cross-platform `enum_shares` — SRVSVC `NetrShareEnum` (opnum 15) over a
//! sealed DCE/RPC channel on `\PIPE\srvsvc`, with optional per-share write
//! probing via raw SMB2 CREATE.
//!
//! Phase B.2 of the cross-platform portage plan. Replaces the Windows-only
//! `NetShareEnum` NetAPI call (and its `stubs/shares.rs` `NOT_PORTED` stub)
//! with a single implementation that runs identically on every host.
//!
//! The public surface (`ShareInfo`, `ShareAccess`, `ShareType`, the four free
//! functions) is bit-for-bit compatible with the Windows version so callers —
//! `SmbClient::enum_shares*` and the desktop `runtime.rs` — don't change.

use std::sync::{Arc, Mutex};

use netraze_dcerpc::interfaces::srvsvc;
use netraze_dcerpc::{RpcChannel, RpcTransport};
use rand::RngCore;

use super::connection::SmbCredential;
use super::rpc::{SmbPipeTransport, build_binder, connect_session};
use super::smb2::Smb2Session;

/// Win32 status `ERROR_MORE_DATA` — server has more shares than fit in this
/// reply, caller should re-issue with the returned `resume_handle` until it
/// gets back `0` (`ERROR_SUCCESS`). MS-SRVS §2.2.4.10.
const ERROR_MORE_DATA: u32 = 234;

/// Hard cap on how many `NetrShareEnum` continuations we'll chase before
/// giving up. Real servers never have anything close to this many shares;
/// hitting the cap means the server is buggy or hostile.
const MAX_RESUMES: usize = 64;

/// Conventional `PreferedMaximumLength` value: ask the server to fit as much
/// as it can in one reply (matches Impacket / nxc / Windows clients).
const PREFERED_MAX_LENGTH: u32 = 0xFFFF_FFFF;

/// SHARE_TYPE bitmask isolating the base type — high nibble carries
/// `STYPE_SPECIAL` / `STYPE_TEMPORARY` flags we don't model granularly.
const SHARE_TYPE_BASE_MASK: u32 = 0x0FFF_FFFF;
const STYPE_SPECIAL_FLAG: u32 = 0x8000_0000;
const STYPE_DISKTREE: u32 = 0;
const STYPE_PRINTQ: u32 = 1;
const STYPE_DEVICE: u32 = 2;
const STYPE_IPC: u32 = 3;

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
    /// Decode an MS-SRVS `SHARE_TYPE` DWORD into our enum. The high nibble
    /// carries flag bits (`STYPE_SPECIAL`, `STYPE_TEMPORARY`); we only model
    /// `STYPE_SPECIAL` because that's the discriminator between `C$` (special
    /// disk) and a user-created `Public` share.
    pub fn from_raw(raw: u32) -> Self {
        let base = raw & SHARE_TYPE_BASE_MASK;
        let special = raw & STYPE_SPECIAL_FLAG != 0;
        match (base, special) {
            (STYPE_DISKTREE, false) => ShareType::Disk,
            (STYPE_DISKTREE, true) => ShareType::Special,
            (STYPE_PRINTQ, _) => ShareType::Printer,
            (STYPE_DEVICE, _) => ShareType::Device,
            (STYPE_IPC, _) => ShareType::Ipc,
            _ => ShareType::Unknown(raw),
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

#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    pub remark: String,
    /// `NoAccess` from `enum_shares` — caller must run
    /// `enum_shares_with_access` (or probe manually) to populate this.
    pub access: ShareAccess,
}

/// Enumerate shares on `target` via SRVSVC `NetrShareEnum(level=1)`.
///
/// `access` is left at `ShareAccess::NoAccess` for every share — this call
/// only walks the share table, it does NOT probe per-share permissions. Use
/// [`enum_shares_with_access`] when the caller needs the access classification.
///
/// Internally loops on `resume_handle` while the server returns
/// `ERROR_MORE_DATA` (a host with hundreds of shares may need 2-3 round
/// trips). Capped at [`MAX_RESUMES`] continuations to defend against a
/// malicious server that streams a never-ending pagination cookie.
pub async fn enum_shares(target: &str, cred: &SmbCredential) -> Result<Vec<ShareInfo>, String> {
    let target_owned = target.to_owned();
    let cred_for_session = cred.clone();
    let (session, ipc_tid) =
        tokio::task::spawn_blocking(move || -> Result<(Smb2Session, u32), String> {
            let mut s = connect_session(&target_owned, &cred_for_session)?;
            let host_only = host_only(&target_owned);
            let tid = s.tree_connect(&host_only, "IPC$")?;
            Ok((s, tid))
        })
        .await
        .map_err(|e| format!("spawn_blocking(connect+tree): {e}"))??;

    let session = Arc::new(Mutex::new(session));

    let session_for_pipe = Arc::clone(&session);
    let pipe = tokio::task::spawn_blocking(move || -> Result<SmbPipeTransport, String> {
        SmbPipeTransport::open(session_for_pipe, ipc_tid, "srvsvc")
    })
    .await
    .map_err(|e| format!("spawn_blocking(pipe_open): {e}"))??;
    let transport: Arc<dyn RpcTransport> = Arc::new(pipe);

    let binder = build_binder(cred, 0);
    let mut channel = RpcChannel::bind_authenticated(
        transport,
        srvsvc::uuid(),
        (srvsvc::VERSION_MAJOR, srvsvc::VERSION_MINOR),
        binder,
    )
    .await
    .map_err(|e| format!("RpcChannel::bind_authenticated(srvsvc): {e}"))?;

    // Continuation loop: server may chunk a large share table across
    // multiple `NetrShareEnum` calls, signalled by ERROR_MORE_DATA + a
    // non-zero resume handle.
    let mut shares = Vec::new();
    let mut resume_handle = 0u32;
    let mut iterations = 0usize;
    loop {
        if iterations >= MAX_RESUMES {
            return Err(format!(
                "NetrShareEnum: server returned >{MAX_RESUMES} continuations — refusing to keep paging"
            ));
        }
        iterations += 1;

        let stub = srvsvc::encode_netr_share_enum_request("", PREFERED_MAX_LENGTH, resume_handle);
        let response_stub = channel
            .call(srvsvc::Opnum::NetrShareEnum as u16, &stub)
            .await
            .map_err(|e| format!("call(NetrShareEnum): {e}"))?;
        let resp = srvsvc::decode_netr_share_enum_response(&response_stub)
            .map_err(|e| format!("decode(NetrShareEnum): {e}"))?;

        for s in resp.shares {
            shares.push(ShareInfo {
                name: s.netname,
                share_type: ShareType::from_raw(s.shi1_type),
                remark: s.remark,
                access: ShareAccess::NoAccess,
            });
        }

        if resp.status == ERROR_MORE_DATA && resp.resume_handle != 0 {
            resume_handle = resp.resume_handle;
            continue;
        }
        if resp.status != 0 && resp.status != ERROR_MORE_DATA {
            return Err(format!(
                "NetrShareEnum returned Win32 status 0x{:08x}",
                resp.status
            ));
        }
        break;
    }

    // Best-effort cleanup; failures don't matter — the caller wants the
    // shares, not a polite session teardown.
    let session_for_close = Arc::clone(&session);
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut s) = session_for_close.lock() {
            let _ = s.tree_disconnect(ipc_tid);
            s.logoff();
        }
    })
    .await;

    Ok(shares)
}

/// Enumerate shares **and** probe per-share read/write access. Equivalent
/// of running [`enum_shares`] then poking each entry with a CREATE on a
/// random non-existent path.
///
/// Probing strategy:
/// 1. Try `tree_connect`. Failure ⇒ [`ShareAccess::NoAccess`] (no point
///    asking about writes if we can't even mount the share).
/// 2. Issue `Smb2Session::probe_write` on a random `__netraze_probe_<rand>__`
///    path. Returns:
///    - `Ok(true)` ⇒ [`ShareAccess::ReadWrite`]
///    - `Ok(false)` ⇒ [`ShareAccess::Read`] (server returned ACCESS_DENIED)
///    - `Err(_)` ⇒ [`ShareAccess::Read`] as a safe fallback (unknown
///      status — assume worst-of-the-two-positives, never falsely report
///      RW we don't actually have).
///
/// IPC$ and printer shares are skipped (left at `NoAccess`); writing to
/// them isn't a meaningful operation and Windows refuses on principle.
pub async fn enum_shares_with_access(
    target: &str,
    cred: &SmbCredential,
) -> Result<Vec<ShareInfo>, String> {
    let mut shares = enum_shares(target, cred).await?;
    if shares.is_empty() {
        return Ok(shares);
    }

    let target_owned = target.to_owned();
    let cred_for_session = cred.clone();
    let names_for_probe: Vec<(usize, String, ShareType)> = shares
        .iter()
        .enumerate()
        .filter(|(_, s)| !matches!(s.share_type, ShareType::Ipc | ShareType::Printer))
        .map(|(i, s)| (i, s.name.clone(), s.share_type.clone()))
        .collect();

    if names_for_probe.is_empty() {
        return Ok(shares);
    }

    // One blocking task drives the whole probe sweep on a single SMB2
    // session — far cheaper than re-handshaking per share.
    let probed = tokio::task::spawn_blocking(move || -> Vec<(usize, ShareAccess)> {
        let mut session = match connect_session(&target_owned, &cred_for_session) {
            Ok(s) => s,
            Err(_) => {
                // Couldn't even open a session for probing. Fall back to
                // NoAccess for every probe target.
                return names_for_probe
                    .into_iter()
                    .map(|(i, _, _)| (i, ShareAccess::NoAccess))
                    .collect();
            }
        };
        let host_only = host_only(&target_owned);

        let mut out = Vec::with_capacity(names_for_probe.len());
        for (idx, name, _ty) in names_for_probe {
            let access = match session.tree_connect(&host_only, &name) {
                Err(_) => ShareAccess::NoAccess,
                Ok(tid) => {
                    let probe_name = random_probe_name();
                    let access = match session.probe_write(tid, &probe_name) {
                        Ok(true) => ShareAccess::ReadWrite,
                        Ok(false) => ShareAccess::Read,
                        Err(_) => ShareAccess::Read,
                    };
                    let _ = session.tree_disconnect(tid);
                    access
                }
            };
            out.push((idx, access));
        }
        session.logoff();
        out
    })
    .await
    .map_err(|e| format!("spawn_blocking(probe_access): {e}"))?;

    for (idx, access) in probed {
        shares[idx].access = access;
    }
    Ok(shares)
}

/// Cheap admin-share probe: open a session, try `tree_connect("ADMIN$")`,
/// report whether it worked. Used by `SmbClient::check_admin` on the
/// password / hash auth paths.
///
/// Fails closed (`false`) on any error — including "couldn't even reach
/// the host". Callers that need to distinguish "denied" from "unreachable"
/// should drive `Smb2Session` directly.
pub async fn can_access_admin_share(target: &str, cred: &SmbCredential) -> bool {
    let target_owned = target.to_owned();
    let cred = cred.clone();
    tokio::task::spawn_blocking(move || -> bool {
        let mut session = match connect_session(&target_owned, &cred) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let host_only = host_only(&target_owned);
        let granted = session.check_admin(&host_only);
        session.logoff();
        granted
    })
    .await
    .unwrap_or(false)
}

/// Strip the `:port` (or `[ipv6]:port`) suffix off `target` so the result
/// is a UNC-safe hostname. UNC paths reject ports; Windows refuses, Samba
/// happens to tolerate them but we don't want to depend on that.
fn host_only(target: &str) -> String {
    if let Some(stripped) = target.strip_prefix('[') {
        // [ipv6]:port → ipv6 (strip up to the closing bracket; ignore the
        // suffix entirely)
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_owned();
        }
    }
    target.split(':').next().unwrap_or(target).to_owned()
}

/// Build a probe filename guaranteed (with overwhelming probability) not
/// to exist on the target. 64 bits of entropy is enough that even a
/// hostile server can't prearrange a collision.
fn random_probe_name() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("__netraze_probe_{:016x}__", u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_type_decoder_round_trips_known_values() {
        assert_eq!(ShareType::from_raw(0), ShareType::Disk);
        assert_eq!(ShareType::from_raw(1), ShareType::Printer);
        assert_eq!(ShareType::from_raw(2), ShareType::Device);
        assert_eq!(ShareType::from_raw(3), ShareType::Ipc);
        // STYPE_SPECIAL flag set on a disk type → Special variant.
        assert_eq!(ShareType::from_raw(0x8000_0000), ShareType::Special);
        // High flag bits + IPC → still IPC (the special-disk discrimination
        // only matters for the disk subtype).
        assert_eq!(ShareType::from_raw(0x8000_0003), ShareType::Ipc);
    }

    #[test]
    fn share_access_display_strings_match_windows_impl() {
        assert_eq!(ShareAccess::ReadWrite.display_str(), "RW");
        assert_eq!(ShareAccess::Read.display_str(), "R");
        assert_eq!(ShareAccess::NoAccess.display_str(), "NO ACCESS");
    }

    #[test]
    fn host_only_strips_port_suffix() {
        assert_eq!(host_only("dc01.lan"), "dc01.lan");
        assert_eq!(host_only("dc01.lan:445"), "dc01.lan");
        assert_eq!(host_only("10.0.0.5"), "10.0.0.5");
        assert_eq!(host_only("10.0.0.5:1445"), "10.0.0.5");
        assert_eq!(host_only("[fe80::1]:445"), "fe80::1");
        assert_eq!(host_only("[fe80::1]"), "fe80::1");
    }

    #[test]
    fn random_probe_name_is_unique_enough() {
        let a = random_probe_name();
        let b = random_probe_name();
        assert_ne!(a, b);
        assert!(a.starts_with("__netraze_probe_"));
        assert!(a.ends_with("__"));
    }
}
