//! MS-SRVS (Server Service) RPC interface.
//!
//! UUID  : `4b324fc8-1670-01d3-1278-5a47bf6ee188`
//! Version: 3.0
//! Pipe  : `\PIPE\srvsvc`
//!
//! We target the minimum opnum set the rest of getexec actually needs:
//!   - opnum 15 — `NetrShareEnum` — enumerate shares
//!   - opnum 16 — `NetrServerGetInfo` — hostname + OS string
//!
//! Phase 1 ships the interface metadata and the typed request/response
//! structs. The full encode/decode impls land in Phase 2 paired with the
//! first live test against a Samba docker image.

use crate::ndr::{NdrReader, NdrWriter};
use crate::uuid::Uuid;

pub const UUID_STR: &str = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
pub const VERSION_MAJOR: u16 = 3;
pub const VERSION_MINOR: u16 = 0;
pub const PIPE: &str = "\\PIPE\\srvsvc";

/// Opnum table. MS-SRVS §3.1.4.
#[repr(u16)]
pub enum Opnum {
    NetrShareEnum = 15,
    NetrServerGetInfo = 21,
}

pub fn uuid() -> Uuid {
    Uuid::parse(UUID_STR).expect("static uuid")
}

// ---------------------------------------------------------------------------
// NetrShareEnum — opnum 15
// ---------------------------------------------------------------------------

/// Info-level 1 (the one we actually use): name + type + remark per share.
#[derive(Debug, Clone, Default)]
pub struct ShareInfo1 {
    pub netname: String,
    pub shi1_type: u32,
    pub remark: String,
}

#[derive(Debug, Clone, Default)]
pub struct NetrShareEnumResponse {
    pub shares: Vec<ShareInfo1>,
    /// Total server-side share count (may exceed `shares.len()` if the
    /// server truncated due to `PreferedMaximumLength`).
    pub total_entries: u32,
    /// Resume handle for continuation — 0 if the enumeration is done.
    pub resume_handle: u32,
    /// Server status (0 = success, ERROR_MORE_DATA = 234, …).
    pub status: u32,
}

/// Build the NDR stub for a `NetrShareEnum(level=1)` request.
///
/// Layout (MS-SRVS §3.1.4.8):
/// ```text
/// [unique, string] WCHAR* ServerName       ; e.g. "\\\\SERVER"
/// DWORD            Level                    ; 1
/// SHARE_ENUM_STRUCT ShareEnum
///   DWORD Level = 1
///   union SHARE_ENUM_UNION
///     case 1: SHARE_INFO_1_CONTAINER { DWORD count; SHARE_INFO_1* buf; }
///       -> on request side: count=0, buf=NULL
/// DWORD            PreferedMaximumLength    ; 0xFFFFFFFF (as much as possible)
/// DWORD*           ResumeHandle (referent + value) ; 0
/// ```
///
/// Phase 1: skeleton only. The full encoder — including the tricky
/// deferred-pointer layout for `ServerName` — lands in Phase 2.
pub fn encode_netr_share_enum_request(
    server_name: &str,
    prefered_max_length: u32,
    resume_handle: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();

    // ServerName: [unique, string] WCHAR* — referent_id then deferred
    // conformant-varying string.
    w.write_referent();
    w.write_conformant_varying_wstring(server_name);

    // Level
    w.write_u32(1);

    // SHARE_ENUM_STRUCT: Level=1, then a tagged-union switch.
    w.write_u32(1);
    // Union tag (matches Level).
    w.write_u32(1);
    // SHARE_INFO_1_CONTAINER { DWORD count=0; SHARE_INFO_1* buf=NULL; }
    w.write_u32(0);
    w.write_null_referent();

    // PreferedMaximumLength
    w.write_u32(prefered_max_length);

    // ResumeHandle: [unique] DWORD*. Windows always sends non-NULL.
    w.write_referent();
    w.write_u32(resume_handle);

    w.into_vec()
}

/// Decode the stub of a NetrShareEnum response. Phase 1 only parses the
/// *tail* (`TotalEntries`, `ResumeHandle`, `status`) so we can exercise the
/// PDU plumbing end-to-end; the full SHARE_INFO_1 array decode is a Phase 2
/// task requiring the deferred-pointer walker.
pub fn decode_netr_share_enum_response_tail(stub: &[u8]) -> crate::Result<NetrShareEnumResponse> {
    // Temporary implementation: skip straight to the last three u32s. This
    // is ONLY correct when the server returned 0 shares and level=1 with a
    // NULL container pointer (a common happy-path test case).
    //
    // When the array decoder lands we'll replace the whole body.
    if stub.len() < 12 {
        return Err(crate::error::DceRpcError::truncated(12, stub.len()));
    }
    let tail = &stub[stub.len() - 12..];
    let mut r = NdrReader::new(tail);
    let total = r.read_u32()?;
    let resume = r.read_u32()?;
    let status = r.read_u32()?;
    Ok(NetrShareEnumResponse {
        shares: Vec::new(),
        total_entries: total,
        resume_handle: resume,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_uuid_parses() {
        let u = uuid();
        assert_eq!(format!("{u}"), UUID_STR);
    }

    #[test]
    fn request_stub_is_not_empty() {
        let stub = encode_netr_share_enum_request("\\\\SERVER", 0xFFFF_FFFF, 0);
        assert!(stub.len() > 16, "stub unreasonably small: {}", stub.len());
        // First 4 bytes are the ServerName referent id — non-zero.
        let referent = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
        assert_ne!(referent, 0);
    }

    #[test]
    fn response_tail_decoder_happy_path() {
        // Synthetic: 3 u32s = total_entries=0, resume=0, status=0
        let mut stub = vec![0u8; 20]; // >= 12 so prefix is ignored
        let n = stub.len();
        stub[n - 12..n - 8].copy_from_slice(&0u32.to_le_bytes());
        stub[n - 8..n - 4].copy_from_slice(&0u32.to_le_bytes());
        stub[n - 4..n].copy_from_slice(&0u32.to_le_bytes());
        let r = decode_netr_share_enum_response_tail(&stub).unwrap();
        assert_eq!(r.total_entries, 0);
        assert_eq!(r.resume_handle, 0);
        assert_eq!(r.status, 0);
        assert!(r.shares.is_empty());
    }
}
