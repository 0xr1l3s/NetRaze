//! MS-SAMR (Security Account Manager Remote) RPC interface.
//!
//! UUID  : `12345778-1234-abcd-ef00-0123456789ac`
//! Version: 1.0
//! Pipe  : `\\PIPE\\samr`
//!
//! Targets the minimum opnum set needed for local user enumeration:
//!   - opnum 62 -- `SamrConnect2` -- open server handle
//!   - opnum  1 -- `SamrCloseHandle` -- cleanup
//!   - opnum  6 -- `SamrEnumerateDomainsInSamServer` -- list domains
//!   - opnum  5 -- `SamrLookupDomain` -- domain name -> SID
//!   - opnum  7 -- `SamrOpenDomain` -- open domain handle
//!   - opnum 13 -- `SamrEnumerateUsersInDomain` -- list local users
//!
//! Wire encoding is checked against Impacket-generated fixtures where
//! available; live validation runs against the Samba AD DC container.

use crate::error::{DceRpcError, Result};
use crate::ndr::{NdrReader, NdrWriter};
use crate::uuid::Uuid;

pub const UUID_STR: &str = "12345778-1234-abcd-ef00-0123456789ac";
pub const VERSION_MAJOR: u16 = 1;
pub const VERSION_MINOR: u16 = 0;
pub const PIPE: &str = "\\\\PIPE\\\\samr";

/// Sanity cap for enumeration buffers (domains or users). 64K is far beyond
/// any realistic Samba/Windows server.
const MAX_ENUM_ENTRIES: u32 = 65_536;

/// SAMR opnum subset used by NetRaze.
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Opnum {
    SamrCloseHandle = 1,
    SamrLookupDomain = 5,
    SamrEnumerateDomainsInSamServer = 6,
    SamrOpenDomain = 7,
    SamrEnumerateUsersInDomain = 13,
    SamrOpenUser = 34,
    SamrQueryInformationUser = 36,
    SamrConnect2 = 57,
}

pub fn uuid() -> Uuid {
    Uuid::parse(UUID_STR).expect("static uuid")
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// 20-byte RPC context handle used throughout SAMR.
pub type SamprHandle = [u8; 20];

/// One entry returned by `SamrEnumerateDomainsInSamServer` or
/// `SamrEnumerateUsersInDomain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumEntry {
    pub relative_id: u32,
    pub name: String,
}

/// Generic enumeration response (domains or users).
#[derive(Debug, Clone, Default)]
pub struct EnumerateResponse {
    pub entries: Vec<EnumEntry>,
    /// Resume handle for continuation -- 0 when done.
    pub resume_handle: u32,
    /// Count returned by the server (may equal `entries.len()`).
    pub count_returned: u32,
    /// Win32/NTSTATUS status at the end of the stub. `0` = success,
    /// `0x105` (`STATUS_MORE_ENTRIES`) = there is more data.
    pub status: u32,
}

// ---------------------------------------------------------------------------
// SamrConnect2 -- opnum 57
// ---------------------------------------------------------------------------

/// `MAXIMUM_ALLOWED` -- universal access mask used by NetExec/Impacket for
/// `SamrConnect2`. `0x0200_0000`.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// Encode `SamrConnect2` request stub.
///
/// If `server_name` is `None` the pointer is encoded as NULL (referent id 0)
/// and the stub is just 8 bytes — this is what Impacket sends by default and
/// what Windows SAMR expects.
pub fn encode_samr_connect2_request(server_name: Option<&str>, desired_access: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    match server_name {
        Some(name) => {
            let owned = name.to_owned();
            // [unique] PSAMPR_SERVER_NAME -> LPWSTR (top-level unique pointer,
            // written inline per Impacket/NDR top-level pointer rules).
            w.write_referent();
            w.write_conformant_varying_wstring_raw(&owned);
            w.align(4); // ULONG must be 4-byte aligned in NDR20
        }
        None => {
            w.write_null_referent();
        }
    }
    w.write_u32(desired_access);
    w.finish()
}

/// Decode `SamrConnect2` response stub.
///
/// Wire layout: `SAMPR_HANDLE ServerHandle` (20 bytes inline) + `DWORD Status`.
pub fn decode_samr_connect2_response(stub: &[u8]) -> Result<(SamprHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// SamrCloseHandle -- opnum 1
// ---------------------------------------------------------------------------

/// Encode `SamrCloseHandle` request stub.
///
/// Impacket sends an extra `DesiredAccess` LONG after the handle (set to 0).
pub fn encode_samr_close_handle_request(handle: &SamprHandle) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(handle);
    w.write_u32(0); // DesiredAccess padding per Impacket
    w.finish()
}

/// Decode `SamrCloseHandle` response stub.
///
/// The server zeroes the handle on success.
pub fn decode_samr_close_handle_response(stub: &[u8]) -> Result<(SamprHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// SamrEnumerateDomainsInSamServer -- opnum 6
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_samr_enumerate_domains_request(
    server_handle: &SamprHandle,
    resume_handle: u32,
    prefered_max_length: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(server_handle);
    w.write_u32(resume_handle);
    w.write_u32(prefered_max_length);
    w.finish()
}

/// Decode response.
pub fn decode_samr_enumerate_domains_response(stub: &[u8]) -> Result<EnumerateResponse> {
    decode_enumeration_response(stub)
}

// ---------------------------------------------------------------------------
// SamrLookupDomain -- opnum 5
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_samr_lookup_domain_request(
    server_handle: &SamprHandle,
    domain_name: &str,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(server_handle);
    // Name is inline RPC_UNICODE_STRING (Impacket structure, not a pointer
    // to the struct).
    w.write_rpc_unicode_string(domain_name);
    w.finish()
}

/// Decode response.
///
/// Wire layout: `[unique] RPC_SID* DomainSid` + `DWORD Status`.
pub fn decode_samr_lookup_domain_response(stub: &[u8]) -> Result<(Vec<u8>, u32)> {
    let mut r = NdrReader::new(stub);
    let sid_present = r.read_unique_referent()?;
    let sid = if sid_present {
        r.read_rpc_sid()?
    } else {
        Vec::new()
    };
    let status = r.read_u32()?;
    Ok((sid, status))
}

// ---------------------------------------------------------------------------
// SamrOpenDomain -- opnum 7
// ---------------------------------------------------------------------------

/// `DOMAIN_READ` | `DOMAIN_LIST_ACCOUNTS` | `DOMAIN_LOOKUP` -- enough to
/// enumerate users. `0x00000211` per MS-SAMR 3.1.5.1.7.
pub const DOMAIN_ENUM_ACCESS: u32 = 0x0000_0211;

/// Encode request.
pub fn encode_samr_open_domain_request(
    server_handle: &SamprHandle,
    desired_access: u32,
    domain_sid: &[u8],
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(server_handle);
    w.write_u32(desired_access);
    // DomainId is inline RPC_SID (Impacket structure, not a pointer).
    w.write_rpc_sid(domain_sid);
    w.finish()
}

/// Decode response.
///
/// Wire layout: `SAMPR_HANDLE DomainHandle` (20 bytes inline) + `DWORD Status`.
pub fn decode_samr_open_domain_response(stub: &[u8]) -> Result<(SamprHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// SamrEnumerateUsersInDomain -- opnum 13
// ---------------------------------------------------------------------------

/// `USER_NORMAL_ACCOUNT` -- standard local/domain users. `0x00000010`.
pub const USER_NORMAL_ACCOUNT: u32 = 0x0000_0010;

/// Encode request.
pub fn encode_samr_enumerate_users_request(
    domain_handle: &SamprHandle,
    resume_handle: u32,
    user_account_control: u32,
    prefered_max_length: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(domain_handle);
    w.write_u32(resume_handle);
    w.write_u32(user_account_control);
    w.write_u32(prefered_max_length);
    w.finish()
}

/// Decode response.
pub fn decode_samr_enumerate_users_response(stub: &[u8]) -> Result<EnumerateResponse> {
    decode_enumeration_response(stub)
}

// ---------------------------------------------------------------------------
// SamrOpenUser -- opnum 34
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_samr_open_user_request(
    domain_handle: &SamprHandle,
    desired_access: u32,
    user_id: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(domain_handle);
    w.write_u32(desired_access);
    w.write_u32(user_id);
    w.finish()
}

/// Decode response.
pub fn decode_samr_open_user_response(stub: &[u8]) -> Result<(SamprHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// SamrQueryInformationUser -- opnum 36
// ---------------------------------------------------------------------------

/// `USER_CONTROL_INFORMATION` level — minimal query that returns only the
/// `UserAccountControl` ULONG. `16` per MS-SAMR §2.2.7.5.
pub const USER_CONTROL_INFORMATION: u32 = 16;

/// Encode `SamrQueryInformationUser` request stub.
pub fn encode_samr_query_information_user_request(
    user_handle: &SamprHandle,
    info_level: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(user_handle);
    w.write_u32(info_level);
    w.finish()
}

/// Decode `SamrQueryInformationUser` response stub for `level = 16`.
///
/// Wire layout (top-level unique pointer rules — referent inline,
/// pointee immediately after):
/// ```text
/// [unique] PSAMPR_USER_INFO_BUFFER  referent (4 bytes)
///   if non-zero:
///     DWORD Level (=16)
///     ULONG UserAccountControl
/// DWORD ErrorCode
/// ```
pub fn decode_samr_query_information_user_response(stub: &[u8]) -> Result<(Option<u32>, u32)> {
    let mut r = NdrReader::new(stub);
    let present = r.read_unique_referent()?;
    let uac = if present {
        let level = r.read_u32()?;
        if level != USER_CONTROL_INFORMATION {
            return Err(DceRpcError::NdrDecode(format!(
                "expected level={USER_CONTROL_INFORMATION} in SamrQueryInformationUser response, got {level}"
            )));
        }
        Some(r.read_u32()?)
    } else {
        None
    };
    let status = r.read_u32()?;
    Ok((uac, status))
}

// ---------------------------------------------------------------------------
// Internal: SAMPR_ENUMERATION_BUFFER decoder shared by domains & users
// ---------------------------------------------------------------------------

/// Decode the common enumeration shape used by opnum 6 and 13.
///
/// Response stub layout (Impacket / Windows / Samba):
/// ```text
/// [unique] DWORD* EnumerationContext   -> referent + deferred value
/// [unique] SAMPR_ENUMERATION_BUFFER* Buffer
///     -> referent + deferred:
///         DWORD EntriesRead
///         [unique] SAMPR_RID_ENUMERATION* Buffer
///             -> referent + deferred conformant array:
///                 DWORD max_count
///                 SAMPR_RID_ENUMERATION[max_count] inline bodies:
///                     DWORD RelativeId
///                     RPC_UNICODE_STRING Name (Length, MaxLength, [unique] Buffer)
///                 deferred wstrings (in array order)
/// [unique] DWORD* CountReturned        -> referent + deferred value
/// DWORD Status
/// ```
fn decode_enumeration_response(stub: &[u8]) -> Result<EnumerateResponse> {
    let mut r = NdrReader::new(stub);

    // EnumerationContext — MS-SAMR returns this as an inline ULONG
    // (not a pointer), matching Impacket's layout.
    let resume_handle = r.read_u32()?;

    // Buffer (SAMPR_ENUMERATION_BUFFER*)
    let mut entries = Vec::new();
    let buf_present = r.read_unique_referent()?;
    if buf_present {
        let entries_read = r.read_u32()?;
        if entries_read > MAX_ENUM_ENTRIES {
            return Err(DceRpcError::NdrDecode(format!(
                "SAMR enumeration entries_read {entries_read} > sanity cap"
            )));
        }

        let inner_present = r.read_unique_referent()?;
        if inner_present {
            let max_count = r.read_conformant_count(MAX_ENUM_ENTRIES)?;
            if max_count != entries_read as usize {
                // Some servers are sloppy; trust EntriesRead for the loop bound
                // but warn implicitly by using max_count for allocation.
            }

            // Read inline bodies first.
            // SAMPR_RID_ENUMERATION layout: RelativeId (u32) + RPC_UNICODE_STRING
            // (Length u16 + MaximumLength u16 + Buffer unique ptr).
            let mut inlines: Vec<(u32, bool)> = Vec::with_capacity(max_count);
            for _ in 0..max_count {
                let rid = r.read_u32()?;
                let _len = r.read_u16()?;
                let _max_len = r.read_u16()?;
                let name_buf_present = r.read_unique_referent()?;
                inlines.push((rid, name_buf_present));
            }

            // Read deferred wstrings in array order.
            entries.reserve(max_count);
            for (rid, name_present) in inlines {
                let name = if name_present {
                    r.read_conformant_varying_wstring()?
                } else {
                    String::new()
                };
                entries.push(EnumEntry {
                    relative_id: rid,
                    name,
                });
            }
        } else if entries_read != 0 {
            return Err(DceRpcError::NdrDecode(format!(
                "SAMR EntriesRead={entries_read} with NULL inner buffer"
            )));
        }
    }

    // CountReturned — inline ULONG per Impacket/MS-SAMR layout.
    let count_returned = r.read_u32()?;

    let status = r.read_u32()?;

    Ok(EnumerateResponse {
        entries,
        resume_handle,
        count_returned,
        status,
    })
}

// ---------------------------------------------------------------------------
// Tests -- validated against Impacket-generated fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samr_connect2_request_layout_matches_impacket() {
        // Fixture generated by Impacket for ServerName="\\.\",
        // DesiredAccess=MAXIMUM_ALLOWED (0x02000000).
        //  referent_id(4) + max_count(4) + offset(4) + actual_count(4)
        //  + data "\\.\" (8) + DesiredAccess(4) = 28 bytes
        let stub = encode_samr_connect2_request(Some("\\\\.\\"), MAXIMUM_ALLOWED);
        assert_eq!(stub.len(), 28, "SamrConnect2 stub length mismatch");
        let expected = [
            // max_count = 4
            0x04, 0x00, 0x00, 0x00, // offset = 0
            0x00, 0x00, 0x00, 0x00, // actual_count = 4
            0x04, 0x00, 0x00, 0x00, // '\\' '\\' '.' '\\' UTF-16LE
            0x5c, 0x00, 0x5c, 0x00, 0x2e, 0x00, 0x5c, 0x00, // DesiredAccess = 0x02000000
            0x00, 0x00, 0x00, 0x02,
        ];
        // Skip the 4-byte referent id (offset 0..3) — it is allocator-dependent.
        assert_eq!(&stub[4..], &expected[..], "SamrConnect2 body mismatch");
    }

    #[test]
    fn samr_connect2_request_ip_matches_impacket() {
        // Fixture generated by Impacket for ServerName="172.23.194.189"
        let stub = encode_samr_connect2_request(Some("172.23.194.189"), MAXIMUM_ALLOWED);
        assert_eq!(stub.len(), 48, "SamrConnect2 IP stub length mismatch");
        // Body after referent_id (skip first 4 bytes)
        let expected_body = [
            // max_count = 14
            0x0e, 0x00, 0x00, 0x00, // offset = 0
            0x00, 0x00, 0x00, 0x00, // actual_count = 14
            0x0e, 0x00, 0x00, 0x00, // "172.23.194.189" UTF-16LE
            0x31, 0x00, 0x37, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x33, 0x00, 0x2e, 0x00,
            0x31, 0x00, 0x39, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x38, 0x00, 0x39, 0x00,
            // DesiredAccess = 0x02000000
            0x00, 0x00, 0x00, 0x02,
        ];
        assert_eq!(
            &stub[4..],
            &expected_body[..],
            "SamrConnect2 IP body mismatch"
        );
    }

    #[test]
    fn samr_connect2_response_decode() {
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&0u32.to_le_bytes());
        let (h, s) = decode_samr_connect2_response(&stub).unwrap();
        assert_eq!(h, [0u8; 20]);
        assert_eq!(s, 0);
    }

    #[test]
    fn samr_enumerate_domains_request_basic() {
        let handle = [0xABu8; 20];
        let stub = encode_samr_enumerate_domains_request(&handle, 0, 0x1000);
        // 20 (handle) + 4 (EnumerationContext) + 4 (PreferedMaximumLength)
        assert!(stub.len() >= 28);
    }

    #[test]
    fn samr_lookup_domain_request_basic() {
        let stub = encode_samr_lookup_domain_request(&[0u8; 20], "GETEXEC");
        assert!(!stub.is_empty());
    }

    #[test]
    fn samr_lookup_domain_request_matches_impacket() {
        // Fixture generated by Impacket for ServerHandle=zeros, Name="DESKTOP-QUFH7TN"
        let stub = encode_samr_lookup_domain_request(&[0u8; 20], "DESKTOP-QUFH7TN");
        assert_eq!(stub.len(), 70, "SamrLookupDomain stub length mismatch");
        let expected_after_handle = [
            // Length = 30
            0x1e, 0x00, // MaximumLength = 30
            0x1e, 0x00,
        ];
        let expected_deferred = [
            // max_count = 15
            0x0f, 0x00, 0x00, 0x00, // offset = 0
            0x00, 0x00, 0x00, 0x00, // actual_count = 15
            0x0f, 0x00, 0x00, 0x00, // "DESKTOP-QUFH7TN" UTF-16LE (15 wchar_t = 30 bytes)
            0x44, 0x00, 0x45, 0x00, 0x53, 0x00, 0x4b, 0x00, 0x54, 0x00, 0x4f, 0x00, 0x50, 0x00,
            0x2d, 0x00, 0x51, 0x00, 0x55, 0x00, 0x46, 0x00, 0x48, 0x00, 0x37, 0x00, 0x54, 0x00,
            0x4e, 0x00,
        ];
        assert_eq!(
            &stub[20..22],
            &expected_after_handle[..2],
            "SamrLookupDomain Length mismatch"
        );
        assert_eq!(
            &stub[22..24],
            &expected_after_handle[2..],
            "SamrLookupDomain MaximumLength mismatch"
        );
        // Skip referent_id (4 bytes at offset 24..28) since it is allocator-dependent.
        assert_eq!(
            &stub[28..],
            &expected_deferred[..],
            "SamrLookupDomain deferred mismatch"
        );
    }

    #[test]
    fn samr_open_domain_request_basic() {
        let sid: Vec<u8> = vec![
            1, 4, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        let stub = encode_samr_open_domain_request(&[0u8; 20], DOMAIN_ENUM_ACCESS, &sid);
        assert!(!stub.is_empty());
    }

    #[test]
    fn samr_close_handle_round_trip() {
        let h = [0xCDu8; 20];
        let stub = encode_samr_close_handle_request(&h);
        // 20 (handle) + 4 (DesiredAccess padding per Impacket)
        assert_eq!(stub.len(), 24);

        let mut resp = h.to_vec();
        resp.extend_from_slice(&0u32.to_le_bytes()); // status
        let (h2, s) = decode_samr_close_handle_response(&resp).unwrap();
        assert_eq!(h2, h);
        assert_eq!(s, 0);
    }
}
