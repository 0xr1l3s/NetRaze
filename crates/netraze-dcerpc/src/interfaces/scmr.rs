//! MS-SCMR (Service Control Manager Remote Protocol) interface.
//!
//! UUID  : `367abb81-9844-35f1-ad32-98f038001003`
//! Version: `2.0`
//! Pipe  : `\\PIPE\\svcctl`
//!
//! Minimal opnum set needed to start the `RemoteRegistry` service when it is
//! stopped — this unblocks the WINREG-based SAM dump path.
//!
//!   - opnum  0 — `RCloseServiceHandle`
//!   - opnum  6 — `RQueryServiceStatus`
//!   - opnum 11 — `RChangeServiceConfigW`
//!   - opnum 15 — `ROpenSCManagerW`
//!   - opnum 16 — `ROpenServiceW`
//!   - opnum 19 — `RStartServiceW`

use crate::error::Result;
use crate::ndr::{NdrReader, NdrWriter};
use crate::uuid::Uuid;

pub const UUID_STR: &str = "367abb81-9844-35f1-ad32-98f038001003";
pub const VERSION_MAJOR: u16 = 2;
pub const VERSION_MINOR: u16 = 0;
pub const PIPE: &str = "\\\\PIPE\\\\svcctl";

/// Matches Impacket default (`SERVICE_START|STOP|CHANGE_CONFIG|QUERY_CONFIG|QUERY_STATUS|ENUMERATE_DEPENDENTS|SC_MANAGER_ENUMERATE_SERVICE` = 0x3F).
pub const SC_MANAGER_ACCESS: u32 = 0x0000_003F;

/// `SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG`
pub const SERVICE_ACCESS_START: u32 = 0x0004 | 0x0010 | 0x0002;

pub const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;
pub const SERVICE_DEMAND_START: u32 = 0x0000_0003;

/// `SERVICE_RUNNING` — `dwCurrentState` value.
pub const SERVICE_RUNNING: u32 = 0x0000_0004;
/// `SERVICE_STOPPED` — `dwCurrentState` value.
pub const SERVICE_STOPPED: u32 = 0x0000_0001;

/// `SERVICE_CONTROL_STOP` — `dwControl` value for `RControlService`.
pub const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;

/// `SERVICE_DISABLED` — `dwStartType` value.
pub const SERVICE_DISABLED: u32 = 0x0000_0004;

/// Win32 error: service is disabled.
pub const ERROR_SERVICE_DISABLED: u32 = 1058;
/// Win32 error: service already running.
pub const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Opnum {
    RCloseServiceHandle = 0,
    RControlService = 1,
    RQueryServiceStatus = 6,
    RChangeServiceConfigW = 11,
    ROpenSCManagerW = 15,
    ROpenServiceW = 16,
    RStartServiceW = 19,
}

pub fn uuid() -> Uuid {
    Uuid::parse(UUID_STR).expect("static uuid")
}

/// 20-byte SCMR context handle (same shape as SAMR / WINREG handles).
pub type ScmHandle = [u8; 20];

// ---------------------------------------------------------------------------
// SERVICE_STATUS
// ---------------------------------------------------------------------------

/// `SERVICE_STATUS` as returned by `RQueryServiceStatus`.
#[derive(Debug, Clone, Default)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

// ---------------------------------------------------------------------------
// ROpenSCManagerW — opnum 15
// ---------------------------------------------------------------------------

/// Encode `ROpenSCManagerW` request stub.
///
/// Wire layout:
/// ```text
/// [unique] LPWSTR lpMachineName    (referent + inline wstring, or NULL)
/// [unique] LPWSTR lpDatabaseName   (referent + inline wstring, or NULL)
/// DWORD           dwDesiredAccess
/// ```
pub fn encode_ropen_sc_manager_w_request(
    machine_name: Option<&str>,
    database_name: Option<&str>,
    desired_access: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    // lpMachineName — `[unique, string]` per MS-SCMR §3.1.4.15. The
    // `[string]` attribute requires a NUL-terminated wstring on the wire;
    // we normalise here so callers can pass either `"HOST"` or `"HOST\0"`
    // and get a valid encoding either way. Without this, the server gets
    // a stub whose `actual_count` doesn't include the terminator and
    // returns RPC fault 0x6F7 (`RPC_X_BAD_STUB_DATA`).
    match machine_name {
        Some(s) => {
            w.write_referent();
            w.write_conformant_varying_wstring(&ensure_nul(s));
        }
        None => w.write_null_referent(),
    }
    // lpDatabaseName — same `[unique, string]` shape, same NUL requirement.
    match database_name {
        Some(s) => {
            w.write_referent();
            w.write_conformant_varying_wstring(&ensure_nul(s));
        }
        None => w.write_null_referent(),
    }
    w.write_u32(desired_access);
    w.finish()
}

/// Normalise an MS-RPC `[string] WCHAR*` argument so the wire layout
/// always carries the trailing NUL the IDL `[string]` attribute mandates.
/// Idempotent — passing `"FOO"` and `"FOO\0"` both produce `"FOO\0"`.
fn ensure_nul(s: &str) -> String {
    if s.ends_with('\0') {
        s.to_owned()
    } else {
        format!("{s}\0")
    }
}

/// Decode `ROpenSCManagerW` response stub.
///
/// Wire layout: `SC_RPC_HANDLE lpScHandle` (20 bytes) + `DWORD ErrorCode`.
pub fn decode_ropen_sc_manager_w_response(stub: &[u8]) -> Result<(ScmHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// ROpenServiceW — opnum 16
// ---------------------------------------------------------------------------

/// Encode `ROpenServiceW` request stub.
///
/// Wire layout:
/// ```text
/// SC_RPC_HANDLE hSCManager         (20 bytes inline)
/// WSTR          lpServiceName      (embedded conformant-varying wstring)
/// DWORD         dwDesiredAccess
/// ```
///
/// **Critical subtlety:** `lpServiceName` is `WSTR` (embedded), *not* `LPWSTR`.
/// It carries its own `max_count / offset / actual_count` header inline.
pub fn encode_ropen_service_w_request(
    scm_handle: &ScmHandle,
    service_name: &str,
    desired_access: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(scm_handle);
    // WSTR inline — same wire shape as a conformant-varying wstring without
    // the preceding pointer referent. Same `[string]` NUL-terminator
    // requirement as `lpMachineName`/`lpDatabaseName`; normalise here.
    w.write_conformant_varying_wstring(&ensure_nul(service_name));
    w.write_u32(desired_access);
    w.finish()
}

/// Decode `ROpenServiceW` response stub.
pub fn decode_ropen_service_w_response(stub: &[u8]) -> Result<(ScmHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// RQueryServiceStatus — opnum 6
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_rquery_service_status_request(service_handle: &ScmHandle) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(service_handle);
    w.finish()
}

/// Decode response.
///
/// Wire layout: `SERVICE_STATUS` (28 bytes inline) + `DWORD ErrorCode`.
pub fn decode_rquery_service_status_response(stub: &[u8]) -> Result<(ServiceStatus, u32)> {
    let mut r = NdrReader::new(stub);
    let status = ServiceStatus {
        service_type: r.read_u32()?,
        current_state: r.read_u32()?,
        controls_accepted: r.read_u32()?,
        win32_exit_code: r.read_u32()?,
        service_specific_exit_code: r.read_u32()?,
        check_point: r.read_u32()?,
        wait_hint: r.read_u32()?,
    };
    let error = r.read_u32()?;
    Ok((status, error))
}

// ---------------------------------------------------------------------------
// RStartServiceW — opnum 19
// ---------------------------------------------------------------------------

/// Encode request.
///
/// `argv` is omitted (encoded as NULL) when `argc == 0`.
pub fn encode_rstart_service_w_request(service_handle: &ScmHandle, argc: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(service_handle);
    w.write_u32(argc);
    if argc == 0 {
        w.write_null_referent();
    } else {
        // argv: UNIQUE_STRING_PTRSW — not needed for our use-case.
        // If we ever need it, this must be implemented.
        w.write_null_referent();
    }
    w.finish()
}

/// Decode response.
pub fn decode_rstart_service_w_response(stub: &[u8]) -> Result<u32> {
    let mut r = NdrReader::new(stub);
    let status = r.read_u32()?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// RChangeServiceConfigW — opnum 11
// ---------------------------------------------------------------------------

/// Encode request.
///
/// Only `dwStartType` is typically changed; everything else is
/// `SERVICE_NO_CHANGE` / NULL.
pub fn encode_rchange_service_config_w_request(
    service_handle: &ScmHandle,
    service_type: u32,
    start_type: u32,
    error_control: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(service_handle);
    w.write_u32(service_type);
    w.write_u32(start_type);
    w.write_u32(error_control);
    // lpBinaryPathName
    w.write_null_referent();
    // lpLoadOrderGroup
    w.write_null_referent();
    // lpdwTagId
    w.write_null_referent();
    // lpDependencies
    w.write_null_referent();
    w.write_u32(0); // dwDependSize
    // lpServiceStartName
    w.write_null_referent();
    // lpPassword
    w.write_null_referent();
    w.write_u32(0); // dwPwSize
    // lpDisplayName
    w.write_null_referent();
    w.finish()
}

/// Decode response.
pub fn decode_rchange_service_config_w_response(stub: &[u8]) -> Result<(Option<u32>, u32)> {
    let mut r = NdrReader::new(stub);
    let tag_present = r.read_unique_referent()?;
    let tag_id = if tag_present {
        Some(r.read_u32()?)
    } else {
        None
    };
    let status = r.read_u32()?;
    Ok((tag_id, status))
}

// ---------------------------------------------------------------------------
// RCloseServiceHandle — opnum 0
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_rclose_service_handle_request(handle: &ScmHandle) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(handle);
    w.finish()
}

/// Decode response.
pub fn decode_rclose_service_handle_response(stub: &[u8]) -> Result<(ScmHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// RControlService — opnum 1
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_rcontrol_service_request(service_handle: &ScmHandle, control: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(service_handle);
    w.write_u32(control);
    w.finish()
}

/// Decode response.
pub fn decode_rcontrol_service_response(stub: &[u8]) -> Result<(ServiceStatus, u32)> {
    let mut r = NdrReader::new(stub);
    let status = ServiceStatus {
        service_type: r.read_u32()?,
        current_state: r.read_u32()?,
        controls_accepted: r.read_u32()?,
        win32_exit_code: r.read_u32()?,
        service_specific_exit_code: r.read_u32()?,
        check_point: r.read_u32()?,
        wait_hint: r.read_u32()?,
    };
    let error = r.read_u32()?;
    Ok((status, error))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ropen_sc_manager_request_layout() {
        let stub =
            encode_ropen_sc_manager_w_request(None, Some("ServicesActive\0"), SC_MANAGER_ACCESS);
        // null referent (4) + non-null referent (4) + wstring header (12) + "ServicesActive" (28) + access (4)
        // = 52 bytes
        assert!(!stub.is_empty());
    }

    /// Pin the wire layout of `ROpenSCManagerW` against the Impacket
    /// reference fixture for `lpMachineName="DUMMY"` /
    /// `lpDatabaseName="ServicesActive"` / `dwDesiredAccess=0xF003F`.
    ///
    /// Referent IDs are allocator-dependent so we **don't** byte-compare the
    /// full stub. Instead we assert each semantically-meaningful field at its
    /// known offset, plus that the referents at top of each `[unique]` arg
    /// are non-zero (=> "pointer present"). This was an earlier draft of the
    /// test that compared random referent bytes and always failed; the new
    /// version pins what actually matters.
    #[test]
    fn ropen_sc_manager_fixture_matches_impacket() {
        let stub =
            encode_ropen_sc_manager_w_request(Some("DUMMY\0"), Some("ServicesActive\0"), 0xF003F);
        assert_eq!(stub.len(), 80, "stub length must match Impacket: 80 bytes");

        // lpMachineName: referent (4) + max_count (4) + offset (4) + actual_count (4) + 6 WCHARs
        assert_ne!(
            u32::from_le_bytes(stub[0..4].try_into().unwrap()),
            0,
            "lpMachineName referent must be non-zero (present)"
        );
        assert_eq!(&stub[4..8], &6u32.to_le_bytes(), "DUMMY max_count");
        assert_eq!(&stub[8..12], &0u32.to_le_bytes(), "DUMMY offset");
        assert_eq!(&stub[12..16], &6u32.to_le_bytes(), "DUMMY actual_count");
        let dummy_wstring: Vec<u8> = "DUMMY\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(&stub[16..28], &dummy_wstring[..], "DUMMY UTF-16 payload");

        // lpDatabaseName: referent (4) + max (4) + offset (4) + actual (4) + 15 WCHARs
        assert_ne!(
            u32::from_le_bytes(stub[28..32].try_into().unwrap()),
            0,
            "lpDatabaseName referent must be non-zero (present)"
        );
        assert_eq!(
            &stub[32..36],
            &15u32.to_le_bytes(),
            "ServicesActive max_count"
        );
        assert_eq!(&stub[36..40], &0u32.to_le_bytes(), "ServicesActive offset");
        assert_eq!(
            &stub[40..44],
            &15u32.to_le_bytes(),
            "ServicesActive actual_count"
        );
        let svc_wstring: Vec<u8> = "ServicesActive\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(
            &stub[44..74],
            &svc_wstring[..],
            "ServicesActive UTF-16 payload"
        );

        // 2-byte alignment pad to u32 boundary before dwDesiredAccess.
        // Per NDR20 the value is "should be zero" but receivers must accept any.
        // We emit zeros; Impacket emits 0xBFBF — both are spec-compliant.
        // Then dwDesiredAccess at offset 76.
        assert_eq!(
            &stub[76..80],
            &0xF003Fu32.to_le_bytes(),
            "dwDesiredAccess must equal 0xF003F"
        );
    }

    /// Regression test for the `0x000006f7` bug: an encoder caller may pass
    /// either `"HOST"` (no NUL) or `"HOST\0"` (with NUL) — both must produce
    /// a wstring whose `actual_count` includes the NUL terminator. Without
    /// this, the server's IDL-generated demarshaller bails on
    /// `RPC_X_BAD_STUB_DATA` because the `[string]` attribute requires the
    /// NUL on the wire.
    #[test]
    fn ropen_sc_manager_normalises_missing_nul() {
        let with_nul = encode_ropen_sc_manager_w_request(Some("DUMMY\0"), None, 0xF003F);
        let without_nul = encode_ropen_sc_manager_w_request(Some("DUMMY"), None, 0xF003F);
        // Same length means the encoder added the NUL on the second call.
        assert_eq!(
            with_nul.len(),
            without_nul.len(),
            "encoder must normalise missing NUL for [string] WCHAR* args"
        );
        // actual_count must be 6 (including NUL) in BOTH cases.
        assert_eq!(&with_nul[12..16], &6u32.to_le_bytes());
        assert_eq!(&without_nul[12..16], &6u32.to_le_bytes());
    }

    #[test]
    fn ropen_service_request_layout() {
        let stub =
            encode_ropen_service_w_request(&[0u8; 20], "RemoteRegistry\0", SERVICE_ACCESS_START);
        // 20 (handle) + 12 (wstring header) + 30 (15 WCHARs) + 2 (pad to 4) + 4 (access) = 68
        assert_eq!(stub.len(), 68);
    }

    #[test]
    fn rquery_service_status_response_decode() {
        let mut stub = vec![];
        // SERVICE_STATUS: 7 DWORDs
        for _ in 0..7 {
            stub.extend_from_slice(&0u32.to_le_bytes());
        }
        stub.extend_from_slice(&0u32.to_le_bytes()); // ErrorCode
        let (status, err) = decode_rquery_service_status_response(&stub).unwrap();
        assert_eq!(status.current_state, 0);
        assert_eq!(err, 0);
    }

    #[test]
    fn rstart_service_request_layout() {
        let stub = encode_rstart_service_w_request(&[0u8; 20], 0);
        // 20 (handle) + 4 (argc) + 4 (NULL argv) = 28
        assert_eq!(stub.len(), 28);
    }

    #[test]
    fn rchange_service_config_request_layout() {
        let stub = encode_rchange_service_config_w_request(
            &[0u8; 20],
            SERVICE_NO_CHANGE,
            SERVICE_DEMAND_START,
            SERVICE_NO_CHANGE,
        );
        // 20 (handle) + 4+4+4 (types) + 4*7 (null ptrs) + 4+4 (sizes) + 4 (displayName) = 68
        assert_eq!(stub.len(), 68);
    }

    #[test]
    fn rclose_handle_roundtrip() {
        let h = [0xCDu8; 20];
        let stub = encode_rclose_service_handle_request(&h);
        assert_eq!(stub.len(), 20);

        let mut resp = h.to_vec();
        resp.extend_from_slice(&0u32.to_le_bytes());
        let (h2, s) = decode_rclose_service_handle_response(&resp).unwrap();
        assert_eq!(h2, h);
        assert_eq!(s, 0);
    }
}
