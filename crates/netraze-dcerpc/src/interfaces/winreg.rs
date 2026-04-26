//! MS-RRP (Windows Remote Registry Protocol) interface.
//!
//! UUID  : `338cd001-2244-31f1-aaaa-900038001003`
//! Version: 1.0
//! Pipe  : `\\PIPE\\winreg`
//!
//! Subset needed for SAM / SYSTEM hive extraction via `BaseRegSaveKey`:
//!   - opnum  2 — `OpenLocalMachine`
//!   - opnum  5 — `BaseRegCloseKey`
//!   - opnum 15 — `BaseRegOpenKey`
//!   - opnum 16 — `BaseRegQueryInfoKey`  (bootkey class-name extraction)
//!   - opnum 20 — `BaseRegSaveKey`       (save hive to remote file)

use crate::error::Result;
use crate::ndr::{NdrReader, NdrWriter};
use crate::uuid::Uuid;

pub const UUID_STR: &str = "338cd001-2244-31f1-aaaa-900038001003";
pub const VERSION_MAJOR: u16 = 1;
pub const VERSION_MINOR: u16 = 0;
pub const PIPE: &str = "\\\\PIPE\\\\winreg";

/// `KEY_ALL_ACCESS` — standard mask for registry operations. `0x000F003F`.
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Opnum {
    OpenLocalMachine = 2,
    BaseRegCloseKey = 5,
    BaseRegOpenKey = 15,
    BaseRegQueryInfoKey = 16,
    BaseRegSaveKey = 20,
}

pub fn uuid() -> Uuid {
    Uuid::parse(UUID_STR).expect("static uuid")
}

/// 20-byte registry context handle (same shape as SAMR context handle).
pub type RegHandle = [u8; 20];

// ---------------------------------------------------------------------------
// OpenLocalMachine -- opnum 2
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_open_local_machine_request(sam_desired: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    // [unique] PREGISTRY_SERVER_NAME -- NULL per Impacket
    w.write_null_referent();
    w.write_u32(sam_desired);
    w.finish()
}

/// Decode response.
pub fn decode_open_local_machine_response(stub: &[u8]) -> Result<(RegHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// BaseRegCloseKey -- opnum 5
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_base_reg_close_key_request(handle: &RegHandle) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(handle);
    w.finish()
}

/// Decode response.
pub fn decode_base_reg_close_key_response(stub: &[u8]) -> Result<(RegHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// BaseRegOpenKey -- opnum 15
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_base_reg_open_key_request(
    hkey: &RegHandle,
    sub_key: &str,
    dw_options: u32,
    sam_desired: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(hkey);
    w.write_rpc_unicode_string(sub_key);
    w.write_u32(dw_options);
    w.write_u32(sam_desired);
    w.finish()
}

/// Decode response.
pub fn decode_base_reg_open_key_response(stub: &[u8]) -> Result<(RegHandle, u32)> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_context_handle()?;
    let status = r.read_u32()?;
    Ok((handle, status))
}

// ---------------------------------------------------------------------------
// BaseRegQueryInfoKey -- opnum 16
// ---------------------------------------------------------------------------

/// Response data we actually care about: the class-name string.
#[derive(Debug, Clone, Default)]
pub struct QueryInfoKeyResponse {
    pub class_name: String,
    pub status: u32,
}

/// Encode request.
pub fn encode_base_reg_query_info_key_request(hkey: &RegHandle) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(hkey);
    w.finish()
}

/// Decode response.
///
/// Impacket lays the response as inline fields (no extra pointer indirection
/// on `lpClassOut`). Layout:
/// ```text
/// RPC_UNICODE_STRING lpClassOut   (Length, MaxLength, [unique] Data ptr)
/// DWORD              lpcSubKeys
/// DWORD              lpcbMaxSubKeyLen
/// DWORD              lpcbMaxClassLen
/// DWORD              lpcValues
/// DWORD              lpcbMaxValueNameLen
/// DWORD              lpcbMaxValueLen
/// DWORD              lpcbSecurityDescriptor
/// FILETIME           lpftLastWriteTime  (dwLowDateTime, dwHighDateTime)
/// error_status_t     ErrorCode
/// ```
pub fn decode_base_reg_query_info_key_response(stub: &[u8]) -> Result<QueryInfoKeyResponse> {
    let mut r = NdrReader::new(stub);

    let class_name = r.read_rpc_unicode_string()?;
    let _lpc_sub_keys = r.read_u32()?;
    let _lpc_max_sub_key_len = r.read_u32()?;
    let _lpc_max_class_len = r.read_u32()?;
    let _lpc_values = r.read_u32()?;
    let _lpc_max_value_name_len = r.read_u32()?;
    let _lpc_max_value_len = r.read_u32()?;
    let _lpcb_security_descriptor = r.read_u32()?;
    let _ft_low = r.read_u32()?;
    let _ft_high = r.read_u32()?;
    let status = r.read_u32()?;

    Ok(QueryInfoKeyResponse { class_name, status })
}

// ---------------------------------------------------------------------------
// BaseRegSaveKey -- opnum 20
// ---------------------------------------------------------------------------

/// Encode request.
pub fn encode_base_reg_save_key_request(hkey: &RegHandle, file_path: &str) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.write_context_handle(hkey);
    w.write_rpc_unicode_string(file_path);
    // [unique] PRPC_SECURITY_ATTRIBUTES -- NULL
    w.write_null_referent();
    w.finish()
}

/// Decode response.
pub fn decode_base_reg_save_key_response(stub: &[u8]) -> Result<u32> {
    let mut r = NdrReader::new(stub);
    let status = r.read_u32()?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_local_machine_request_basic() {
        let stub = encode_open_local_machine_request(KEY_ALL_ACCESS);
        // null referent (4) + samDesired (4) = 8
        assert_eq!(stub.len(), 8);
    }

    #[test]
    fn open_local_machine_response_decode() {
        let mut stub = vec![0xabu8; 20];
        stub.extend_from_slice(&0u32.to_le_bytes());
        let (h, s) = decode_open_local_machine_response(&stub).unwrap();
        assert_eq!(h, [0xabu8; 20]);
        assert_eq!(s, 0);
    }

    #[test]
    fn base_reg_open_key_request_basic() {
        let stub = encode_base_reg_open_key_request(
            &[0u8; 20],
            "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
            0,
            KEY_ALL_ACCESS,
        );
        assert!(!stub.is_empty());
        assert!(stub.len() >= 20 + 8 + 4 + 4); // handle + unicode header + ptr + opts + access
    }

    #[test]
    fn base_reg_query_info_key_response_decode() {
        // Minimal synthetic response: empty class + zeros + status=0
        let mut stub = Vec::new();
        // RPC_UNICODE_STRING empty: len=0, maxlen=0, null referent
        stub.extend_from_slice(&0u16.to_le_bytes());
        stub.extend_from_slice(&0u16.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        // 7 DWORDs + FILETIME (2 DWORDs)
        for _ in 0..9 {
            stub.extend_from_slice(&0u32.to_le_bytes());
        }
        stub.extend_from_slice(&0u32.to_le_bytes()); // status

        let resp = decode_base_reg_query_info_key_response(&stub).unwrap();
        assert_eq!(resp.class_name, "");
        assert_eq!(resp.status, 0);
    }

    #[test]
    fn base_reg_save_key_request_basic() {
        let stub = encode_base_reg_save_key_request(&[0u8; 20], "Windows\\Temp\\sam_test.save");
        assert!(!stub.is_empty());
    }
}
