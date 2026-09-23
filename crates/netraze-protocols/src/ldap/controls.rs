//! LDAP controls (RFC 4511 §4.1.11 + extensions).
//!
//! Paged results keep directory searches below AD's ordinary 1000-object
//! response limit. BloodHound CE collection additionally requests DACL/owner
//! security descriptor fields and deleted objects using Microsoft's controls.

use super::message::{Control, PagedResultsValue};
use rasn::types::OctetString;

// ── Paged results ──────────────────────────────────────────────────────────

/// OID for the simple paged-results control (Microsoft 1.2.840.113556.1.4.319).
pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

/// Microsoft LDAP_SERVER_SD_FLAGS_OID (MS-ADTS §3.1.1.3.4.1.11).
pub const OID_SECURITY_DESCRIPTOR_FLAGS: &str = "1.2.840.113556.1.4.801";

/// Microsoft LDAP_SERVER_SHOW_DELETED_OID (MS-ADTS §3.1.1.3.4.1.14).
pub const OID_SHOW_DELETED: &str = "1.2.840.113556.1.4.417";

/// Build a `Control` for a paged-results request.
pub(crate) fn paged_results_control(size: u32, cookie: &[u8]) -> Result<Control, String> {
    let val = PagedResultsValue {
        size,
        cookie: OctetString::from(cookie.to_vec()),
    };
    let encoded = rasn::ber::encode(&val).map_err(|error| error.to_string())?;
    Ok(Control::new(
        OctetString::from(OID_PAGED_RESULTS.as_bytes().to_vec()),
        false,
        Some(OctetString::from(encoded)),
    ))
}

/// Request owner, DACL, and group information in `nTSecurityDescriptor`.
///
/// The value is BER `SEQUENCE { INTEGER 5 }`, where `5` is
/// `OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION`. This matches the
/// RustHound-CE collector and deliberately omits SACL data, which ordinarily
/// requires elevated directory privileges.
pub(crate) fn security_descriptor_flags_control() -> Control {
    Control::new(
        OctetString::from(OID_SECURITY_DESCRIPTOR_FLAGS.as_bytes().to_vec()),
        true,
        Some(OctetString::from(vec![0x30, 0x03, 0x02, 0x01, 0x05])),
    )
}

/// Include tombstoned/deleted directory objects when the server permits it.
pub(crate) fn show_deleted_control() -> Control {
    Control::new(
        OctetString::from(OID_SHOW_DELETED.as_bytes().to_vec()),
        false,
        None,
    )
}

/// Decode the paged-results cookie from a control value.
pub(crate) fn decode_paged_cookie(value: &[u8]) -> Result<Vec<u8>, String> {
    let val = rasn::ber::decode::<PagedResultsValue>(value).map_err(|error| error.to_string())?;
    Ok(val.cookie.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_value_matches_the_ber_fixture() {
        let control = paged_results_control(1000, &[]).unwrap();
        assert_eq!(
            control.control_value.as_deref(),
            Some([0x30, 0x06, 0x02, 0x02, 0x03, 0xe8, 0x04, 0x00].as_slice())
        );
    }

    #[test]
    fn paged_cookie_round_trips_binary_data() {
        let control = paged_results_control(1000, &[0, 0xff, 1]).unwrap();
        assert_eq!(
            decode_paged_cookie(control.control_value.as_deref().unwrap()).unwrap(),
            [0, 0xff, 1]
        );
    }

    #[test]
    fn security_descriptor_flags_match_rusthound_ce() {
        let control = security_descriptor_flags_control();
        assert_eq!(
            control.control_type.as_ref(),
            OID_SECURITY_DESCRIPTOR_FLAGS.as_bytes()
        );
        assert!(control.criticality);
        assert_eq!(
            control.control_value.as_deref(),
            Some([0x30, 0x03, 0x02, 0x01, 0x05].as_slice())
        );
    }

    #[test]
    fn show_deleted_is_non_critical_and_valueless() {
        let control = show_deleted_control();
        assert_eq!(control.control_type.as_ref(), OID_SHOW_DELETED.as_bytes());
        assert!(!control.criticality);
        assert!(control.control_value.is_none());
    }
}
