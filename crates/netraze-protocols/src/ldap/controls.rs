//! LDAP controls (RFC 4511 §4.1.11 + extensions).
//!
//! Phase 1 only needs the paged-results control
//! (`1.2.840.113556.1.4.319`, MS-ADTS §4.1.11.2) — mandatory for any
//! production LDAP search because AD caps results at 1000 entries without it.

use super::message::{Control, PagedResultsValue};
use rasn::types::OctetString;

// ── Paged results ──────────────────────────────────────────────────────────

/// OID for the simple paged-results control (Microsoft 1.2.840.113556.1.4.319).
pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

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
}
