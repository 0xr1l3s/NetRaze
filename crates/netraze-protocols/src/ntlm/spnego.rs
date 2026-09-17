//! Strict, length-checked SPNEGO encoding and decoding (RFC 4178).

use super::message::NtlmError;

const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLMSSP_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    AcceptCompleted,
    AcceptIncomplete,
    Reject,
    RequestMic,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegTokenResp {
    pub state: Option<NegState>,
    pub response_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

#[must_use]
pub fn ntlm_mech_types_der() -> Vec<u8> {
    tlv(0x30, NTLMSSP_OID)
}

#[must_use]
pub fn wrap_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
    let mech_types = tlv(0xa0, &ntlm_mech_types_der());
    let request_token = tlv(0xa2, &tlv(0x04, ntlmssp));
    let mut sequence = mech_types;
    sequence.extend_from_slice(&request_token);
    let neg_token_init = tlv(0xa0, &tlv(0x30, &sequence));
    let mut initial_context = SPNEGO_OID.to_vec();
    initial_context.extend_from_slice(&neg_token_init);
    tlv(0x60, &initial_context)
}

#[must_use]
pub fn wrap_spnego_resp(ntlmssp: &[u8]) -> Vec<u8> {
    wrap_spnego_resp_with_mic(ntlmssp, None)
}

#[must_use]
pub fn wrap_spnego_resp_with_mic(ntlmssp: &[u8], mic: Option<&[u8]>) -> Vec<u8> {
    let mut fields = tlv(0xa2, &tlv(0x04, ntlmssp));
    if let Some(mic) = mic {
        fields.extend_from_slice(&tlv(0xa3, &tlv(0x04, mic)));
    }
    tlv(0xa1, &tlv(0x30, &fields))
}

pub fn parse_neg_token_resp(input: &[u8]) -> Result<NegTokenResp, NtlmError> {
    let (outer_tag, outer, rest) = parse_tlv(input)?;
    if !rest.is_empty() {
        return Err(spnego("trailing bytes after NegotiationToken"));
    }
    if outer_tag != 0xa1 {
        return Err(spnego("expected negTokenResp [1]"));
    }
    let (sequence_tag, mut fields, sequence_rest) = parse_tlv(outer)?;
    if sequence_tag != 0x30 || !sequence_rest.is_empty() {
        return Err(spnego("invalid NegTokenResp sequence"));
    }
    let mut response = NegTokenResp::default();
    let mut previous_tag = 0_u8;
    while !fields.is_empty() {
        let (tag, value, rest) = parse_tlv(fields)?;
        if tag <= previous_tag || !(0xa0..=0xa3).contains(&tag) {
            return Err(spnego("duplicate or out-of-order NegTokenResp field"));
        }
        previous_tag = tag;
        match tag {
            0xa0 => {
                let (enum_tag, encoded, inner_rest) = parse_tlv(value)?;
                if enum_tag != 0x0a || encoded.len() != 1 || !inner_rest.is_empty() {
                    return Err(spnego("invalid negState"));
                }
                response.state = Some(match encoded[0] {
                    0 => NegState::AcceptCompleted,
                    1 => NegState::AcceptIncomplete,
                    2 => NegState::Reject,
                    3 => NegState::RequestMic,
                    _ => return Err(spnego("unknown negState")),
                });
            }
            0xa1 => {
                let (oid_tag, _, inner_rest) = parse_tlv(value)?;
                if oid_tag != 0x06 || !inner_rest.is_empty() || value != NTLMSSP_OID {
                    return Err(spnego("server selected an unsupported mechanism"));
                }
            }
            0xa2 => response.response_token = Some(parse_octet_string(value)?.to_vec()),
            0xa3 => response.mech_list_mic = Some(parse_octet_string(value)?.to_vec()),
            _ => unreachable!(),
        }
        fields = rest;
    }
    Ok(response)
}

/// Compatibility helper that performs structural parsing instead of signature scanning.
pub fn extract_ntlmssp(spnego: &[u8]) -> Option<&[u8]> {
    let (outer_tag, outer, rest) = parse_tlv(spnego).ok()?;
    if outer_tag != 0xa1 || !rest.is_empty() {
        return None;
    }
    let (sequence_tag, mut fields, sequence_rest) = parse_tlv(outer).ok()?;
    if sequence_tag != 0x30 || !sequence_rest.is_empty() {
        return None;
    }
    while !fields.is_empty() {
        let (tag, value, remaining) = parse_tlv(fields).ok()?;
        if tag == 0xa2 {
            let token = parse_octet_string(value).ok()?;
            return token.starts_with(b"NTLMSSP\0").then_some(token);
        }
        fields = remaining;
    }
    None
}

fn parse_octet_string(input: &[u8]) -> Result<&[u8], NtlmError> {
    let (tag, contents, rest) = parse_tlv(input)?;
    if tag != 0x04 || !rest.is_empty() {
        return Err(spnego("expected OCTET STRING"));
    }
    Ok(contents)
}

fn parse_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), NtlmError> {
    let (&tag, after_tag) = input.split_first().ok_or_else(|| spnego("truncated tag"))?;
    let (&first_length, after_length) = after_tag
        .split_first()
        .ok_or_else(|| spnego("truncated length"))?;
    let (length, header_length) = if first_length < 0x80 {
        (usize::from(first_length), 0)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() || after_length.len() < count {
            return Err(spnego("invalid long-form length"));
        }
        if after_length[0] == 0 {
            return Err(spnego("non-minimal long-form length"));
        }
        let mut length = 0_usize;
        for byte in &after_length[..count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| spnego("length overflow"))?;
        }
        if length < 0x80 {
            return Err(spnego("non-minimal long-form length"));
        }
        (length, count)
    };
    let body = &after_length[header_length..];
    if body.len() < length {
        return Err(spnego("truncated value"));
    }
    Ok((tag, &body[..length], &body[length..]))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    encode_length(contents.len(), &mut output);
    output.extend_from_slice(contents);
    output
}

fn encode_length(length: usize, output: &mut Vec<u8>) {
    if length < 0x80 {
        output.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    output.push(0x80 | u8::try_from(bytes.len() - first).expect("usize width fits u8"));
    output.extend_from_slice(&bytes[first..]);
}

fn spnego(message: &str) -> NtlmError {
    NtlmError::Spnego(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trip_extracts_exact_token_and_mic() {
        let token = b"NTLMSSP\0payload";
        let encoded = wrap_spnego_resp_with_mic(token, Some(&[7; 16]));
        let decoded = parse_neg_token_resp(&encoded).unwrap();
        assert_eq!(decoded.response_token.as_deref(), Some(token.as_slice()));
        assert_eq!(decoded.mech_list_mic, Some(vec![7; 16]));
        assert_eq!(extract_ntlmssp(&encoded), Some(token.as_slice()));
    }

    #[test]
    fn parser_does_not_scan_nested_junk_for_ntlm_signature() {
        assert!(parse_neg_token_resp(b"junk NTLMSSP\0").is_err());
        assert!(extract_ntlmssp(b"junk NTLMSSP\0").is_none());
    }

    #[test]
    fn parser_rejects_truncated_long_length() {
        assert!(parse_neg_token_resp(&[0xa1, 0x82, 0x01]).is_err());
    }

    #[test]
    fn parser_rejects_a_non_ntlm_supported_mechanism() {
        let kerberos_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let mut fields = tlv(0xa1, &kerberos_oid);
        fields.extend_from_slice(&tlv(0xa2, &tlv(0x04, b"NTLMSSP\0challenge")));
        let token = tlv(0xa1, &tlv(0x30, &fields));

        assert!(parse_neg_token_resp(&token).is_err());
    }
}
