//! NTLMv2 handshake messages used by LDAP SASL/GSS-SPNEGO.

use super::crypto::hmac_md5;
use rand::RngCore;
use thiserror::Error;

pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NTLMSSP_NEGOTIATE_EXTENDED_SS: u32 = 0x0008_0000;
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

/// Flags required for LDAP integrity and confidentiality.
pub const NEGOTIATE_FLAGS: u32 = NTLMSSP_NEGOTIATE_56
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_EXTENDED_SS
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_UNICODE;

const REQUIRED_PROTECTION_FLAGS: u32 = NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_EXTENDED_SS
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_SIGN;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NtlmError {
    #[error("NTLM message is too short: {0} bytes")]
    TooShort(usize),
    #[error("invalid NTLMSSP signature")]
    BadSignature,
    #[error("expected NTLMSSP message type {expected}, got {got}")]
    WrongType { expected: u32, got: u32 },
    #[error("invalid NTLM security buffer")]
    InvalidSecurityBuffer,
    #[error("server did not negotiate required LDAP sign-and-seal flags (0x{0:08x})")]
    MissingProtectionFlags(u32),
    #[error("NTLM cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("NTLM handshake state error: {0}")]
    State(String),
    #[error("NTLM message integrity check failed")]
    Integrity,
    #[error("invalid SPNEGO token: {0}")]
    Spnego(String),
}

impl From<NtlmError> for String {
    fn from(error: NtlmError) -> Self {
        error.to_string()
    }
}

/// Secret material accepted by NTLMv2. Debug output never includes the secret.
#[derive(Clone)]
pub enum NtlmCredential {
    Password(String),
    NtHash([u8; 16]),
}

impl core::fmt::Debug for NtlmCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("Password(<redacted>)"),
            Self::NtHash(_) => formatter.write_str("NtHash(<redacted>)"),
        }
    }
}

impl NtlmCredential {
    pub fn nt_hash(&self) -> Result<[u8; 16], NtlmError> {
        Ok(match self {
            Self::Password(password) => super::crypto::nt_hash_from_password(password),
            Self::NtHash(hash) => *hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeMessage {
    pub server_challenge: [u8; 8],
    pub negotiate_flags: u32,
    pub target_info: Vec<u8>,
    pub timestamp: Option<[u8; 8]>,
    pub version: Option<(u8, u8, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmV2Auth {
    pub nt_response: Vec<u8>,
    pub lm_response: Vec<u8>,
    pub session_base_key: [u8; 16],
}

#[must_use]
pub fn build_negotiate() -> Vec<u8> {
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&1_u32.to_le_bytes());
    message.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
    message.extend_from_slice(&[0; 16]);
    message.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    message
}

pub fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    if data.len() < 32 {
        return Err(NtlmError::TooShort(data.len()));
    }
    if data.get(..8) != Some(b"NTLMSSP\0") {
        return Err(NtlmError::BadSignature);
    }
    let message_type = read_u32(data, 8)?;
    if message_type != 2 {
        return Err(NtlmError::WrongType {
            expected: 2,
            got: message_type,
        });
    }
    let negotiate_flags = read_u32(data, 20)? & NEGOTIATE_FLAGS;
    if negotiate_flags & REQUIRED_PROTECTION_FLAGS != REQUIRED_PROTECTION_FLAGS {
        return Err(NtlmError::MissingProtectionFlags(negotiate_flags));
    }
    let has_version = negotiate_flags & NTLMSSP_NEGOTIATE_VERSION != 0;
    if has_version && data.len() < 56 {
        return Err(NtlmError::TooShort(data.len()));
    }
    let mut server_challenge = [0; 8];
    server_challenge.copy_from_slice(&data[24..32]);
    let target_info = if data.len() >= 48 {
        read_security_buffer(data, 40)?.to_vec()
    } else {
        Vec::new()
    };
    let timestamp =
        extract_av_pair(&target_info, 7).and_then(|value| <[u8; 8]>::try_from(value).ok());
    let version = if has_version {
        Some((data[48], data[49], u16::from_le_bytes([data[50], data[51]])))
    } else {
        None
    };
    Ok(ChallengeMessage {
        server_challenge,
        negotiate_flags,
        target_info,
        timestamp,
        version,
    })
}

pub fn compute_ntlmv2(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
    challenge: &ChallengeMessage,
) -> Result<NtlmV2Auth, NtlmError> {
    let mut client_challenge = [0; 8];
    rand::thread_rng().fill_bytes(&mut client_challenge);
    compute_ntlmv2_with_inputs(
        nt_hash,
        username,
        domain,
        challenge,
        challenge.timestamp.unwrap_or_else(current_filetime),
        client_challenge,
    )
}

pub(crate) fn compute_ntlmv2_with_inputs(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
    challenge: &ChallengeMessage,
    timestamp: [u8; 8],
    client_challenge: [u8; 8],
) -> Result<NtlmV2Auth, NtlmError> {
    let identity: Vec<u8> = format!("{}{}", username.to_uppercase(), domain)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let response_key = hmac_md5(nt_hash, &identity).map_err(NtlmError::Crypto)?;
    let target_info = target_info_with_mic_flag(&challenge.target_info)?;
    let mut blob = Vec::with_capacity(32 + target_info.len());
    blob.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    blob.extend_from_slice(&timestamp);
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&[0; 4]);
    blob.extend_from_slice(&target_info);
    blob.extend_from_slice(&[0; 4]);

    let mut proof_input = challenge.server_challenge.to_vec();
    proof_input.extend_from_slice(&blob);
    let proof = hmac_md5(&response_key, &proof_input).map_err(NtlmError::Crypto)?;
    let mut nt_response = proof.to_vec();
    nt_response.extend_from_slice(&blob);
    let session_base_key = hmac_md5(&response_key, &proof).map_err(NtlmError::Crypto)?;

    let mut lm_input = challenge.server_challenge.to_vec();
    lm_input.extend_from_slice(&client_challenge);
    let mut lm_response = hmac_md5(&response_key, &lm_input)
        .map_err(NtlmError::Crypto)?
        .to_vec();
    lm_response.extend_from_slice(&client_challenge);
    Ok(NtlmV2Auth {
        nt_response,
        lm_response,
        session_base_key,
    })
}

/// Build Type 3 without a handshake MIC. Kept for existing protocol consumers.
pub fn build_authenticate(auth: &NtlmV2Auth, username: &str, domain: &str) -> (Vec<u8>, [u8; 16]) {
    let mut exported_session_key = [0; 16];
    rand::thread_rng().fill_bytes(&mut exported_session_key);
    (
        build_authenticate_with_key(
            auth,
            username,
            domain,
            NEGOTIATE_FLAGS,
            exported_session_key,
            None,
        ),
        exported_session_key,
    )
}

pub(crate) fn build_authenticate_with_key(
    auth: &NtlmV2Auth,
    username: &str,
    domain: &str,
    negotiated_flags: u32,
    exported_session_key: [u8; 16],
    transcript: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let domain_utf16 = utf16le(domain);
    let user_utf16 = utf16le(username);
    let encrypted_session_key = rc4_oneshot(&exported_session_key, &auth.session_base_key);
    let include_mic = transcript.is_some();
    let include_version = negotiated_flags & NTLMSSP_NEGOTIATE_VERSION != 0;
    let mic_offset = 64 + usize::from(include_version) * 8;
    let payload_offset =
        u32::try_from(mic_offset + usize::from(include_mic) * 16).expect("NTLM header fits in u32");
    let fields: [&[u8]; 6] = [
        &auth.lm_response,
        &auth.nt_response,
        &domain_utf16,
        &user_utf16,
        &[],
        &encrypted_session_key,
    ];
    let mut offsets = [0_u32; 6];
    let mut next = payload_offset;
    for (index, field) in fields.iter().enumerate() {
        offsets[index] = next;
        next += u32::try_from(field.len()).expect("NTLM fields fit in u32");
    }

    let mut message = Vec::with_capacity(next as usize);
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&3_u32.to_le_bytes());
    for (field, offset) in fields.iter().zip(offsets) {
        write_security_buffer(&mut message, field.len(), offset);
    }
    message.extend_from_slice(&negotiated_flags.to_le_bytes());
    if include_version {
        message.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    }
    if include_mic {
        message.extend_from_slice(&[0; 16]);
    }
    for field in fields {
        message.extend_from_slice(field);
    }
    if let Some((negotiate, challenge)) = transcript {
        let mut mic_input = Vec::with_capacity(negotiate.len() + challenge.len() + message.len());
        mic_input.extend_from_slice(negotiate);
        mic_input.extend_from_slice(challenge);
        mic_input.extend_from_slice(&message);
        let mic =
            hmac_md5(&exported_session_key, &mic_input).expect("HMAC-MD5 accepts a 16-byte key");
        message[mic_offset..mic_offset + 16].copy_from_slice(&mic);
    }
    message
}

#[must_use]
pub fn build_anonymous_authenticate() -> Vec<u8> {
    const FLAGS: u32 = NTLMSSP_NEGOTIATE_EXTENDED_SS
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_UNICODE;
    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&3_u32.to_le_bytes());
    for _ in 0..6 {
        write_security_buffer(&mut message, 0, 72);
    }
    message.extend_from_slice(&FLAGS.to_le_bytes());
    message.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    message
}

fn target_info_with_mic_flag(info: &[u8]) -> Result<Vec<u8>, NtlmError> {
    const MSV_AV_EOL: u16 = 0;
    const MSV_AV_FLAGS: u16 = 6;
    const MIC_PRESENT: u32 = 2;

    let mut output = Vec::with_capacity(info.len() + 8);
    let mut offset = 0_usize;
    let mut found_flags = false;
    let mut found_eol = false;
    while offset < info.len() {
        let header = info
            .get(offset..offset + 4)
            .ok_or(NtlmError::InvalidSecurityBuffer)?;
        let id = u16::from_le_bytes([header[0], header[1]]);
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .ok_or(NtlmError::InvalidSecurityBuffer)?;
        let value = info
            .get(offset..end)
            .ok_or(NtlmError::InvalidSecurityBuffer)?;
        if id == MSV_AV_EOL {
            if length != 0 || end != info.len() {
                return Err(NtlmError::InvalidSecurityBuffer);
            }
            found_eol = true;
            break;
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&(length as u16).to_le_bytes());
        if id == MSV_AV_FLAGS {
            if found_flags || length != 4 {
                return Err(NtlmError::InvalidSecurityBuffer);
            }
            let flags = u32::from_le_bytes(value.try_into().expect("length checked")) | MIC_PRESENT;
            output.extend_from_slice(&flags.to_le_bytes());
            found_flags = true;
        } else {
            output.extend_from_slice(value);
        }
        offset = end;
    }
    if !found_eol {
        return Err(NtlmError::InvalidSecurityBuffer);
    }
    if !found_flags {
        output.extend_from_slice(&MSV_AV_FLAGS.to_le_bytes());
        output.extend_from_slice(&4_u16.to_le_bytes());
        output.extend_from_slice(&MIC_PRESENT.to_le_bytes());
    }
    output.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    Ok(output)
}

pub fn extract_av_pair(info: &[u8], target_id: u16) -> Option<&[u8]> {
    let mut offset = 0_usize;
    while offset.checked_add(4)? <= info.len() {
        let id = u16::from_le_bytes(info[offset..offset + 2].try_into().ok()?);
        let length = u16::from_le_bytes(info[offset + 2..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        let end = offset.checked_add(length)?;
        if end > info.len() || id == 0 {
            return None;
        }
        if id == target_id {
            return Some(&info[offset..end]);
        }
        offset = end;
    }
    None
}

fn read_security_buffer(data: &[u8], offset: usize) -> Result<&[u8], NtlmError> {
    let header = data
        .get(offset..offset + 8)
        .ok_or(NtlmError::InvalidSecurityBuffer)?;
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let maximum = u16::from_le_bytes([header[2], header[3]]) as usize;
    let start = u32::from_le_bytes(header[4..8].try_into().expect("length checked")) as usize;
    if maximum < length {
        return Err(NtlmError::InvalidSecurityBuffer);
    }
    let end = start
        .checked_add(length)
        .ok_or(NtlmError::InvalidSecurityBuffer)?;
    data.get(start..end).ok_or(NtlmError::InvalidSecurityBuffer)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, NtlmError> {
    data.get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(NtlmError::TooShort(data.len()))
}

fn write_security_buffer(message: &mut Vec<u8>, length: usize, offset: u32) {
    let length = u16::try_from(length).expect("NTLM field fits in u16");
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(&offset.to_le_bytes());
}

fn utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn current_filetime() -> [u8; 8] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ((now.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(now.subsec_nanos()) / 100)
        .to_le_bytes()
}

fn rc4_oneshot(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut rc4 = super::security::Rc4::new(key);
    let mut output = data.to_vec();
    rc4.transform(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_rejects_out_of_bounds_target_info() {
        let mut challenge = vec![0; 56];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8..12].copy_from_slice(&2_u32.to_le_bytes());
        challenge[20..24].copy_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
        challenge[40..42].copy_from_slice(&8_u16.to_le_bytes());
        challenge[42..44].copy_from_slice(&8_u16.to_le_bytes());
        challenge[44..48].copy_from_slice(&100_u32.to_le_bytes());
        assert_eq!(
            parse_challenge(&challenge),
            Err(NtlmError::InvalidSecurityBuffer)
        );
    }

    #[test]
    fn challenge_rejects_a_truncated_negotiated_version() {
        let mut challenge = vec![0; 52];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8..12].copy_from_slice(&2_u32.to_le_bytes());
        challenge[20..24].copy_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
        challenge[40..42].copy_from_slice(&4_u16.to_le_bytes());
        challenge[42..44].copy_from_slice(&4_u16.to_le_bytes());
        challenge[44..48].copy_from_slice(&48_u32.to_le_bytes());

        assert_eq!(
            parse_challenge(&challenge),
            Err(NtlmError::TooShort(challenge.len()))
        );
    }

    #[test]
    fn authenticate_mic_covers_the_zeroed_mic_message() {
        let auth = NtlmV2Auth {
            nt_response: vec![1; 32],
            lm_response: vec![2; 24],
            session_base_key: [3; 16],
        };
        let key = [4; 16];
        let mut message = build_authenticate_with_key(
            &auth,
            "alice",
            "EXAMPLE",
            NEGOTIATE_FLAGS,
            key,
            Some((b"negotiate", b"challenge")),
        );
        let actual = message[72..88].to_vec();
        message[72..88].fill(0);
        let mut input = b"negotiatechallenge".to_vec();
        input.extend_from_slice(&message);
        assert_eq!(actual, hmac_md5(&key, &input).unwrap());
    }

    #[test]
    fn ntlmv2_blob_marks_the_type_three_mic_as_present() {
        let challenge = ChallengeMessage {
            server_challenge: [0x11; 8],
            negotiate_flags: NEGOTIATE_FLAGS,
            target_info: vec![0; 4],
            timestamp: Some([0x22; 8]),
            version: None,
        };
        let response = compute_ntlmv2_with_inputs(
            &[0x33; 16],
            "alice",
            "EXAMPLE",
            &challenge,
            [0x22; 8],
            [0x44; 8],
        )
        .unwrap();
        assert_eq!(&response.nt_response[44..48], &[6, 0, 4, 0]);
        assert_eq!(&response.nt_response[48..52], &2_u32.to_le_bytes());
    }

    /// MS-NLMP §4.2.4 NTLMv2 LM challenge-response known-answer vector.
    #[test]
    fn ntlmv2_lm_response_matches_ms_nlmp_vector() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            negotiate_flags: NEGOTIATE_FLAGS,
            target_info: vec![0; 4],
            timestamp: Some([0; 8]),
            version: None,
        };
        let response = compute_ntlmv2_with_inputs(
            &crate::ntlm::crypto::nt_hash_from_password("Password"),
            "User",
            "Domain",
            &challenge,
            [0; 8],
            [0xaa; 8],
        )
        .unwrap();
        assert_eq!(
            response.lm_response,
            [
                0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc,
                0xcc, 0x19, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            ]
        );
    }

    #[test]
    fn target_info_requires_one_terminal_eol_pair() {
        let missing_eol = [1, 0, 0, 0];
        let trailing_after_eol = [0, 0, 0, 0, 1, 0, 0, 0];
        let duplicate_flags = [6, 0, 4, 0, 0, 0, 0, 0, 6, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert!(target_info_with_mic_flag(&missing_eol).is_err());
        assert!(target_info_with_mic_flag(&trailing_after_eol).is_err());
        assert!(target_info_with_mic_flag(&duplicate_flags).is_err());
    }
}
