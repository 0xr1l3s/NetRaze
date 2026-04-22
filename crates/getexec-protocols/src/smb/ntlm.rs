//! NTLMv2 authentication for pass-the-hash SMB connections.

use super::crypto::{hmac_md5, md4};

/// Compute NT hash (MD4 of UTF-16LE password).
pub fn nt_hash_from_password(password: &str) -> Result<[u8; 16], String> {
    let pw_utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4(&pw_utf16)
}

/// Parsed NTLMSSP Challenge (Type 2) message.
pub struct ChallengeMessage {
    pub server_challenge: [u8; 8],
    pub negotiate_flags: u32,
    pub target_info: Vec<u8>,
    pub timestamp: Option<[u8; 8]>,
    /// NTLM Version field: (major, minor, build).
    pub version: Option<(u8, u8, u16)>,
}

/// NTLMv2 authentication result.
pub struct NtlmV2Auth {
    pub nt_response: Vec<u8>,
    pub lm_response: Vec<u8>,
    pub session_base_key: [u8; 16],
}

// ── NTLMSSP Negotiate flags ──
const NTLMSSP_NEGOTIATE_UNICODE: u32       = 0x00000001;
const NTLMSSP_REQUEST_TARGET: u32          = 0x00000004;
const NTLMSSP_NEGOTIATE_SIGN: u32          = 0x00000010;
const NTLMSSP_NEGOTIATE_SEAL: u32          = 0x00000020;
const NTLMSSP_NEGOTIATE_NTLM: u32         = 0x00000200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32   = 0x00008000;
const NTLMSSP_NEGOTIATE_EXTENDED_SS: u32   = 0x00080000;
const NTLMSSP_NEGOTIATE_128: u32           = 0x20000000;
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32      = 0x40000000;
const NTLMSSP_NEGOTIATE_56: u32            = 0x80000000;

const NEGOTIATE_FLAGS: u32 = NTLMSSP_NEGOTIATE_56
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_EXTENDED_SS
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_UNICODE;

/// Build NTLMSSP Negotiate message (Type 1).
pub fn build_negotiate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(40);
    msg.extend_from_slice(b"NTLMSSP\0");
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]); // DomainNameFields
    msg.extend_from_slice(&[0u8; 8]); // WorkstationFields
    msg
}

/// Parse NTLMSSP Challenge message (Type 2).
pub fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, String> {
    if data.len() < 32 {
        return Err("Challenge message too short".into());
    }
    if &data[0..8] != b"NTLMSSP\0" {
        return Err("Invalid NTLMSSP signature".into());
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if msg_type != 2 {
        return Err(format!("Expected Type 2 challenge, got {msg_type}"));
    }

    let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());

    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&data[24..32]);

    // TargetInfoFields at offset 40
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes(data[40..42].try_into().unwrap()) as usize;
        let ti_offset = u32::from_le_bytes(data[44..48].try_into().unwrap()) as usize;
        if ti_len > 0 && ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Extract timestamp from AV_PAIRs (AvId = 7 = MsvAvTimestamp)
    let timestamp = extract_av_pair(&target_info, 7)
        .and_then(|t| <[u8; 8]>::try_from(t.as_slice()).ok());

    // Parse Version field at offset 48 (8 bytes) if NTLMSSP_NEGOTIATE_VERSION (0x02000000) is set
    let version = if data.len() >= 56 {
        let major = data[48];
        let minor = data[49];
        let build = u16::from_le_bytes(data[50..52].try_into().unwrap());
        if major > 0 || build > 0 {
            Some((major, minor, build))
        } else {
            None
        }
    } else {
        None
    };

    Ok(ChallengeMessage {
        server_challenge: challenge,
        negotiate_flags: flags,
        target_info,
        timestamp,
        version,
    })
}

/// Compute NTLMv2 response from NT hash.
pub fn compute_ntlmv2(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
    challenge: &ChallengeMessage,
) -> Result<NtlmV2Auth, String> {
    // ResponseKeyNT = HMAC_MD5(NT_Hash, UNICODE(Uppercase(UserName) + UserDomain))
    let user_domain = format!("{}{}", username.to_uppercase(), domain);
    let user_domain_utf16: Vec<u8> = user_domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let response_key = hmac_md5(nt_hash, &user_domain_utf16)?;

    let client_challenge = rand_bytes::<8>();

    // Timestamp: use server's if available, else compute current
    let timestamp = challenge.timestamp.unwrap_or_else(current_filetime);

    // Build NTLMv2 client blob
    let mut blob = Vec::new();
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&[0u8; 6]); // Reserved
    blob.extend_from_slice(&timestamp);
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&[0u8; 4]); // Reserved
    blob.extend_from_slice(&challenge.target_info);
    blob.extend_from_slice(&[0u8; 4]); // Reserved

    // NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + blob)
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof = hmac_md5(&response_key, &proof_input)?;

    // NtChallengeResponse = NTProofStr + blob
    let mut nt_response = Vec::new();
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);

    // SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    let session_base_key = hmac_md5(&response_key, &nt_proof)?;

    // LMv2 Response
    let lm_client_challenge = rand_bytes::<8>();
    let mut lm_input = Vec::new();
    lm_input.extend_from_slice(&challenge.server_challenge);
    lm_input.extend_from_slice(&lm_client_challenge);
    let lm_proof = hmac_md5(&response_key, &lm_input)?;
    let mut lm_response = Vec::new();
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&lm_client_challenge);

    Ok(NtlmV2Auth {
        nt_response,
        lm_response,
        session_base_key,
    })
}

/// Build NTLMSSP Authenticate message (Type 3).
pub fn build_authenticate(
    auth: &NtlmV2Auth,
    username: &str,
    domain: &str,
    _server_flags: u32,
) -> Vec<u8> {
    let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let user_utf16: Vec<u8> = username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let workstation_utf16: Vec<u8> = Vec::new();

    // Encrypted random session key (KEY_EXCH)
    let random_session_key = rand_bytes::<16>();
    let encrypted_session_key = super::crypto::rc4_transform(&random_session_key, &auth.session_base_key)
        .unwrap_or_else(|_| random_session_key.to_vec());

    // Payload offset = 8 (sig) + 4 (type) + 6×8 (fields) + 4 (flags) + 8 (version) = 72
    let payload_offset = 72u32;

    let lm_off = payload_offset;
    let nt_off = lm_off + auth.lm_response.len() as u32;
    let dom_off = nt_off + auth.nt_response.len() as u32;
    let usr_off = dom_off + domain_utf16.len() as u32;
    let ws_off = usr_off + user_utf16.len() as u32;
    let sk_off = ws_off + workstation_utf16.len() as u32;

    let mut msg = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\0");
    msg.extend_from_slice(&3u32.to_le_bytes());

    write_fields(&mut msg, auth.lm_response.len() as u16, lm_off);
    write_fields(&mut msg, auth.nt_response.len() as u16, nt_off);
    write_fields(&mut msg, domain_utf16.len() as u16, dom_off);
    write_fields(&mut msg, user_utf16.len() as u16, usr_off);
    write_fields(&mut msg, workstation_utf16.len() as u16, ws_off);
    write_fields(&mut msg, encrypted_session_key.len() as u16, sk_off);

    msg.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());

    // Version: 10.0, build 0, NTLM revision 15
    msg.extend_from_slice(&[10, 0, 0x00, 0x00, 0, 0, 0, 0x0f]);

    // Payload
    msg.extend_from_slice(&auth.lm_response);
    msg.extend_from_slice(&auth.nt_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&user_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&encrypted_session_key);

    msg
}

// ── SPNEGO wrappers ──

/// Wrap NTLMSSP in SPNEGO NegTokenInit (first Session Setup).
pub fn wrap_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
    // OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
    let ntlmssp_oid: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    // OID 1.3.6.1.5.5.2 (SPNEGO)
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    let mech_token = asn1_wrap(0xa2, &asn1_wrap(0x04, ntlmssp));
    let mech_types = asn1_wrap(0xa0, &asn1_wrap(0x30, ntlmssp_oid));

    let mut neg_body = Vec::new();
    neg_body.extend_from_slice(&mech_types);
    neg_body.extend_from_slice(&mech_token);

    let neg_init = asn1_wrap(0xa0, &asn1_wrap(0x30, &neg_body));

    let mut app_body = Vec::new();
    app_body.extend_from_slice(spnego_oid);
    app_body.extend_from_slice(&neg_init);
    asn1_wrap(0x60, &app_body)
}

/// Wrap NTLMSSP in SPNEGO NegTokenResp (second Session Setup).
pub fn wrap_spnego_resp(ntlmssp: &[u8]) -> Vec<u8> {
    let resp_token = asn1_wrap(0xa2, &asn1_wrap(0x04, ntlmssp));
    asn1_wrap(0xa1, &asn1_wrap(0x30, &resp_token))
}

/// Extract NTLMSSP message from SPNEGO by scanning for "NTLMSSP\0".
pub fn extract_ntlmssp(spnego: &[u8]) -> Option<&[u8]> {
    spnego
        .windows(8)
        .position(|w| w == b"NTLMSSP\0")
        .map(|pos| &spnego[pos..])
}

// ── Helpers ──

fn write_fields(msg: &mut Vec<u8>, len: u16, offset: u32) {
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(&len.to_le_bytes()); // MaxLen = Len
    msg.extend_from_slice(&offset.to_le_bytes());
}

/// Extract an AV_PAIR value from target info by AvId.
pub fn extract_av_pair(info: &[u8], target_id: u16) -> Option<Vec<u8>> {
    let mut offset = 0;
    while offset + 4 <= info.len() {
        let av_id = u16::from_le_bytes(info[offset..offset + 2].try_into().unwrap());
        let av_len = u16::from_le_bytes(info[offset + 2..offset + 4].try_into().unwrap()) as usize;
        if av_id == 0 {
            break;
        }
        if av_id == target_id && offset + 4 + av_len <= info.len() {
            return Some(info[offset + 4..offset + 4 + av_len].to_vec());
        }
        offset += 4 + av_len;
    }
    None
}

fn asn1_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(tag);
    let len = content.len();
    if len < 0x80 {
        result.push(len as u8);
    } else if len < 0x100 {
        result.push(0x81);
        result.push(len as u8);
    } else {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push(len as u8);
    }
    result.extend_from_slice(content);
    result
}

fn current_filetime() -> [u8; 8] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let filetime = (now.as_secs() + 11_644_473_600) * 10_000_000
        + now.subsec_nanos() as u64 / 100;
    filetime.to_le_bytes()
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
