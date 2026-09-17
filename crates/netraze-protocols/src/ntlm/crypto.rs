//! MD4 + HMAC-MD5 primitives for NTLMv2.
//!
//! These are the only crypto operations the NTLM handshake needs; the
//! full AES/DES/RC4 toolkit lives in `crate::smb::crypto` and is not
//! duplicated here because this module doesn't touch LSA/SAM decryption.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Digest as _;
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

/// MD4 digest.
pub fn md4(data: &[u8]) -> Result<[u8; 16], String> {
    let mut hasher = Md4::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out);
    Ok(buf)
}

/// HMAC-MD5.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16], String> {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC-MD5 key length: {e}"))?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out);
    Ok(buf)
}

/// NT hash: MD4 of the password encoded as UTF-16LE.
#[must_use]
pub fn nt_hash_from_password(password: &str) -> [u8; 16] {
    let encoded: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    md4(&encoded).expect("MD4 accepts every input length")
}
