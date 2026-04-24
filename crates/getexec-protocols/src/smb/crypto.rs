//! Pure-Rust crypto primitives for SAM/LSA hash decryption and NTLM auth.
//!
//! Ported from a `windows::Win32::Security::Cryptography::BCrypt*` backend to
//! pure-Rust crates (Phase 0 of the cross-platform port). The public API
//! (names, signatures, `Result<_, String>`) is preserved so callers in
//! `sam.rs`, `ntlm.rs`, `dump.rs`, `hive.rs` don't need to change.

use aes::Aes128;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use cipher::{BlockDecrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Digest as _;
use md5::Md5;

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type HmacMd5 = Hmac<Md5>;

/// MD4 hash.
pub fn md4(data: &[u8]) -> Result<[u8; 16], String> {
    let mut hasher = Md4::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out);
    Ok(buf)
}

/// MD5 hash.
pub fn md5(data: &[u8]) -> Result<[u8; 16], String> {
    let mut hasher = Md5::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out);
    Ok(buf)
}

/// HMAC-MD5: H(K ^ opad, H(K ^ ipad, data)).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16], String> {
    // `HmacMd5::new_from_slice` is ambiguous between the `Mac` and `KeyInit`
    // traits — both are in scope. Disambiguate via the trait we actually want.
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC-MD5 key: {e}"))?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&out);
    Ok(buf)
}

/// AES-128-CBC decrypt, no padding. `iv` is 16 bytes, `key` is 16 bytes,
/// `ciphertext` length must be a multiple of 16.
pub fn aes_128_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 || iv.len() != 16 {
        return Err("AES key must be 16 bytes, IV must be 16 bytes".into());
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(format!(
            "AES-CBC (no padding) requires block-aligned input, got {} bytes",
            ciphertext.len()
        ));
    }

    let dec = Aes128CbcDec::new_from_slices(key, iv).map_err(|e| format!("AES init: {e}"))?;
    let mut buf = ciphertext.to_vec();
    // `NoPadding` is a marker — length stays identical, but the trait method
    // still returns the unpadded slice length for API uniformity.
    let pt = dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| format!("AES decrypt: {e}"))?;
    Ok(pt.to_vec())
}

/// RC4 encrypt/decrypt (stream cipher — the two ops are identical).
///
/// Implemented inline rather than via the `rc4` crate because `Rc4<N>` fixes
/// the key size as a type-level `ArrayLength`, while our callers vary
/// (16-byte NTLM session keys, 3-byte test vectors, arbitrary syskey
/// material). RC4 is ~20 lines and well-documented, so we own it.
pub fn rc4_transform(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() || key.len() > 256 {
        return Err(format!("RC4 key length must be 1..=256, got {}", key.len()));
    }
    // KSA: key schedule.
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    // PRGA: combine keystream with data.
    let mut out = Vec::with_capacity(data.len());
    let (mut i, mut j) = (0u8, 0u8);
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        out.push(byte ^ k);
    }
    Ok(out)
}

/// DES-ECB decrypt a single 8-byte block with an 8-byte key.
pub fn des_ecb_decrypt(block: &[u8; 8], key: &[u8; 8]) -> Result<[u8; 8], String> {
    let cipher = Des::new_from_slice(key).map_err(|e| format!("DES init: {e}"))?;
    let mut buf = *block;
    cipher.decrypt_block((&mut buf).into());
    Ok(buf)
}

/// Expand a 7-byte key to 8-byte DES key with parity bits.
pub fn des_key_expand(key7: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = key7[0] >> 1;
    k[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    k[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    k[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    k[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5);
    k[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6);
    k[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7);
    k[7] = key7[6] & 0x7F;
    for b in &mut k {
        *b = (*b << 1) & 0xFE;
    }
    k
}

/// Convert a RID into two 8-byte DES keys for hash de-obfuscation.
pub fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let s = rid.to_le_bytes();
    let k1_raw: [u8; 7] = [s[0], s[1], s[2], s[3], s[0], s[1], s[2]];
    let k2_raw: [u8; 7] = [s[3], s[0], s[1], s[2], s[3], s[0], s[1]];
    (des_key_expand(&k1_raw), des_key_expand(&k2_raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_empty() {
        let h = md4(b"").unwrap();
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assert_eq!(
            h,
            [
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
                0x89, 0xc0,
            ]
        );
    }

    #[test]
    fn md5_empty() {
        let h = md5(b"").unwrap();
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            h,
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e,
            ]
        );
    }

    #[test]
    fn hmac_md5_rfc2104_vec1() {
        // RFC 2104 test vector #1
        let key = [0x0bu8; 16];
        let mac = hmac_md5(&key, b"Hi There").unwrap();
        assert_eq!(
            mac,
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
                0xfc, 0x9d,
            ]
        );
    }

    #[test]
    fn rc4_known_vector() {
        // RC4 with key "Key" and plaintext "Plaintext" = BBF316E8D940AF0AD3
        let ct = rc4_transform(b"Plaintext", b"Key").unwrap();
        assert_eq!(ct, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn des_ecb_known_vector() {
        // FIPS 81 / classic DES test vector: key=0x0123456789ABCDEF
        // plain=0x4E6F772069732074 → cipher=0x3FA40E8A984D4815
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ct: [u8; 8] = [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15];
        let pt = des_ecb_decrypt(&ct, &key).unwrap();
        assert_eq!(pt, [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74]);
    }

    #[test]
    fn aes_cbc_roundtrip() {
        use aes::cipher::BlockEncryptMut;
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let plaintext = [0x11u8; 32];
        let mut buf = plaintext;
        let enc = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
        let _ = enc
            .encrypt_padded_mut::<NoPadding>(&mut buf, plaintext.len())
            .unwrap();
        let pt = aes_128_cbc_decrypt(&buf, &key, &iv).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }
}
