//! SAM hash extraction — bootkey, syskey, per-user NTLM hash decryption.

use super::crypto;
use super::hive::Hive;

/// One extracted SAM hash entry.
pub struct SamHash {
    pub username: String,
    pub rid: u32,
    pub lm_hash: String,
    pub nt_hash: String,
}

impl std::fmt::Display for SamHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:::",
            self.username, self.rid, self.lm_hash, self.nt_hash
        )
    }
}

const BOOTKEY_PERM: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";
const EMPTY_NT: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

// ---------- bootkey extraction (from SYSTEM hive) ---------

pub fn extract_bootkey(system: &Hive) -> Result<[u8; 16], String> {
    // Determine current control set
    let select = system.path("Select")?;
    let default_data = system.value(select, "Default")?;
    if default_data.len() < 4 {
        return Err("Select\\Default value too short".into());
    }
    let cs_num = u32::from_le_bytes(default_data[..4].try_into().unwrap());
    let lsa_path = format!("ControlSet{:03}\\Control\\Lsa", cs_num);
    let lsa = system.path(&lsa_path)?;

    let mut scrambled = Vec::with_capacity(16);
    for name in ["JD", "Skew1", "GBG", "Data"] {
        let sub = system.subkey(lsa, name)?;
        let class = system.class_name(sub)?;
        let bytes = hex_decode(&class)?;
        scrambled.extend_from_slice(&bytes);
    }
    if scrambled.len() < 16 {
        return Err(format!(
            "Scrambled bootkey too short: {} bytes",
            scrambled.len()
        ));
    }

    let mut bootkey = [0u8; 16];
    for i in 0..16 {
        bootkey[i] = scrambled[BOOTKEY_PERM[i]];
    }
    Ok(bootkey)
}

// ---------- SAM hash dump ---------

pub fn dump_sam_hashes(sam: &Hive, bootkey: &[u8; 16]) -> Result<Vec<SamHash>, String> {
    let account = sam.path("SAM\\Domains\\Account")?;

    // Read F value — contains the encrypted syskey
    let f_value = sam.value(account, "F")?;
    if f_value.len() < 0x70 {
        return Err("SAM F value too short".into());
    }

    let syskey = decrypt_syskey(&f_value, bootkey)?;

    // Enumerate users
    let users_key = sam.path("SAM\\Domains\\Account\\Users")?;
    let children = sam.subkeys(users_key)?;

    let mut hashes = Vec::new();
    for (name, key) in &children {
        if name == "Names" {
            continue;
        }
        let rid = match u32::from_str_radix(name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let v_value = match sam.value(*key, "V") {
            Ok(v) => v,
            Err(_) => continue,
        };
        match parse_user_v(&v_value, &syskey, rid) {
            Ok(h) => hashes.push(h),
            Err(e) => {
                // Skip users we can't parse
                eprintln!("[SAM] skip RID {rid}: {e}");
            }
        }
    }

    // Sort by RID
    hashes.sort_by_key(|h| h.rid);
    Ok(hashes)
}

// ---------- syskey decryption ----------

fn decrypt_syskey(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16], String> {
    let revision = f[0x68] as u32;
    match revision {
        1 => decrypt_syskey_rc4(f, bootkey),
        2 => decrypt_syskey_aes(f, bootkey),
        _ => Err(format!("Unknown SAM key revision: {revision}")),
    }
}

fn decrypt_syskey_rc4(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16], String> {
    // SAM_KEY_DATA (RC4 path):
    //   0x68: Revision=1, +4 Length, +8 Salt[16], +24 Key[16], +40 Checksum[16]
    if f.len() < 0x68 + 40 {
        return Err("F value too short for RC4 syskey".into());
    }
    let salt = &f[0x70..0x80]; // offset 0x68 + 8
    let encrypted = &f[0x80..0x90]; // offset 0x68 + 24

    // RC4 key = MD5(salt + AQWERTY + bootkey + ANUM)
    let aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
    let anum = b"0123456789012345678901234567890123456789\0";
    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(aqwerty);
    md5_input.extend_from_slice(bootkey);
    md5_input.extend_from_slice(anum);
    let rc4_key = crypto::md5(&md5_input)?;

    let decrypted = crypto::rc4_transform(encrypted, &rc4_key)?;
    if decrypted.len() < 16 {
        return Err("RC4 syskey decrypt too short".into());
    }
    let mut syskey = [0u8; 16];
    syskey.copy_from_slice(&decrypted[..16]);
    Ok(syskey)
}

fn decrypt_syskey_aes(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16], String> {
    // SAM_KEY_DATA_AES:
    //   0x68: Revision=2 (u32)
    //   0x6C: Length (u32)
    //   0x70: CheckLen (u32)
    //   0x74: DataLen (u32)
    //   0x78: Salt[16]
    //   0x88: EncryptedData[DataLen]
    if f.len() < 0x88 {
        return Err("F value too short for AES syskey header".into());
    }
    let data_len =
        u32::from_le_bytes(f[0x74..0x78].try_into().unwrap()) as usize;
    let salt = &f[0x78..0x88];
    let end = 0x88 + data_len;
    if f.len() < end {
        return Err(format!("F value too short for AES syskey data: need {end}, have {}", f.len()));
    }
    let encrypted = &f[0x88..end];

    let mut iv = [0u8; 16];
    iv.copy_from_slice(salt);
    let decrypted = crypto::aes_128_cbc_decrypt(encrypted, bootkey, &iv)?;
    if decrypted.len() < 16 {
        return Err("AES syskey decrypt too short".into());
    }
    let mut syskey = [0u8; 16];
    syskey.copy_from_slice(&decrypted[..16]);
    Ok(syskey)
}

// ---------- per-user V value parsing ----------

fn parse_user_v(v: &[u8], syskey: &[u8; 16], rid: u32) -> Result<SamHash, String> {
    if v.len() < 0xCC + 4 {
        return Err("V value too short".into());
    }

    // Username: offset at V[0x0C], length at V[0x10], data base at V[0xCC]
    let name_off = u32_le(v, 0x0C) as usize + 0xCC;
    let name_len = u32_le(v, 0x10) as usize;
    let username = if name_off + name_len <= v.len() {
        utf16_le_str(&v[name_off..name_off + name_len])
    } else {
        format!("(RID {})", rid)
    };

    // NT hash: offset at V[0xA8], length at V[0xAC]
    let nt_off = u32_le(v, 0xA8) as usize + 0xCC;
    let nt_len = u32_le(v, 0xAC) as usize;

    let nt_hash = if nt_len > 4 && nt_off + nt_len <= v.len() {
        match decrypt_user_hash(&v[nt_off..nt_off + nt_len], syskey, rid) {
            Ok(h) => hex_encode(&h),
            Err(_) => EMPTY_NT.to_string(),
        }
    } else {
        EMPTY_NT.to_string()
    };

    // LM hash: offset at V[0x9C], length at V[0xA0]
    let lm_off = u32_le(v, 0x9C) as usize + 0xCC;
    let lm_len = u32_le(v, 0xA0) as usize;

    let lm_hash = if lm_len > 4 && lm_off + lm_len <= v.len() {
        match decrypt_user_hash(&v[lm_off..lm_off + lm_len], syskey, rid) {
            Ok(h) => hex_encode(&h),
            Err(_) => EMPTY_LM.to_string(),
        }
    } else {
        EMPTY_LM.to_string()
    };

    Ok(SamHash {
        username,
        rid,
        lm_hash,
        nt_hash,
    })
}

fn decrypt_user_hash(data: &[u8], syskey: &[u8; 16], rid: u32) -> Result<[u8; 16], String> {
    if data.len() < 4 {
        return Err("Hash data too short".into());
    }
    let revision = u16::from_le_bytes([data[2], data[3]]);
    let obfuscated = match revision {
        1 => decrypt_hash_rc4(data, syskey, rid)?,
        2 => decrypt_hash_aes(data, syskey)?,
        _ => return Err(format!("Unknown hash revision: {revision}")),
    };

    // DES de-obfuscation with RID
    if obfuscated.len() < 16 {
        return Err("Obfuscated hash too short".into());
    }
    let (k1, k2) = crypto::rid_to_des_keys(rid);
    let block1: [u8; 8] = obfuscated[..8].try_into().unwrap();
    let block2: [u8; 8] = obfuscated[8..16].try_into().unwrap();
    let d1 = crypto::des_ecb_decrypt(&block1, &k1)?;
    let d2 = crypto::des_ecb_decrypt(&block2, &k2)?;

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&d1);
    hash[8..].copy_from_slice(&d2);
    Ok(hash)
}

fn decrypt_hash_rc4(data: &[u8], syskey: &[u8; 16], rid: u32) -> Result<Vec<u8>, String> {
    // SAM_HASH (revision 1): PekID(2) + Revision(2) + EncryptedHash(16)
    if data.len() < 20 {
        return Err("RC4 hash data too short".into());
    }
    let enc = &data[4..20];
    // RC4 key = MD5(syskey + RID_le + NTPASSWORD\0 or LMPASSWORD\0)
    let rid_bytes = rid.to_le_bytes();
    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(syskey);
    md5_input.extend_from_slice(&rid_bytes);
    md5_input.extend_from_slice(b"NTPASSWORD\0");
    let rc4_key = crypto::md5(&md5_input)?;
    crypto::rc4_transform(enc, &rc4_key)
}

fn decrypt_hash_aes(data: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, String> {
    // SAM_HASH_AES (revision 2): PekID(2) + Revision(2) + DataOffset(4) + Salt(16) + Enc(...)
    if data.len() < 24 {
        return Err("AES hash data too short".into());
    }
    let salt = &data[8..24];
    let enc = &data[24..];
    if enc.is_empty() {
        return Err("AES hash encrypted data empty".into());
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(salt);
    crypto::aes_128_cbc_decrypt(enc, syskey, &iv)
}

// ---------- helpers ----------

fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn utf16_le_str(data: &[u8]) -> String {
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("Odd hex length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Bad hex at {i}: {e}"))
        })
        .collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
