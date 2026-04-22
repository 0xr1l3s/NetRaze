//! Minimal registry hive (regf) binary format parser.
//!
//! Supports navigating keys, reading values, class names, and enumerating subkeys.
//! Offsets stored inside the hive are relative to file offset 0x1000 (first hbin block).

const HBIN_BASE: usize = 0x1000;

pub struct Hive {
    data: Vec<u8>,
}

/// Opaque handle to an NK (named key) cell, stored as its file offset.
#[derive(Clone, Copy)]
pub struct HiveKey(usize);

impl Hive {
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < HBIN_BASE + 32 {
            return Err("Hive too small".into());
        }
        if &data[0..4] != b"regf" {
            return Err(format!("Bad hive magic: {:?}", &data[0..4]));
        }
        Ok(Self { data })
    }

    /// File offset of the root NK cell (after the 4-byte cell size).
    fn root_cell_foff(&self) -> usize {
        let rel = self.u32(0x24) as usize;
        HBIN_BASE + rel + 4 // +4 to skip cell size
    }

    pub fn root(&self) -> HiveKey {
        HiveKey(self.root_cell_foff())
    }

    // ---------- primitive readers ----------

    fn u16(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.data[off], self.data[off + 1]])
    }

    fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap())
    }

    fn i32(&self, off: usize) -> i32 {
        i32::from_le_bytes(self.data[off..off + 4].try_into().unwrap())
    }

    /// Convert a relative cell offset (as stored in the hive) to a file offset
    /// that points past the 4-byte cell size, i.e., directly at the cell data.
    fn cell(&self, rel: u32) -> usize {
        HBIN_BASE + rel as usize + 4
    }

    // ---------- NK accessors ----------

    fn nk_sig(&self, foff: usize) -> bool {
        self.data[foff] == b'n' && self.data[foff + 1] == b'k'
    }

    fn nk_subkey_count(&self, f: usize) -> u32 {
        self.u32(f + 20)
    }

    fn nk_subkey_list_off(&self, f: usize) -> u32 {
        self.u32(f + 28)
    }

    fn nk_value_count(&self, f: usize) -> u32 {
        self.u32(f + 36)
    }

    fn nk_value_list_off(&self, f: usize) -> u32 {
        self.u32(f + 40)
    }

    fn nk_classname_off(&self, f: usize) -> u32 {
        self.u32(f + 48)
    }

    fn nk_key_name_len(&self, f: usize) -> u16 {
        self.u16(f + 72)
    }

    fn nk_classname_len(&self, f: usize) -> u16 {
        self.u16(f + 74)
    }

    fn nk_key_name(&self, f: usize) -> String {
        let len = self.nk_key_name_len(f) as usize;
        let start = f + 76;
        // Key names are usually ASCII in saved hives
        String::from_utf8_lossy(&self.data[start..start + len]).to_string()
    }

    // ---------- public API ----------

    /// Find a direct child subkey by name (case-insensitive).
    pub fn subkey(&self, parent: HiveKey, name: &str) -> Result<HiveKey, String> {
        let f = parent.0;
        if !self.nk_sig(f) {
            return Err(format!("Not an NK cell at 0x{:x}", f));
        }
        let count = self.nk_subkey_count(f);
        if count == 0 {
            return Err(format!("Key has no subkeys (looking for '{name}')"));
        }
        let list_off = self.nk_subkey_list_off(f);
        if list_off == 0xFFFFFFFF {
            return Err(format!("No subkey list (looking for '{name}')"));
        }
        self.find_in_subkey_list(list_off, name)
    }

    /// Navigate a backslash-separated path from the root key.
    pub fn path(&self, path: &str) -> Result<HiveKey, String> {
        let mut key = self.root();
        for part in path.split('\\') {
            if part.is_empty() {
                continue;
            }
            key = self.subkey(key, part)?;
        }
        Ok(key)
    }

    /// Read a named value's raw data bytes.
    pub fn value(&self, key: HiveKey, name: &str) -> Result<Vec<u8>, String> {
        let f = key.0;
        let count = self.nk_value_count(f);
        if count == 0 {
            return Err(format!("Key has no values (looking for '{name}')"));
        }
        let vl_off = self.nk_value_list_off(f);
        let vl_f = self.cell(vl_off);

        let name_upper = name.to_ascii_uppercase();
        for i in 0..count as usize {
            let vk_off = self.u32(vl_f + i * 4);
            let vk_f = self.cell(vk_off);
            if self.data[vk_f] != b'v' || self.data[vk_f + 1] != b'k' {
                continue;
            }
            let vname_len = self.u16(vk_f + 2) as usize;
            let vname = if vname_len == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(&self.data[vk_f + 20..vk_f + 20 + vname_len]).to_string()
            };
            if vname.to_ascii_uppercase() != name_upper {
                continue;
            }
            return self.read_vk_data(vk_f);
        }
        Err(format!("Value '{name}' not found"))
    }

    /// Read the class name of an NK cell.
    pub fn class_name(&self, key: HiveKey) -> Result<String, String> {
        let f = key.0;
        let cn_off = self.nk_classname_off(f);
        let cn_len = self.nk_classname_len(f) as usize;
        if cn_off == 0xFFFFFFFF || cn_len == 0 {
            return Err("No class name".into());
        }
        let cn_f = self.cell(cn_off);
        // Class names are UTF-16LE
        let bytes = &self.data[cn_f..cn_f + cn_len];
        let chars: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&chars))
    }

    /// Enumerate all direct child subkeys: (name, HiveKey).
    pub fn subkeys(&self, key: HiveKey) -> Result<Vec<(String, HiveKey)>, String> {
        let f = key.0;
        let count = self.nk_subkey_count(f);
        if count == 0 {
            return Ok(Vec::new());
        }
        let list_off = self.nk_subkey_list_off(f);
        if list_off == 0xFFFFFFFF {
            return Ok(Vec::new());
        }
        self.collect_subkey_list(list_off)
    }

    // ---------- internals ----------

    fn read_vk_data(&self, vk_f: usize) -> Result<Vec<u8>, String> {
        let data_len_raw = self.u32(vk_f + 4);
        let data_off = self.u32(vk_f + 8);

        let inline = (data_len_raw & 0x80000000) != 0;
        let data_len = (data_len_raw & 0x7FFFFFFF) as usize;

        if inline {
            // Data stored in the offset field itself (≤4 bytes)
            let len = data_len.min(4);
            Ok(self.data[vk_f + 8..vk_f + 8 + len].to_vec())
        } else if data_len == 0 {
            Ok(Vec::new())
        } else {
            let d_f = self.cell(data_off);
            if d_f + data_len > self.data.len() {
                return Err(format!(
                    "VK data out of bounds: off=0x{:x} len={}",
                    d_f, data_len
                ));
            }
            Ok(self.data[d_f..d_f + data_len].to_vec())
        }
    }

    fn find_in_subkey_list(&self, list_off: u32, name: &str) -> Result<HiveKey, String> {
        let f = self.cell(list_off);
        let sig = [self.data[f], self.data[f + 1]];
        let count = self.u16(f + 2) as usize;
        let name_upper = name.to_ascii_uppercase();

        match &sig {
            b"lf" | b"lh" => {
                // Each entry: u32 offset + u32 hash = 8 bytes
                for i in 0..count {
                    let entry_f = f + 4 + i * 8;
                    let child_off = self.u32(entry_f);
                    let child_f = self.cell(child_off);
                    if !self.nk_sig(child_f) {
                        continue;
                    }
                    if self.nk_key_name(child_f).to_ascii_uppercase() == name_upper {
                        return Ok(HiveKey(child_f));
                    }
                }
            }
            b"li" => {
                // Each entry: u32 offset = 4 bytes
                for i in 0..count {
                    let child_off = self.u32(f + 4 + i * 4);
                    let child_f = self.cell(child_off);
                    if !self.nk_sig(child_f) {
                        continue;
                    }
                    if self.nk_key_name(child_f).to_ascii_uppercase() == name_upper {
                        return Ok(HiveKey(child_f));
                    }
                }
            }
            b"ri" => {
                // Index root: entries point to other lf/lh/li lists
                for i in 0..count {
                    let sub_off = self.u32(f + 4 + i * 4);
                    if let Ok(key) = self.find_in_subkey_list(sub_off, name) {
                        return Ok(key);
                    }
                }
            }
            _ => return Err(format!("Unknown subkey list signature: {:?}", sig)),
        }
        Err(format!("Subkey '{name}' not found"))
    }

    fn collect_subkey_list(&self, list_off: u32) -> Result<Vec<(String, HiveKey)>, String> {
        let f = self.cell(list_off);
        let sig = [self.data[f], self.data[f + 1]];
        let count = self.u16(f + 2) as usize;
        let mut out = Vec::new();

        match &sig {
            b"lf" | b"lh" => {
                for i in 0..count {
                    let child_off = self.u32(f + 4 + i * 8);
                    let child_f = self.cell(child_off);
                    if self.nk_sig(child_f) {
                        out.push((self.nk_key_name(child_f), HiveKey(child_f)));
                    }
                }
            }
            b"li" => {
                for i in 0..count {
                    let child_off = self.u32(f + 4 + i * 4);
                    let child_f = self.cell(child_off);
                    if self.nk_sig(child_f) {
                        out.push((self.nk_key_name(child_f), HiveKey(child_f)));
                    }
                }
            }
            b"ri" => {
                for i in 0..count {
                    let sub_off = self.u32(f + 4 + i * 4);
                    out.extend(self.collect_subkey_list(sub_off)?);
                }
            }
            _ => return Err(format!("Unknown subkey list signature: {:?}", sig)),
        }
        Ok(out)
    }
}
