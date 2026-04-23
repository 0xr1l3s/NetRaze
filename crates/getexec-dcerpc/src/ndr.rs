//! NDR20 (Network Data Representation v1 little-endian) reader/writer.
//!
//! NDR20 is painful because it's two passes: fixed-size data goes inline at
//! its "natural" position, but variable-size payloads (strings, conformant
//! arrays, pointees behind `ref` / `unique` pointers) are *deferred* —
//! appended after the fixed layout in the order the pointers were
//! encountered. Nested pointers inside a deferred pointee defer *their*
//! pointees further. See MS-RPCE §2.2.4 and Impacket `dcerpc/v5/ndr.py` for
//! the ugly details.
//!
//! This module implements only the subset we actually need on the wire:
//!   - primitives: u8, u16, u32, u64 (all LE)
//!   - alignment padding (1/2/4/8)
//!   - `referent_id` handling (unique pointers)
//!   - conformant varying wide strings (WCHAR*) — the common case for
//!     Windows RPC method parameters
//!   - conformant arrays of primitive types (used for enum results)
//!
//! Anything more exotic (full deferred-pointer chaining across structs, fixed
//! arrays, tagged unions) gets added opnum-by-opnum as needed.

use crate::error::{DceRpcError, Result};

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Append-only NDR20 writer. Tracks alignment relative to the start of the
/// stub buffer and allocates referent IDs monotonically.
pub struct NdrWriter {
    buf: Vec<u8>,
    /// Monotonic referent counter. NDR specifies non-zero values; Windows
    /// commonly starts at 0x00020000 and increments by 4.
    next_referent: u32,
}

impl Default for NdrWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl NdrWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            next_referent: 0x0002_0000,
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Pad so the next write starts on an `align`-byte boundary relative to
    /// the *start* of the stub (which is how NDR20 alignment is defined).
    pub fn align(&mut self, align: usize) {
        debug_assert!(align.is_power_of_two(), "align must be power of two");
        let pad = (align - (self.buf.len() % align)) % align;
        for _ in 0..pad {
            self.buf.push(0);
        }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Reserve and return a fresh non-zero referent ID and write it into the
    /// stream. Used for `unique` pointers; returns the ID in case the caller
    /// wants to stash it for a later deferred write.
    pub fn write_referent(&mut self) -> u32 {
        let id = self.next_referent;
        self.next_referent = self.next_referent.wrapping_add(4);
        self.write_u32(id);
        id
    }

    /// Write a NULL referent id. Used for nullable `unique` pointers that
    /// are currently `None`.
    pub fn write_null_referent(&mut self) {
        self.write_u32(0);
    }

    /// Emit a conformant varying UTF-16 string — the `[string]
    /// WCHAR*` idiom used everywhere in Windows RPC. Layout:
    ///
    /// ```text
    /// max_count  (u32, LE) = chars incl. trailing NUL
    /// offset     (u32, LE) = always 0
    /// actual_count (u32, LE) = chars incl. trailing NUL
    /// [WCHAR; actual_count]
    /// ```
    ///
    /// Alignment: the three u32 prefix starts aligned(4); the WCHARs follow
    /// on u16 alignment (already satisfied after three u32s).
    pub fn write_conformant_varying_wstring(&mut self, s: &str) {
        // Encode input into UTF-16 and append a trailing NUL.
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.push(0);
        let count = units.len() as u32;
        self.write_u32(count); // max
        self.write_u32(0); // offset
        self.write_u32(count); // actual
        for u in units {
            self.write_u16(u);
        }
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Cursor-style NDR20 reader. Tracks position for alignment but never looks
/// backwards — caller is expected to mirror the exact read order.
pub struct NdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn align(&mut self, align: usize) {
        debug_assert!(align.is_power_of_two(), "align must be power of two");
        let pad = (align - (self.pos % align)) % align;
        self.pos = self.pos.saturating_add(pad);
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(DceRpcError::truncated(self.pos + n, self.buf.len()))
        } else {
            Ok(())
        }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        self.align(2);
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        self.align(4);
        self.need(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        self.align(8);
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }

    /// Read the counterpart of [`NdrWriter::write_conformant_varying_wstring`].
    /// Returns the decoded Rust `String` (trailing NUL stripped).
    pub fn read_conformant_varying_wstring(&mut self) -> Result<String> {
        let max = self.read_u32()? as usize;
        let _offset = self.read_u32()?;
        let actual = self.read_u32()? as usize;
        if actual > max {
            return Err(DceRpcError::NdrDecode(format!(
                "wstring actual {actual} > max {max}"
            )));
        }
        // Sanity cap: 64 KiB of WCHAR is absurdly large for RPC strings.
        if actual > 0x1_0000 {
            return Err(DceRpcError::NdrDecode(format!(
                "wstring actual {actual} exceeds 64KiB sanity cap"
            )));
        }
        let mut units = Vec::with_capacity(actual);
        for _ in 0..actual {
            units.push(self.read_u16()?);
        }
        // Strip trailing NUL if present.
        if units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units)
            .map_err(|e| DceRpcError::NdrDecode(format!("invalid utf16: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_alignment_adds_padding() {
        let mut w = NdrWriter::new();
        w.write_u8(0xaa);
        w.write_u32(0x1122_3344);
        let bytes = w.into_vec();
        // 0xaa, 0, 0, 0, 0x44, 0x33, 0x22, 0x11
        assert_eq!(bytes, vec![0xaa, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn wstring_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_conformant_varying_wstring("\\\\SERVER\\IPC$");
        let bytes = w.into_vec();
        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_conformant_varying_wstring().unwrap();
        assert_eq!(decoded, "\\\\SERVER\\IPC$");
    }

    #[test]
    fn wstring_rejects_truncated() {
        // max=5, offset=0, actual=5, but only 2 WCHARs follow -> truncated
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&[b'a', 0, b'b', 0]);
        let mut r = NdrReader::new(&bytes);
        assert!(r.read_conformant_varying_wstring().is_err());
    }

    #[test]
    fn referent_ids_are_nonzero_and_incrementing() {
        let mut w = NdrWriter::new();
        let a = w.write_referent();
        let b = w.write_referent();
        assert_ne!(a, 0);
        assert_eq!(b, a.wrapping_add(4));
    }
}
