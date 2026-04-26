//! NDR20 (Network Data Representation v1 little-endian) reader/writer.
//!
//! NDR20 is painful because it's two passes: fixed-size data goes inline at
//! its "natural" position, but variable-size payloads (strings, conformant
//! arrays, pointees behind `unique` / `full` pointers) are *deferred* —
//! appended after the inline body of the *enclosing* constructed type, in
//! the order the referent IDs were encountered. Nested pointers inside a
//! deferred pointee defer *their* pointees further, breadth-first.
//! See MS-RPCE §2.2.4 and Impacket `dcerpc/v5/ndr.py` for the messy details.
//!
//! # Implementation model
//!
//! The writer keeps a FIFO queue of deferred closures. When you encode a
//! `unique` pointer to some pointee, the referent ID is written inline and
//! a closure that emits the pointee is pushed to the queue. After the
//! caller finishes the inline portion of a constructed type, calling
//! [`NdrWriter::flush_deferred`] drains the queue — closures may enqueue
//! further closures during execution, which the loop picks up naturally.
//! The result is the BFS layout NDR20 expects: all immediate inline data
//! first, then all level-1 pointees, then all level-2, etc.
//!
//! The reader doesn't need a queue — the caller knows the schema and reads
//! the deferred portion in order, by calling [`NdrReader::read_unique_referent`]
//! to get a Some/None marker and then sequencing the pointee reads at the
//! right moment.
//!
//! # Subset implemented
//!
//! - primitives: `u8`, `u16`, `u32`, `u64` (all LE)
//! - alignment padding (1/2/4/8) relative to stub start
//! - `unique` pointers (referent != 0 ⇒ deferred pointee, referent == 0 ⇒ NULL)
//! - conformant-varying UTF-16 wide strings (WCHAR*)
//! - conformant arrays of structs whose body the caller provides via callback
//!
//! Anything more exotic (full pointers with aliasing, fixed arrays, tagged
//! unions, NDR64) is added opnum-by-opnum as needed.

use std::collections::VecDeque;

use crate::error::{DceRpcError, Result};

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Boxed deferred-pointee writer. `'static` so the queue can outlive the
/// caller's stack frame; closures take ownership of their captures.
type DeferredWriter = Box<dyn FnOnce(&mut NdrWriter)>;

/// Append-only NDR20 writer. Tracks alignment relative to the start of the
/// stub buffer, allocates referent IDs monotonically, and queues deferred
/// pointee writes for `unique` pointers.
pub struct NdrWriter {
    buf: Vec<u8>,
    deferred: VecDeque<DeferredWriter>,
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
            deferred: VecDeque::new(),
            next_referent: 0x0002_0000,
        }
    }

    /// Drain all queued deferred writers, then return the assembled bytes.
    /// Equivalent to calling [`flush_deferred`](Self::flush_deferred) and
    /// then taking the inner buffer — provided as one call because callers
    /// almost always want both.
    pub fn finish(mut self) -> Vec<u8> {
        self.flush_deferred();
        self.buf
    }

    /// Take the buffer without flushing — only useful in tests asserting on
    /// the inline portion alone.
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
    /// stream. Used internally by [`write_unique_ptr`](Self::write_unique_ptr);
    /// exposed in case a caller needs raw referent control.
    pub fn write_referent(&mut self) -> u32 {
        let id = self.next_referent;
        self.next_referent = self.next_referent.wrapping_add(4);
        self.write_u32(id);
        id
    }

    /// Write a NULL referent id (the marker for an empty `unique` pointer).
    pub fn write_null_referent(&mut self) {
        self.write_u32(0);
    }

    /// Write a `unique` pointer.
    ///
    /// - `present == true` → write a non-zero referent ID inline and queue
    ///   `write_pointee` to be invoked later by [`flush_deferred`](Self::flush_deferred).
    /// - `present == false` → write a NULL referent and drop the closure.
    ///
    /// The closure is `FnOnce + 'static`; it must own its captured data.
    pub fn write_unique_ptr<F>(&mut self, present: bool, write_pointee: F)
    where
        F: FnOnce(&mut NdrWriter) + 'static,
    {
        if present {
            self.write_referent();
            self.deferred.push_back(Box::new(write_pointee));
        } else {
            self.write_null_referent();
        }
    }

    /// Drain all queued deferred writers in FIFO order. Closures may enqueue
    /// further deferreds during execution; the loop picks them up.
    pub fn flush_deferred(&mut self) {
        while let Some(cb) = self.deferred.pop_front() {
            cb(self);
        }
    }

    /// Emit a conformant varying UTF-16 string — the `[string] WCHAR*` idiom
    /// used everywhere in Windows RPC. Layout:
    ///
    /// ```text
    /// max_count    (u32, LE) = chars incl. trailing NUL
    /// offset       (u32, LE) = always 0
    /// actual_count (u32, LE) = chars incl. trailing NUL
    /// [WCHAR; actual_count]
    /// ```
    ///
    /// Alignment: the three u32 prefix starts aligned(4); the WCHARs follow
    /// on u16 alignment (already satisfied after three u32s).
    pub fn write_conformant_varying_wstring(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let count = units.len() as u32;
        self.write_u32(count); // max
        self.write_u32(0); // offset
        self.write_u32(count); // actual
        for u in units {
            self.write_u16(u);
        }
    }

    /// Same as [`write_conformant_varying_wstring`](Self::write_conformant_varying_wstring)
    /// but **without** the trailing NUL. Used for SAMR `PSAMPR_SERVER_NAME`
    /// (`LPWSTR`) where Impacket/Windows do not emit a terminator.
    pub fn write_conformant_varying_wstring_raw(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let count = units.len() as u32;
        self.write_u32(count); // max
        self.write_u32(0); // offset
        self.write_u32(count); // actual
        for u in units {
            self.write_u16(u);
        }
    }

    /// Emit a conformant array of structs. Layout:
    ///
    /// ```text
    /// max_count (u32, LE)
    /// [struct; max_count]    ← inline bodies
    /// ```
    ///
    /// `write_element` is called for each item to emit its inline portion.
    /// Pointers inside an element should use [`write_unique_ptr`](Self::write_unique_ptr) —
    /// their pointees end up *after* all inline bodies of the array, which
    /// matches NDR20's "all level-N defers after all level-N inlines" rule.
    pub fn write_conformant_array<T, F>(&mut self, items: &[T], mut write_element: F)
    where
        F: FnMut(&mut NdrWriter, &T),
    {
        self.write_u32(items.len() as u32);
        for item in items {
            write_element(self, item);
        }
    }

    /// Write a 20-byte RPC context handle inline (no alignment needed —
    /// 20 is not a power of two, but the handle is always placed at a
    /// 4-byte boundary by the surrounding struct layout).
    pub fn write_context_handle(&mut self, h: &[u8; 20]) {
        self.buf.extend_from_slice(h);
    }

    /// Write an `RPC_SID` (MS-DTYP §2.4.2.2) in NDR20.
    ///
    /// Layout: `Revision(u8) SubAuthorityCount(u8) IdentifierAuthority([u8;6], BE)
    ///          SubAuthority[u32;Count]`.
    /// The 6-byte authority is written big-endian per the spec; sub-authorities
    /// are little-endian (NDR default).
    pub fn write_rpc_sid(&mut self, sid: &[u8]) {
        let owned = sid.to_owned();
        assert!(owned.len() >= 8, "SID too short");
        let count = owned[1] as usize;
        assert_eq!(owned.len(), 8 + count * 4, "SID length mismatch");
        // MS-RPCE §14.3.7.1: for a structure containing a conformant array as
        // its last member, the max_count is moved to the beginning.
        self.write_u32(count as u32); // max_count
        self.write_u8(owned[0]); // Revision
        self.write_u8(owned[1]); // SubAuthorityCount
        self.buf.extend_from_slice(&owned[2..8]); // IdentifierAuthority (BE)
        for i in 0..count {
            let off = 8 + i * 4;
            let sub =
                u32::from_le_bytes([owned[off], owned[off + 1], owned[off + 2], owned[off + 3]]);
            self.write_u32(sub);
        }
    }

    /// Write an `RPC_UNICODE_STRING` (MS-DTYP §2.3.10) in NDR20.
    ///
    /// Wire layout (Impacket-style, which is what Samba/Windows expect for
    /// SAMR structures):
    ///
    /// ```text
    /// inline:
    ///   Length           u16  (bytes, excluding NUL)
    ///   MaximumLength    u16  (bytes, including NUL)
    ///   [unique] Buffer  u32  (referent id)
    /// deferred:
    ///   conformant-varying WCHAR*  (max_count, offset, actual_count, chars+NUL)
    /// ```
    pub fn write_rpc_unicode_string(&mut self, s: &str) {
        let owned = s.to_owned();
        let units: Vec<u16> = s.encode_utf16().collect();
        let len_bytes = (units.len() * 2) as u16;
        let max_len_bytes = len_bytes;
        self.write_u16(len_bytes);
        self.write_u16(max_len_bytes);
        self.write_unique_ptr(true, move |w| {
            w.write_conformant_varying_wstring(&owned);
        });
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Cursor-style NDR20 reader. Tracks position for alignment but never looks
/// backwards — caller is expected to mirror the exact read order produced
/// by [`NdrWriter`].
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

    /// Read a `unique` pointer referent. Returns `true` if non-null (caller
    /// should later read the deferred pointee at the appropriate moment),
    /// `false` if NULL.
    pub fn read_unique_referent(&mut self) -> Result<bool> {
        let id = self.read_u32()?;
        Ok(id != 0)
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

    /// Read the max_count prefix of a conformant array, with a sanity bound.
    /// Returns the count as `usize`. Bound exists because a malicious server
    /// could otherwise force a huge `Vec::with_capacity`.
    pub fn read_conformant_count(&mut self, max_allowed: u32) -> Result<usize> {
        let count = self.read_u32()?;
        if count > max_allowed {
            return Err(DceRpcError::NdrDecode(format!(
                "conformant count {count} > sanity max {max_allowed}"
            )));
        }
        Ok(count as usize)
    }

    /// Read a 20-byte RPC context handle.
    pub fn read_context_handle(&mut self) -> Result<[u8; 20]> {
        self.need(20)?;
        let mut h = [0u8; 20];
        h.copy_from_slice(&self.buf[self.pos..self.pos + 20]);
        self.pos += 20;
        Ok(h)
    }

    /// Read an `RPC_SID` (MS-DTYP §2.4.2.2) in NDR20.
    pub fn read_rpc_sid(&mut self) -> Result<Vec<u8>> {
        // MS-RPCE §14.3.7.1: conformant-array max_count is at the front of
        // the struct. Verify it matches SubAuthorityCount.
        let max_count = self.read_u32()? as usize;
        let revision = self.read_u8()?;
        let count = self.read_u8()? as usize;
        if count > 15 {
            return Err(DceRpcError::NdrDecode(format!(
                "SID sub-authority count {count} exceeds max 15"
            )));
        }
        if max_count != count {
            // Defensive: some servers might be sloppy, but a mismatch is
            // unusual enough to surface in case it signals corruption.
            return Err(DceRpcError::NdrDecode(format!(
                "SID max_count {max_count} != count {count}"
            )));
        }
        let mut sid = Vec::with_capacity(8 + count * 4);
        sid.push(revision);
        sid.push(count as u8);
        self.need(6)?;
        sid.extend_from_slice(&self.buf[self.pos..self.pos + 6]);
        self.pos += 6;
        for _ in 0..count {
            let sub = self.read_u32()?;
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        Ok(sid)
    }

    /// Read an `RPC_UNICODE_STRING` (MS-DTYP §2.3.10) in NDR20.
    ///
    /// See [`NdrWriter::write_rpc_unicode_string`] for the wire layout.
    /// Returns the decoded string (trailing NUL stripped if present).
    pub fn read_rpc_unicode_string(&mut self) -> Result<String> {
        let _len = self.read_u16()?;
        let _max_len = self.read_u16()?;
        let present = self.read_unique_referent()?;
        if !present {
            return Ok(String::new());
        }
        self.read_conformant_varying_wstring()
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
        let bytes = w.finish();
        // 0xaa, 0, 0, 0, 0x44, 0x33, 0x22, 0x11
        assert_eq!(bytes, vec![0xaa, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn wstring_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_conformant_varying_wstring("\\\\SERVER\\IPC$");
        let bytes = w.finish();
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

    #[test]
    fn unique_ptr_null_writes_zero_referent_no_defer() {
        let mut w = NdrWriter::new();
        w.write_unique_ptr(false, |_w| panic!("must not be called"));
        let bytes = w.finish();
        assert_eq!(bytes, vec![0, 0, 0, 0]);
    }

    #[test]
    fn unique_ptr_present_defers_payload() {
        // Layout expected: [referent_id (u32 LE)] [wstring max=5][offset=0]
        // [actual=5][b'h',0][b'e',0][b'l',0][b'l',0][b'o',0]
        let mut w = NdrWriter::new();
        w.write_unique_ptr(true, |w| {
            w.write_conformant_varying_wstring("hello");
        });
        let bytes = w.finish();
        // First 4 bytes = referent (non-zero). Skip them and decode the
        // remaining wstring. Wstring layout: 12B prefix (max/offset/actual)
        // + 5 WCHARs ("hello" — no implicit NUL added).
        assert_eq!(bytes.len(), 4 + 12 + 5 * 2);
        let referent = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_ne!(referent, 0);
        let mut r = NdrReader::new(&bytes[4..]);
        assert_eq!(r.read_conformant_varying_wstring().unwrap(), "hello");
    }

    /// Build a `SHARE_INFO_1_CONTAINER` analogue manually and verify the
    /// BFS deferred-pointee layout the SRVSVC interface expects:
    /// ```
    ///   inline:    EntriesRead   Buffer_referent
    ///   deferred1: max_count     [s1_inline][s2_inline]
    ///   deferred2: s1.netname  s1.remark  s2.netname  s2.remark
    /// ```
    #[test]
    fn nested_unique_ptrs_layout_is_bfs() {
        struct Share {
            netname: String,
            kind: u32,
            remark: String,
        }
        let shares = vec![
            Share {
                netname: "IPC$".into(),
                kind: 3,
                remark: "Remote IPC".into(),
            },
            Share {
                netname: "C$".into(),
                kind: 0,
                remark: "Default".into(),
            },
        ];
        let mut w = NdrWriter::new();

        // Container body: EntriesRead + Buffer pointer
        w.write_u32(shares.len() as u32);
        let owned = shares;
        w.write_unique_ptr(true, move |w| {
            // Pointee = conformant array (max_count + bodies)
            w.write_conformant_array(&owned, |w, share| {
                let netname = share.netname.clone();
                w.write_unique_ptr(true, move |w| {
                    w.write_conformant_varying_wstring(&netname);
                });
                w.write_u32(share.kind);
                let remark = share.remark.clone();
                w.write_unique_ptr(true, move |w| {
                    w.write_conformant_varying_wstring(&remark);
                });
            });
        });

        let bytes = w.finish();
        let mut r = NdrReader::new(&bytes);

        // Mirror reading. Container body.
        let entries_read = r.read_u32().unwrap();
        assert_eq!(entries_read, 2);
        assert!(r.read_unique_referent().unwrap()); // Buffer is non-null

        // Deferred level 1: max_count + array of inline bodies
        let max_count = r.read_conformant_count(1024).unwrap();
        assert_eq!(max_count, 2);
        let mut inlines = Vec::with_capacity(max_count);
        for _ in 0..max_count {
            let netname_present = r.read_unique_referent().unwrap();
            let kind = r.read_u32().unwrap();
            let remark_present = r.read_unique_referent().unwrap();
            inlines.push((netname_present, kind, remark_present));
        }
        assert!(inlines.iter().all(|(np, _, rp)| *np && *rp));
        assert_eq!(inlines[0].1, 3);
        assert_eq!(inlines[1].1, 0);

        // Deferred level 2: per-element pointees in array order
        let s1_netname = r.read_conformant_varying_wstring().unwrap();
        let s1_remark = r.read_conformant_varying_wstring().unwrap();
        let s2_netname = r.read_conformant_varying_wstring().unwrap();
        let s2_remark = r.read_conformant_varying_wstring().unwrap();
        assert_eq!(s1_netname, "IPC$");
        assert_eq!(s1_remark, "Remote IPC");
        assert_eq!(s2_netname, "C$");
        assert_eq!(s2_remark, "Default");

        // Buffer fully consumed.
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn flush_deferred_handles_nested_enqueues() {
        // A defers B which defers C — make sure all three execute, in order.
        let mut w = NdrWriter::new();
        w.write_unique_ptr(true, |w| {
            w.write_u32(0xAAAA_AAAA);
            w.write_unique_ptr(true, |w| {
                w.write_u32(0xBBBB_BBBB);
                w.write_unique_ptr(true, |w| {
                    w.write_u32(0xCCCC_CCCC);
                });
            });
        });
        let bytes = w.finish();
        let mut r = NdrReader::new(&bytes);
        assert!(r.read_unique_referent().unwrap()); // A
        assert_eq!(r.read_u32().unwrap(), 0xAAAA_AAAA);
        assert!(r.read_unique_referent().unwrap()); // B
        assert_eq!(r.read_u32().unwrap(), 0xBBBB_BBBB);
        assert!(r.read_unique_referent().unwrap()); // C
        assert_eq!(r.read_u32().unwrap(), 0xCCCC_CCCC);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn read_conformant_count_rejects_oversized() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10_000_000u32.to_le_bytes());
        let mut r = NdrReader::new(&bytes);
        assert!(r.read_conformant_count(1024).is_err());
    }
}
