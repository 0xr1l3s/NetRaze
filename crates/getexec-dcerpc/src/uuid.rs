//! Tiny UUID type — we don't take a `uuid` crate dependency because we only
//! need:
//!   - DCE/RPC "little-endian on the wire" encoding (different from RFC 4122)
//!   - const construction from string literals, for interface UUIDs
//!   - equality + Debug for testing
//!
//! MS-RPCE uses the first three fields in little-endian byte order and the
//! last two (clock_seq + node) in big-endian. Most Rust uuid crates default
//! to RFC 4122 big-endian, which trips people up. Rolling our own keeps the
//! expectation explicit at the call site.

use std::fmt;

use crate::error::DceRpcError;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid {
    /// Canonical byte layout: `time_low (LE) | time_mid (LE) | time_hi (LE) |
    /// clock_seq_hi | clock_seq_lo | node[6]`. Total 16 bytes.
    bytes: [u8; 16],
}

impl Uuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Parse `"12345678-1234-1234-1234-123456789abc"` into our wire layout.
    /// Returns `InvalidField` on any malformed input.
    pub fn parse(s: &str) -> Result<Self, DceRpcError> {
        if s.len() != 36 {
            return Err(DceRpcError::invalid("uuid", format!("length {}", s.len())));
        }
        let b = s.as_bytes();
        if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return Err(DceRpcError::invalid("uuid", "missing separators"));
        }
        let hex = |lo, hi| -> Result<u8, DceRpcError> {
            let decode = |c: u8| -> Result<u8, DceRpcError> {
                match c {
                    b'0'..=b'9' => Ok(c - b'0'),
                    b'a'..=b'f' => Ok(c - b'a' + 10),
                    b'A'..=b'F' => Ok(c - b'A' + 10),
                    _ => Err(DceRpcError::invalid("uuid", "non-hex char")),
                }
            };
            Ok(decode(lo)? << 4 | decode(hi)?)
        };
        // Walk the ascii parse: groups at offsets 0..8, 9..13, 14..18,
        // 19..23, 24..36 — these are the 5 canonical hyphen-separated
        // sections of a UUID.
        let groups: [&[u8]; 5] = [&b[0..8], &b[9..13], &b[14..18], &b[19..23], &b[24..36]];
        let mut out = [0u8; 16];

        // Fields 1–3 are little-endian on the MS-RPCE wire.
        let mut write_le = |dst_start: usize, dst_len: usize, group: &[u8]| -> Result<(), DceRpcError> {
            // group length is always 2 * dst_len (e.g. 8 chars for 4 bytes)
            for i in 0..dst_len {
                let b0 = group[i * 2];
                let b1 = group[i * 2 + 1];
                // Write byte `i` of the integer to position
                // (dst_start + dst_len - 1 - i) so the LSB of the
                // big-endian hex string lands at the *lowest* wire offset.
                out[dst_start + dst_len - 1 - i] = hex(b0, b1)?;
            }
            Ok(())
        };
        write_le(0, 4, groups[0])?; // time_low
        write_le(4, 2, groups[1])?; // time_mid
        write_le(6, 2, groups[2])?; // time_hi_and_version

        // Fields 4 and 5 are big-endian on the wire.
        let write_be = |dst: &mut [u8], group: &[u8]| -> Result<(), DceRpcError> {
            for i in 0..dst.len() {
                dst[i] = hex(group[i * 2], group[i * 2 + 1])?;
            }
            Ok(())
        };
        write_be(&mut out[8..10], groups[3])?;
        write_be(&mut out[10..16], groups[4])?;
        Ok(Self { bytes: out })
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.bytes;
        // Reverse LE fields when rendering so round-tripping `parse` →
        // `Debug` gives back the original canonical string.
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0],
            b[5], b[4],
            b[7], b[6],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srvsvc_uuid_roundtrip() {
        // MS-SRVS well-known interface UUID
        let s = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
        let u = Uuid::parse(s).expect("parse");
        assert_eq!(format!("{u}"), s);
        // Wire bytes: first 3 fields LE, last 2 BE.
        assert_eq!(u.as_bytes()[0], 0xc8);
        assert_eq!(u.as_bytes()[3], 0x4b);
        assert_eq!(u.as_bytes()[8], 0x12);
        assert_eq!(u.as_bytes()[15], 0x88);
    }

    #[test]
    fn reject_malformed() {
        assert!(Uuid::parse("not-a-uuid").is_err());
        assert!(Uuid::parse("4b324fc8-1670-01d3-1278-5a47bf6ee18").is_err()); // too short
        assert!(Uuid::parse("4b324fc8x1670-01d3-1278-5a47bf6ee188").is_err()); // bad separator
    }
}
