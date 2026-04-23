//! NTLMSSP sign+seal wrapper for DCE/RPC `PKT_PRIVACY` (MS-RPCE §2.2.2.11).
//!
//! # What this module owns
//!
//! The *DCE/RPC-specific* NTLMSSP glue:
//!   - the `auth_verifier` trailer format (8-byte sec_trailer + opaque blob)
//!   - sign-then-seal (RC4 on the stub + HMAC-MD5 MIC), version-aware based
//!     on which ntlm flags were negotiated (NTLMSSP_NEGOTIATE_KEY_EXCH, etc.)
//!   - the `bind` / `auth3` / `alter_context` handshake with the server
//!
//! # What this module *does not* own
//!
//! The raw NTLMSSP negotiate → challenge → authenticate message
//! construction, NTLMv2 hash derivation, and session-key computation live
//! in `getexec-protocols::smb::ntlm` today. Phase 1 just calls into that
//! module's public API; Phase 7 extracts them here once all consumers have
//! been ported.
//!
//! This file intentionally ships as a skeleton — the real wire encoding
//! lands alongside the first RPC interface that actually needs it
//! (SRVSVC NetrShareEnum), at which point we'll also add test vectors from
//! captured Impacket traffic.

use crate::error::{DceRpcError, Result};

/// Auth levels defined in MS-RPCE §2.2.1.1.8. Only the ones we'll ever emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthLevel {
    None = 1,
    Connect = 2,
    Call = 3,
    Pkt = 4,
    PktIntegrity = 5,
    PktPrivacy = 6,
}

/// Auth types. We only do NTLMSSP (type 10) — kerberos/negoex is out of
/// scope for v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    None = 0,
    Ntlmssp = 10,
}

/// The 8-byte `sec_trailer` prefix that goes in front of every
/// `auth_verifier` blob, MS-RPCE §2.2.2.11.
#[derive(Debug, Clone, Copy)]
pub struct SecTrailer {
    pub auth_type: AuthType,
    pub auth_level: AuthLevel,
    /// Bytes of pad added to the body to align the auth_verifier on a
    /// 4-byte boundary. 0..=3.
    pub auth_pad_length: u8,
    /// Reserved — must be 0 on the wire.
    pub auth_reserved: u8,
    /// Per-interface call id for the auth verifier. Monotonic; 0 is valid.
    pub auth_context_id: u32,
}

impl SecTrailer {
    pub const SIZE: usize = 8;

    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.auth_type as u8);
        out.push(self.auth_level as u8);
        out.push(self.auth_pad_length);
        out.push(self.auth_reserved);
        out.extend_from_slice(&self.auth_context_id.to_le_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(DceRpcError::truncated(Self::SIZE, buf.len()));
        }
        let auth_type = match buf[0] {
            0 => AuthType::None,
            10 => AuthType::Ntlmssp,
            other => {
                return Err(DceRpcError::invalid(
                    "auth_type",
                    format!("unsupported {other}"),
                ));
            }
        };
        let auth_level = match buf[1] {
            1 => AuthLevel::None,
            2 => AuthLevel::Connect,
            3 => AuthLevel::Call,
            4 => AuthLevel::Pkt,
            5 => AuthLevel::PktIntegrity,
            6 => AuthLevel::PktPrivacy,
            other => {
                return Err(DceRpcError::invalid(
                    "auth_level",
                    format!("unsupported {other}"),
                ));
            }
        };
        Ok(Self {
            auth_type,
            auth_level,
            auth_pad_length: buf[2],
            auth_reserved: buf[3],
            auth_context_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }
}

/// High-level authenticator state. Phase 1 ships only the type skeleton;
/// `seal_request` / `unseal_response` land with the first NTLMSSP-signed
/// opnum call.
pub struct NtlmAuthenticator {
    pub level: AuthLevel,
    pub context_id: u32,
    /// Outgoing sequence number. Incremented per signed fragment.
    pub send_seq: u32,
    /// Incoming sequence number expected from the server.
    pub recv_seq: u32,
    /// Session key derived by NTLMSSP. Phase 1 leaves this as raw bytes —
    /// the sign/seal machinery reads it directly.
    pub session_key: [u8; 16],
}

impl NtlmAuthenticator {
    /// Seal (encrypt) and sign the given stub. Returns `(sealed_stub,
    /// auth_verifier)`. The caller splices them into a request PDU.
    ///
    /// Phase 1: not implemented — returns `NotImplemented`. Real encoding
    /// goes in alongside the first interface call.
    pub fn seal_request(&mut self, _stub: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(DceRpcError::NotImplemented(
            "NtlmAuthenticator::seal_request — lands with first NTLMSSP opnum",
        ))
    }

    /// Verify the signature on an incoming response and decrypt its stub
    /// in-place. Phase 1: not implemented.
    pub fn unseal_response(
        &mut self,
        _sealed_stub: &mut [u8],
        _auth_verifier: &[u8],
    ) -> Result<()> {
        Err(DceRpcError::NotImplemented(
            "NtlmAuthenticator::unseal_response",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_trailer_roundtrip() {
        let t = SecTrailer {
            auth_type: AuthType::Ntlmssp,
            auth_level: AuthLevel::PktPrivacy,
            auth_pad_length: 3,
            auth_reserved: 0,
            auth_context_id: 42,
        };
        let mut out = Vec::new();
        t.encode_to(&mut out);
        assert_eq!(out.len(), SecTrailer::SIZE);
        let parsed = SecTrailer::decode(&out).unwrap();
        assert_eq!(parsed.auth_type, AuthType::Ntlmssp);
        assert_eq!(parsed.auth_level, AuthLevel::PktPrivacy);
        assert_eq!(parsed.auth_pad_length, 3);
        assert_eq!(parsed.auth_context_id, 42);
    }

    #[test]
    fn sec_trailer_rejects_bad_type() {
        let bytes = [99u8, 6, 0, 0, 0, 0, 0, 0];
        assert!(SecTrailer::decode(&bytes).is_err());
    }
}
