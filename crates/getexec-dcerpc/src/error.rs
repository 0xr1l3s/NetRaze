//! Crate-wide error type. One enum for PDU parse failures, NDR decode
//! problems, NTLMSSP negotiation failures, and transport-level IO errors —
//! so callers can match on the kind but still get a `Display` for logs.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DceRpcError>;

#[derive(Debug, Error)]
pub enum DceRpcError {
    /// The received buffer is shorter than required, or claims a length
    /// that doesn't fit the header.
    #[error("truncated PDU: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },

    /// A header field carried a value we don't recognise (bad ptype,
    /// unknown auth type, wrong rpc_vers, …).
    #[error("invalid field `{field}`: {detail}")]
    InvalidField {
        field: &'static str,
        detail: String,
    },

    /// Decoded an NDR pointer we've never seen on the wire before, or a
    /// conformance count that exceeds the containing buffer.
    #[error("ndr decode error: {0}")]
    NdrDecode(String),

    /// Encoding would exceed the max transmit fragment size negotiated at
    /// bind time. Caller should fragment the request.
    #[error("encoded request exceeds max fragment size ({size} > {limit})")]
    FragmentTooLarge { size: usize, limit: usize },

    /// Authenticator (NTLMSSP) rejected the bind or alter_context, or the
    /// checksum/seal on an incoming fragment did not verify.
    #[error("authentication error: {0}")]
    Auth(String),

    /// Server returned a `fault` PDU. `status` is the wire DCE/RPC status
    /// (0x1c010003 etc.) — callers usually map it to NTSTATUS themselves.
    #[error("server returned RPC fault: status=0x{status:08x}")]
    Fault { status: u32 },

    /// Transport layer (SMB pipe, TCP 135) failure.
    #[error("transport error: {0}")]
    Transport(String),

    /// Functionality not yet implemented in this Phase 1 scaffold. Kept as a
    /// first-class variant so callers can detect stubs explicitly rather
    /// than string-matching.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

impl DceRpcError {
    pub(crate) fn truncated(need: usize, have: usize) -> Self {
        Self::Truncated { need, have }
    }

    pub(crate) fn invalid(field: &'static str, detail: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            detail: detail.into(),
        }
    }
}
