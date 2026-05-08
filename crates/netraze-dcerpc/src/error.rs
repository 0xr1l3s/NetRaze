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
    InvalidField { field: &'static str, detail: String },

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
    #[error("server returned RPC fault: status=0x{status:08x} ({})", explain_rpc_fault(*status))]
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

/// Human-readable explanation for the most common RPC fault status codes
/// we see in the wild. Surfaced inside the `Fault` Display impl so the
/// operator gets context (and a hint where to look) instead of a bare
/// hex code.
///
/// References:
/// - `[MS-RPCE]` §3.1.1.5.5 — RPC fault codes
/// - `winerror.h` — Win32 error codes (some are mapped 1:1 by the runtime)
/// - Impacket `dcerpc/v5/rpcrt.py` — same codes surfaced in `DCERPCException`
fn explain_rpc_fault(status: u32) -> &'static str {
    match status {
        // ── Standard DCE/RPC fault codes (1c01xxxx, MS-RPCE §3.1.1.5.5) ──
        0x1C01_0001 => "nca_s_fault_other",
        0x1C01_0002 => "nca_s_fault_access_denied — credentials valid but ACL denies the call",
        0x1C01_0003 => "nca_s_fault_cant_perform — server can't perform the requested op",
        0x1C00_001C => "nca_s_fault_int_div_by_zero",
        0x1C00_001D => "nca_s_fault_addr_error",
        0x1C00_001E => "nca_s_fault_fp_div_zero",
        0x1C00_001F => "nca_s_fault_fp_underflow",
        0x1C00_0020 => "nca_s_fault_fp_overflow",
        0x1C00_0021 => "nca_s_fault_invalid_tag",
        0x1C00_0022 => "nca_s_fault_invalid_bound",
        0x1C00_0023 => "nca_s_rpc_version_mismatch — connection RPC version mismatch",
        0x1C00_0024 => "nca_s_unspec_reject",
        0x1C00_0025 => "nca_s_bad_actid",
        0x1C00_0026 => "nca_s_who_are_you_failed",
        0x1C00_0027 => "nca_s_manager_not_entered",
        0x1C00_0028 => "nca_s_fault_cancel",
        0x1C00_0029 => "nca_s_fault_ill_inst",
        0x1C00_002A => "nca_s_fault_fp_error",
        0x1C00_002B => "nca_s_fault_int_overflow",
        0x1C00_002E => "nca_s_fault_unspec",
        0x1C04_0001 => "nca_s_fault_remote_comm_failure",
        0x1C04_0002 => "nca_s_fault_pipe_empty",
        0x1C04_0003 => "nca_s_fault_pipe_closed",
        0x1C04_0004 => "nca_s_fault_pipe_order",
        0x1C04_0005 => "nca_s_fault_pipe_discipline",
        0x1C04_0006 => "nca_s_fault_pipe_comm_error",
        0x1C04_0007 => "nca_s_fault_pipe_memory",
        0x1C04_0008 => "nca_s_fault_context_mismatch",
        0x1C04_0009 => "nca_s_fault_remote_no_memory",
        0x1C04_0014 => "nca_s_invalid_pres_context_id — bind context_id mismatch",

        // ── Win32 RPC errors (winerror.h, surfaced as fault by some servers) ──
        0x0000_06D1 => "RPC_S_PROCNUM_OUT_OF_RANGE — opnum doesn't exist on this interface version",
        0x0000_06D8 => "EPT_S_NOT_REGISTERED — endpoint mapper has no entry for this interface",
        0x0000_06E4 => "RPC_S_CANNOT_SUPPORT — server's RPC runtime refused the call. \
                       Common causes: (1) auth_context_id == 0 (we now mirror Impacket's +79231 offset); \
                       (2) NEGOTIATE_TARGET_INFO flag missing (now set); \
                       (3) auth level mismatch between Bind and Request (we use PKT_PRIVACY); \
                       (4) NDR transfer syntax mismatch (we negotiate NDR20); \
                       (5) hardened server policy (e.g. Server 2019+ 'Restrict NTLM' or \
                       'Service Control Manager Remote Access' GPO denies SCMR over NP — \
                       try Kerberos auth or test from a host inside the trust)",
        0x0000_06F7 => "RPC_X_BAD_STUB_DATA — server can't unmarshal our payload. \
                       Usually a [string] WCHAR* missing its NUL terminator, \
                       or a union discriminator/body mismatch",
        0x0000_06F5 => "RPC_X_INVALID_BOUND — conformant array bound exceeded",
        0x0000_06F6 => "RPC_X_INVALID_TAG — discriminated union tag invalid",
        0x0000_0721 => "RPC_S_SEC_PKG_ERROR — security package (NTLMSSP) failed mid-call. \
                       Usually means our seal/sign keys diverged from the server's after a sealed Request",
        0x0000_0717 => "RPC_S_PROTECT_LEVEL_MISMATCH — auth level on Request differs from bind",
        _ => "see [MS-ERREF] / winerror.h for this status code",
    }
}
