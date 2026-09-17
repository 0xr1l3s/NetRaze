//! Shared NTLMSSP + SPNEGO helpers for protocol implementations.
//!
//! LDAP uses this module directly. The established SMB and DCE/RPC NTLM
//! implementations remain separate until their migration is validated.
//!
//! MS-NLMP is the reference for every byte layout in this module.

pub mod crypto;
pub mod handshake;
pub mod message;
pub mod security;
pub mod spnego;

pub use crypto::{hmac_md5, md4, nt_hash_from_password};
pub use handshake::{NtlmAuthenticateResult, NtlmClient};
pub use message::{
    ChallengeMessage, NEGOTIATE_FLAGS, NtlmCredential, NtlmError, NtlmV2Auth,
    build_anonymous_authenticate, build_authenticate, build_negotiate, compute_ntlmv2,
    parse_challenge,
};
pub use security::NtlmSecurityContext;
pub use spnego::{
    NegState, NegTokenResp, extract_ntlmssp, ntlm_mech_types_der, parse_neg_token_resp,
    wrap_spnego_init, wrap_spnego_resp, wrap_spnego_resp_with_mic,
};
