//! `RpcChannel` — high-level DCE/RPC client built on top of [`RpcTransport`].
//!
//! Where [`crate::pdu`] handles individual fragments and [`crate::auth`]
//! handles NTLMSSP sign+seal in isolation, this module composes them into the
//! ergonomic API every interface caller actually wants:
//!
//! ```ignore
//! let mut ch = RpcChannel::bind_authenticated(transport, srvsvc::uuid(),
//!                                             (3, 0), binder).await?;
//! let stub = srvsvc::encode_netr_share_enum_request(...);
//! let resp_stub = ch.call(15, &stub).await?;
//! ```
//!
//! # Responsibilities
//!
//! - Drive the bind handshake (anonymous, or 3-leg NTLMSSP via [`NtlmBinder`])
//! - Hold the per-connection [`NtlmAuthenticator`] and apply seal/unseal to
//!   every Request/Response — callers stay oblivious to PKT_PRIVACY framing
//! - Reassemble multi-fragment responses: a single `transport.recv()` may
//!   return multiple PDUs concatenated, AND a logical response may span
//!   multiple `recv()` calls. We walk by `frag_length` and loop until
//!   `PFC_LAST_FRAG`.
//! - Surface server `Fault` PDUs as [`DceRpcError::Fault`] so callers don't
//!   silently treat them as truncated stubs.
//!
//! # Concurrency
//!
//! `call` takes `&mut self`. DCE/RPC over SMB pipes is strictly sequential
//! (`FSCTL_PIPE_TRANSCEIVE` is one-in-one-out per pipe handle), and the
//! NTLMSSP sealing keystream is inherently stateful. Callers that want
//! parallelism should open multiple pipes / multiple channels.
//!
//! # What this module does NOT do
//!
//! - Multi-fragment **request** PDUs. Every stub we currently emit fits in a
//!   single fragment (max_xmit ≥ 4280 bytes, the largest stub we ship is
//!   well under that). When that ever stops being true the call site —
//!   not [`RpcChannel`] — should split the stub at NDR-aware boundaries.
//! - `alter_context`. Once bound to one interface, a channel speaks only
//!   that interface for its lifetime. Want SAMR after SRVSVC? Open another
//!   pipe and another channel.
//! - Header signing (`PFC_SUPPORT_HEADER_SIGN`). Not negotiated; nothing in
//!   our seal layer signs the header.

use std::sync::Arc;

use crate::auth::{NtlmAuthenticator, NtlmBinder, SecTrailer};
use crate::error::{DceRpcError, Result};
use crate::pdu::{
    self, AckResult, PFC_LAST_FRAG, PacketType, PresentationContext, PresentationSyntax,
};
use crate::transport::RpcTransport;
use crate::uuid::Uuid;

/// Default presentation context id used for the first (and only) abstract
/// syntax we offer in the Bind. Servers echo this back in every Response;
/// we verify it on Response decode.
const DEFAULT_CONTEXT_ID: u16 = 0;

/// A bound DCE/RPC connection ready to serve `call(opnum, stub)` round-trips.
///
/// Construct via [`RpcChannel::bind`] (anonymous; only Samba `srvsvc`
/// accepts) or [`RpcChannel::bind_authenticated`] (NTLMSSP NTLMv2 +
/// PKT_PRIVACY — required by every other interface on Windows).
pub struct RpcChannel {
    transport: Arc<dyn RpcTransport>,
    /// Monotonic per-call id. Starts at 1 — call_id 0 is reserved by some
    /// implementations, and starting at 1 matches what Impacket emits.
    next_call_id: u32,
    context_id: u16,
    /// When `Some`, every Request stub is sealed and every Response stub is
    /// unsealed via this authenticator (which holds the per-direction RC4
    /// keystream and seq_num). When `None`, the channel is anonymous and
    /// PDUs are exchanged in plaintext with `auth_length = 0`.
    authenticator: Option<NtlmAuthenticator>,
    /// Negotiated max fragment sizes. We don't currently fragment outgoing
    /// requests, but we surface these so callers can spot a server that
    /// forced a tiny xmit cap (e.g. 1432 over routed networks).
    pub max_xmit: u16,
    pub max_recv: u16,
}

impl std::fmt::Debug for RpcChannel {
    /// Hand-written because `Arc<dyn RpcTransport>` and [`NtlmAuthenticator`]
    /// do not implement `Debug` (the trait object can't, and the
    /// authenticator deliberately keeps its keys out of any string repr).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcChannel")
            .field("authenticated", &self.authenticator.is_some())
            .field("context_id", &self.context_id)
            .field("next_call_id", &self.next_call_id)
            .field("max_xmit", &self.max_xmit)
            .field("max_recv", &self.max_recv)
            .finish_non_exhaustive()
    }
}

impl RpcChannel {
    /// Anonymous bind. The server accepts any presentation context with no
    /// authentication; on Microsoft hosts only `srvsvc` and `wkssvc`
    /// historically allowed this, and even those are locked down on modern
    /// Windows. Samba defaults still permit anonymous srvsvc — useful for
    /// testing this layer end-to-end without a credential.
    pub async fn bind(
        transport: Arc<dyn RpcTransport>,
        abstract_uuid: Uuid,
        abstract_version: (u16, u16),
    ) -> Result<Self> {
        let (max_xmit_offer, max_recv_offer) =
            (transport.max_xmit_frag(), transport.max_recv_frag());

        let ctx = build_context(abstract_uuid, abstract_version);
        let bind_pdu = pdu::encode_bind(
            initial_call_id(),
            max_xmit_offer,
            max_recv_offer,
            0,
            &[ctx],
            None,
        )?;
        transport.send(&bind_pdu).await?;

        let ack_buf = transport.recv().await?;
        let ack = pdu::decode_bind_ack(&ack_buf)?;
        check_bind_acceptance(&ack)?;

        Ok(Self {
            transport,
            next_call_id: initial_call_id() + 1,
            context_id: DEFAULT_CONTEXT_ID,
            authenticator: None,
            max_xmit: ack.max_xmit,
            max_recv: ack.max_recv,
        })
    }

    /// 3-leg NTLMSSP bind: `Bind+NEGOTIATE → BindAck+CHALLENGE →
    /// Auth3+AUTHENTICATE`. On success the returned channel seals every
    /// subsequent request with PKT_PRIVACY using the keys derived from the
    /// session.
    ///
    /// `binder` carries the NT hash + identity + auth level. It is consumed
    /// by this call — a fresh binder is required for any future rebind.
    ///
    /// The Auth3 PDU is a one-way message: the server processes it and
    /// reuses the existing TCP/SMB pipe context, with no response PDU. We
    /// rely on [`RpcTransport::send_oneway`] to suppress the spurious recv()
    /// that would otherwise hang on FSCTL_PIPE_TRANSCEIVE.
    pub async fn bind_authenticated(
        transport: Arc<dyn RpcTransport>,
        abstract_uuid: Uuid,
        abstract_version: (u16, u16),
        mut binder: NtlmBinder,
    ) -> Result<Self> {
        let (max_xmit_offer, max_recv_offer) =
            (transport.max_xmit_frag(), transport.max_recv_frag());

        let ctx = build_context(abstract_uuid, abstract_version);
        let call_id = initial_call_id();
        let bind_verifier = binder.bind_verifier();
        let bind_pdu = pdu::encode_bind(
            call_id,
            max_xmit_offer,
            max_recv_offer,
            0,
            &[ctx],
            Some(&bind_verifier),
        )?;
        transport.send(&bind_pdu).await?;

        let ack_buf = transport.recv().await?;
        let ack = pdu::decode_bind_ack(&ack_buf)?;
        check_bind_acceptance(&ack)?;

        // The server's CHALLENGE comes wrapped in a sec_trailer prefix.
        // Strip those 8 bytes before handing the raw NTLMSSP CHALLENGE to
        // the binder. We *do not* validate every sec_trailer field here —
        // the server may legitimately echo a different auth_pad_length on
        // the BindAck because the Bind itself had no encrypted body.
        if ack.server_auth_verifier.len() < SecTrailer::SIZE {
            return Err(DceRpcError::Auth(format!(
                "BindAck auth_verifier too short for sec_trailer: {} bytes",
                ack.server_auth_verifier.len()
            )));
        }
        let server_trailer = SecTrailer::decode(&ack.server_auth_verifier[..SecTrailer::SIZE])?;
        eprintln!(
            "[DEBUG] BindAck sec_trailer: auth_type={:?}, auth_level={:?}, auth_pad_length={}, auth_context_id=0x{:04x}",
            server_trailer.auth_type,
            server_trailer.auth_level,
            server_trailer.auth_pad_length,
            server_trailer.auth_context_id
        );
        if !matches!(server_trailer.auth_type, crate::auth::AuthType::Ntlmssp) {
            return Err(DceRpcError::Auth(format!(
                "BindAck auth_type: expected NTLMSSP, got {:?}",
                server_trailer.auth_type
            )));
        }
        let challenge_blob = &ack.server_auth_verifier[SecTrailer::SIZE..];
        let challenge_flags =
            u32::from_le_bytes(challenge_blob[20..24].try_into().unwrap_or_default());
        eprintln!("[DEBUG] NTLMSSP CHALLENGE flags: 0x{challenge_flags:08x}");
        binder.consume_challenge(challenge_blob)?;

        let (auth3_verifier, authenticator) = binder.finish()?;
        let auth3_pdu = pdu::encode_auth3(call_id, &auth3_verifier)?;
        // AUTH3 is one-way per MS-RPCE §2.2.2.5. send_oneway lets the
        // SMB-pipe transport issue a plain WRITE instead of TRANSCEIVE so
        // it doesn't block waiting for a response that will never come.
        transport.send_oneway(&auth3_pdu).await?;

        Ok(Self {
            transport,
            next_call_id: call_id + 1,
            context_id: DEFAULT_CONTEXT_ID,
            authenticator: Some(authenticator),
            max_xmit: ack.max_xmit,
            max_recv: ack.max_recv,
        })
    }

    /// Whether this channel is sealed (PKT_PRIVACY) or anonymous. Useful
    /// for diagnostics/logging — most callers don't care.
    pub fn is_authenticated(&self) -> bool {
        self.authenticator.is_some()
    }

    /// Issue an opnum call: encode + seal the request, drive the transport,
    /// reassemble the (possibly multi-fragment) response, unseal, and
    /// return the concatenated stub bytes.
    ///
    /// `stub` is the fully NDR-encoded input parameter block — this method
    /// does not touch the NDR layer. The returned bytes are the equivalent
    /// for the output parameters: the caller decodes via the per-interface
    /// `decode_*_response` helper.
    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let call_id = self.allocate_call_id();

        // Build the request PDU — sealed if authenticated, plain otherwise.
        let request_pdu = match self.authenticator.as_mut() {
            Some(auth) => {
                // Compute padding and final lengths so the header we sign
                // contains the exact frag_length that will appear on the wire.
                let pad_len = (4 - (stub.len() % 4)) % 4;
                let frag_len = pdu::CommonHeader::SIZE
                    + 8
                    + stub.len()
                    + pad_len
                    + crate::auth::SecTrailer::SIZE
                    + crate::auth::NTLM_SIGNATURE_SIZE;
                let mut hdr = pdu::CommonHeader::new(pdu::PacketType::Request, call_id);
                hdr.frag_length = frag_len as u16;
                hdr.auth_length = crate::auth::NTLM_SIGNATURE_SIZE as u16;

                let mut prefix = Vec::with_capacity(pdu::CommonHeader::SIZE + 8);
                hdr.encode_to(&mut prefix);
                prefix.extend_from_slice(&(stub.len() as u32).to_le_bytes());
                prefix.extend_from_slice(&self.context_id.to_le_bytes());
                prefix.extend_from_slice(&opnum.to_le_bytes());

                let (sealed_stub, auth_verifier) = auth.seal_request(&prefix, stub)?;

                let mut pdu = prefix;
                pdu.extend_from_slice(&sealed_stub);
                pdu.extend_from_slice(&auth_verifier);
                pdu
            }
            None => pdu::encode_request(call_id, self.context_id, opnum, stub, None)?,
        };
        self.transport.send(&request_pdu).await?;

        self.drain_response(call_id).await
    }

    /// Walk the response stream until we see a PDU with `PFC_LAST_FRAG`.
    ///
    /// A single `transport.recv()` may carry multiple PDUs concatenated
    /// (some servers coalesce when the response fits in one TCP segment),
    /// and a logical response may span multiple `recv()`s. Both cases are
    /// handled in one loop: we keep a `pending` byte buffer and refill from
    /// the transport whenever it runs dry.
    async fn drain_response(&mut self, expected_call_id: u32) -> Result<Vec<u8>> {
        let mut acc = Vec::new();
        let mut pending: Vec<u8> = Vec::new();

        loop {
            if pending.is_empty() {
                pending = self.transport.recv().await?;
                if pending.is_empty() {
                    return Err(DceRpcError::Transport(
                        "RpcChannel::drain_response — transport returned empty buffer".into(),
                    ));
                }
            }

            // Peek the header to know how many bytes to slice off `pending`.
            let header = pdu::peek_header(&pending)?;
            let frag_len = header.frag_length as usize;
            if pending.len() < frag_len {
                return Err(DceRpcError::truncated(frag_len, pending.len()));
            }
            let frag_bytes: Vec<u8> = pending.drain(..frag_len).collect();

            if header.call_id != expected_call_id {
                return Err(DceRpcError::Auth(format!(
                    "call_id mismatch: expected {expected_call_id}, got {}",
                    header.call_id
                )));
            }

            match header.ptype {
                PacketType::Fault => {
                    let status = pdu::decode_fault_status(&frag_bytes)?;
                    return Err(DceRpcError::Fault { status });
                }
                PacketType::Response => {
                    let resp = pdu::decode_response(&frag_bytes)?;
                    if resp.context_id != self.context_id {
                        return Err(DceRpcError::invalid(
                            "context_id",
                            format!(
                                "Response context_id {} ≠ bound {}",
                                resp.context_id, self.context_id
                            ),
                        ));
                    }
                    let prefix_len = pdu::CommonHeader::SIZE + 8;
                    let chunk = self.extract_stub_chunk(
                        &frag_bytes[..prefix_len],
                        resp.stub_data,
                        resp.auth_verifier,
                    )?;
                    acc.extend_from_slice(&chunk);

                    if header.pfc_flags & PFC_LAST_FRAG != 0 {
                        // Anything left in `pending` after the last frag is a
                        // protocol violation — the server stuffed a second
                        // logical response into our recv buffer. Surface it
                        // explicitly rather than silently dropping bytes.
                        if !pending.is_empty() {
                            return Err(DceRpcError::invalid(
                                "trailing_pdu",
                                format!("{} bytes follow the LAST_FRAG response", pending.len()),
                            ));
                        }
                        return Ok(acc);
                    }
                }
                other => {
                    return Err(DceRpcError::invalid(
                        "ptype",
                        format!("expected Response or Fault, got {other:?}"),
                    ));
                }
            }
        }
    }

    /// Decrypt a single response fragment's stub (or pass it through if
    /// anonymous), then trim the NDR-pad bytes that the server appended to
    /// align the auth_verifier on a 4-byte boundary.
    fn extract_stub_chunk(
        &mut self,
        prefix: &[u8],
        stub: &[u8],
        auth_verifier: &[u8],
    ) -> Result<Vec<u8>> {
        match self.authenticator.as_mut() {
            None => Ok(stub.to_vec()),
            Some(auth) => {
                if auth_verifier.len() < SecTrailer::SIZE {
                    return Err(DceRpcError::Auth(format!(
                        "Response auth_verifier too short: {} bytes",
                        auth_verifier.len()
                    )));
                }
                let mut sealed = stub.to_vec();
                auth.unseal_response(prefix, &mut sealed, auth_verifier)?;
                let trailer = SecTrailer::decode(&auth_verifier[..SecTrailer::SIZE])?;
                let pad = trailer.auth_pad_length as usize;
                if pad > sealed.len() {
                    return Err(DceRpcError::invalid(
                        "auth_pad_length",
                        format!("pad {pad} > stub {}", sealed.len()),
                    ));
                }
                sealed.truncate(sealed.len() - pad);
                Ok(sealed)
            }
        }
    }

    fn allocate_call_id(&mut self) -> u32 {
        let id = self.next_call_id;
        // Wrap to 1 (skip 0) — call_id 0 is reserved by some implementations.
        self.next_call_id = self.next_call_id.checked_add(1).unwrap_or(1);
        id
    }
}

/// Build the single PresentationContext we offer in every Bind: the caller's
/// abstract syntax + NDR20 transfer syntax at context_id 0.
fn build_context(abstract_uuid: Uuid, abstract_version: (u16, u16)) -> PresentationContext {
    let (major, minor) = abstract_version;
    PresentationContext {
        context_id: DEFAULT_CONTEXT_ID,
        abstract_syntax: PresentationSyntax {
            uuid: abstract_uuid,
            // MS-RPCE §2.2.2.13: interface_version = (minor << 16) | major.
            version: ((minor as u32) << 16) | (major as u32),
        },
        transfer_syntax: pdu::ndr20_transfer_syntax(),
    }
}

/// Reject any BindAck that doesn't accept our single context. Surface the
/// reason code so callers can tell `provider_rejection_reason_not_specified`
/// (typical for "interface not registered") apart from
/// `local_limit_exceeded`.
fn check_bind_acceptance(ack: &pdu::BindAckParsed) -> Result<()> {
    if ack.results.len() != 1 {
        return Err(DceRpcError::invalid(
            "bind_ack_results",
            format!("expected 1 result, got {}", ack.results.len()),
        ));
    }
    let (result, reason) = ack.results[0];
    if result != AckResult::Acceptance {
        return Err(DceRpcError::Auth(format!(
            "BindAck rejected: result={result:?} reason={reason}"
        )));
    }
    Ok(())
}

/// We start at 1 because some Windows implementations treat call_id 0 as a
/// sentinel (no current call) and reject Requests carrying it. Matches
/// Impacket's behaviour.
fn initial_call_id() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// Hand-built PDU helpers used in tests below — encoded as raw bytes because
// `pdu::encode_to` is module-private and we want to exercise corner cases
// (PFC_FIRST_FRAG without LAST_FRAG, multiple PDUs in one buffer, etc.) that
// the production encoder doesn't expose directly.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::CommonHeader;
    use crate::transport::LoopbackTransport;
    use crate::uuid::Uuid;

    /// Pin the SRVSVC UUID into one place — both bind tests and call tests
    /// use it.
    fn srvsvc_uuid() -> Uuid {
        Uuid::parse("4b324fc8-1670-01d3-1278-5a47bf6ee188").unwrap()
    }

    fn write_common_header(
        out: &mut Vec<u8>,
        ptype: PacketType,
        pfc_flags: u8,
        call_id: u32,
        frag_length: u16,
        auth_length: u16,
    ) {
        out.push(5); // rpc_vers
        out.push(0); // rpc_vers_minor
        out.push(ptype as u8);
        out.push(pfc_flags);
        out.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // drep little-endian
        out.extend_from_slice(&frag_length.to_le_bytes());
        out.extend_from_slice(&auth_length.to_le_bytes());
        out.extend_from_slice(&call_id.to_le_bytes());
    }

    /// Synthesise a BindAck with a single result entry, no auth_verifier
    /// (anonymous bind acceptance) and a 4280/4280 frag negotiation.
    fn synth_bind_ack_anonymous(call_id: u32, result: u16, reason: u16) -> Vec<u8> {
        let sec_addr: &[u8] = b"\\PIPE\\srvsvc\0";
        let mut body = Vec::new();
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
        body.extend_from_slice(&(sec_addr.len() as u16).to_le_bytes());
        body.extend_from_slice(sec_addr);
        // 4-byte alignment from start of PDU.
        let pdu_off = CommonHeader::SIZE + body.len();
        let pad = (4 - (pdu_off % 4)) % 4;
        body.extend_from_slice(&vec![0u8; pad]);
        body.push(1); // n_results
        body.extend_from_slice(&[0u8; 3]);
        body.extend_from_slice(&result.to_le_bytes());
        body.extend_from_slice(&reason.to_le_bytes());
        body.extend_from_slice(&[0u8; 20]); // transfer_syntax placeholder

        let frag_len = (CommonHeader::SIZE + body.len()) as u16;
        let mut out = Vec::with_capacity(frag_len as usize);
        write_common_header(&mut out, PacketType::BindAck, 0x03, call_id, frag_len, 0);
        out.extend_from_slice(&body);
        out
    }

    /// Synthesise a Response PDU carrying `stub` with the given pfc_flags
    /// and zero auth_verifier (matches an anonymous bind's responses).
    fn synth_response(call_id: u32, stub: &[u8], pfc_flags: u8) -> Vec<u8> {
        // Body = alloc_hint(4) + context_id(2) + cancel_count(1) + reserved(1) + stub.
        let body_len = 8 + stub.len();
        let frag_len = (CommonHeader::SIZE + body_len) as u16;
        let mut out = Vec::with_capacity(frag_len as usize);
        write_common_header(
            &mut out,
            PacketType::Response,
            pfc_flags,
            call_id,
            frag_len,
            0,
        );
        out.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        out.extend_from_slice(&DEFAULT_CONTEXT_ID.to_le_bytes()); // context_id
        out.push(0); // cancel_count
        out.push(0); // reserved
        out.extend_from_slice(stub);
        out
    }

    /// Synthesise a Fault PDU with the given NCA status code.
    fn synth_fault(call_id: u32, status: u32) -> Vec<u8> {
        // Layout: hdr(16) + alloc_hint(4) + context_id(2) + cancel_count(1) +
        // reserved(1) + status(4) + reserved2(4) = 32.
        let frag_len: u16 = (CommonHeader::SIZE + 16) as u16;
        let mut out = Vec::with_capacity(frag_len as usize);
        write_common_header(&mut out, PacketType::Fault, 0x03, call_id, frag_len, 0);
        out.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        out.extend_from_slice(&0u16.to_le_bytes()); // context_id
        out.push(0); // cancel_count
        out.push(0); // reserved
        out.extend_from_slice(&status.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        out
    }

    #[tokio::test]
    async fn bind_anonymous_round_trip() {
        let t = Arc::new(LoopbackTransport::new());
        // Loopback discards sends; we only need to inject the BindAck.
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        let ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        assert!(!ch.is_authenticated());
        assert_eq!(ch.max_xmit, 4280);
        assert_eq!(ch.max_recv, 4280);
        assert_eq!(ch.context_id, DEFAULT_CONTEXT_ID);
    }

    #[tokio::test]
    async fn bind_surfaces_provider_rejection() {
        let t = Arc::new(LoopbackTransport::new());
        // result=2 (provider_rejection), reason=1 (proposed_transfer_syntaxes_not_supported)
        t.inject_response(synth_bind_ack_anonymous(1, 2, 1));
        let err = RpcChannel::bind(t, srvsvc_uuid(), (3, 0))
            .await
            .unwrap_err();
        // Anonymous bind sets BindAck rejection as Auth (no provider context).
        match err {
            DceRpcError::Auth(msg) => {
                assert!(
                    msg.contains("ProviderRejection"),
                    "expected provider rejection in error msg, got: {msg}"
                );
            }
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_anonymous_single_fragment_response() {
        let t = Arc::new(LoopbackTransport::new());
        let stub = b"hello-from-server";
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // call_id 2 because allocator starts at initial_call_id+1 = 2 after bind.
        t.inject_response(synth_response(2, stub, 0x03)); // FIRST | LAST
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let got = ch.call(15, b"input-stub").await.unwrap();
        assert_eq!(got, stub);
    }

    #[tokio::test]
    async fn call_handles_multi_fragment_in_separate_recvs() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // Two fragments arriving in separate transport.recv() buffers.
        // First: FIRST_FRAG only. Second: LAST_FRAG only.
        t.inject_response(synth_response(2, b"first-half-", 0x01));
        t.inject_response(synth_response(2, b"second-half", 0x02));
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let got = ch.call(15, b"x").await.unwrap();
        assert_eq!(got, b"first-half-second-half");
    }

    #[tokio::test]
    async fn call_handles_multi_fragment_concatenated_in_one_recv() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // Two fragments delivered in a single recv() — server coalesced.
        let mut combined = synth_response(2, b"AAA", 0x01);
        combined.extend_from_slice(&synth_response(2, b"BBB", 0x02));
        t.inject_response(combined);
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let got = ch.call(15, b"x").await.unwrap();
        assert_eq!(got, b"AAABBB");
    }

    #[tokio::test]
    async fn call_surfaces_fault_pdu() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // 0x1C010002 = nca_s_fault_ndr (NDR decode failure on server)
        t.inject_response(synth_fault(2, 0x1C01_0002));
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let err = ch.call(15, b"x").await.unwrap_err();
        match err {
            DceRpcError::Fault { status } => assert_eq!(status, 0x1C01_0002),
            other => panic!("expected Fault, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_rejects_call_id_mismatch() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // Server replies with the wrong call_id (99 instead of 2) — must be flagged.
        t.inject_response(synth_response(99, b"oops", 0x03));
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let err = ch.call(15, b"x").await.unwrap_err();
        match err {
            DceRpcError::Auth(msg) => assert!(msg.contains("call_id mismatch")),
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_rejects_trailing_bytes_after_last_frag() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        // FIRST|LAST followed by extra junk in the same recv buffer.
        let mut combined = synth_response(2, b"OK", 0x03);
        combined.extend_from_slice(b"junk-after-last-frag");
        t.inject_response(combined);
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        let err = ch.call(15, b"x").await.unwrap_err();
        match err {
            DceRpcError::InvalidField { field, .. } => assert_eq!(field, "trailing_pdu"),
            other => panic!("expected InvalidField(trailing_pdu), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_id_increments_per_call() {
        let t = Arc::new(LoopbackTransport::new());
        t.inject_response(synth_bind_ack_anonymous(1, 0, 0));
        t.inject_response(synth_response(2, b"a", 0x03));
        t.inject_response(synth_response(3, b"b", 0x03));
        let mut ch = RpcChannel::bind(t, srvsvc_uuid(), (3, 0)).await.unwrap();
        assert_eq!(ch.call(15, b"x").await.unwrap(), b"a");
        assert_eq!(ch.call(15, b"x").await.unwrap(), b"b");
    }

    #[tokio::test]
    async fn build_context_packs_version_correctly() {
        // SRVSVC is (3, 0) → 0x0000_0003 (minor=0 in high half, major=3 in low half)
        let ctx = build_context(srvsvc_uuid(), (3, 0));
        assert_eq!(ctx.context_id, DEFAULT_CONTEXT_ID);
        assert_eq!(ctx.abstract_syntax.version, 0x0000_0003);
        // SAMR-style (1, 0) → 0x0000_0001
        let ctx2 = build_context(srvsvc_uuid(), (1, 0));
        assert_eq!(ctx2.abstract_syntax.version, 0x0000_0001);
        // Hypothetical (1, 5) → 0x0005_0001 to make sure minor is in the high half
        let ctx3 = build_context(srvsvc_uuid(), (1, 5));
        assert_eq!(ctx3.abstract_syntax.version, 0x0005_0001);
    }
}
