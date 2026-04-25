//! DCE/RPC v5 connection-oriented PDU layer (MS-RPCE §2.2).
//!
//! Every CO PDU begins with the same 16-byte common header followed by
//! ptype-specific fields and optionally an `auth_verifier` at the very end.
//! This module models the common header and the fragment types we actually
//! generate client-side: `bind`, `bind_ack`, `alter_context`,
//! `alter_context_resp`, `auth3`, `request`, `response`, `fault`.
//!
//! We intentionally do NOT model every field on every fragment — only the
//! fields our client cares about. The encoder writes minimal well-formed
//! fragments; the decoder peeks the common header and parses only the
//! ptype-specific fields a client needs to react to.

use crate::error::{DceRpcError, Result};
use crate::uuid::Uuid;

/// DCE/RPC common header — 16 bytes on the wire, MS-RPCE §2.2.6.1.
#[derive(Debug, Clone, Copy)]
pub struct CommonHeader {
    pub rpc_vers: u8,
    pub rpc_vers_minor: u8,
    pub ptype: PacketType,
    pub pfc_flags: u8,
    /// `[0]` = integer repr (0x10 = little-endian), `[1]` = char repr (0x00 = ASCII),
    /// `[2]` = float repr (0x00 = IEEE), `[3]` reserved.
    pub drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl CommonHeader {
    pub const SIZE: usize = 16;

    pub fn new(ptype: PacketType, call_id: u32) -> Self {
        Self {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            ptype,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            drep: [0x10, 0x00, 0x00, 0x00],
            frag_length: 0, // encoder fills in
            auth_length: 0, // encoder fills in
            call_id,
        }
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.rpc_vers);
        out.push(self.rpc_vers_minor);
        out.push(self.ptype as u8);
        out.push(self.pfc_flags);
        out.extend_from_slice(&self.drep);
        out.extend_from_slice(&self.frag_length.to_le_bytes());
        out.extend_from_slice(&self.auth_length.to_le_bytes());
        out.extend_from_slice(&self.call_id.to_le_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(DceRpcError::truncated(Self::SIZE, buf.len()));
        }
        let ptype = PacketType::from_u8(buf[2])
            .ok_or_else(|| DceRpcError::invalid("ptype", format!("0x{:02x}", buf[2])))?;
        if buf[0] != 5 {
            return Err(DceRpcError::invalid(
                "rpc_vers",
                format!("expected 5, got {}", buf[0]),
            ));
        }
        // MS-RPCE currently only defines minor versions 0 (NDR20) and 1
        // (NDR64). We reject anything else so we don't silently mis-decode.
        if buf[1] > 1 {
            return Err(DceRpcError::invalid(
                "rpc_vers_minor",
                format!("{}", buf[1]),
            ));
        }
        Ok(Self {
            rpc_vers: buf[0],
            rpc_vers_minor: buf[1],
            ptype,
            pfc_flags: buf[3],
            drep: [buf[4], buf[5], buf[6], buf[7]],
            frag_length: u16::from_le_bytes([buf[8], buf[9]]),
            auth_length: u16::from_le_bytes([buf[10], buf[11]]),
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

/// `PFC_*` flags from MS-RPCE §2.2.6.1. Only the ones we actually use.
pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
pub const PFC_PENDING_CANCEL: u8 = 0x04;
pub const PFC_SUPPORT_HEADER_SIGN: u8 = 0x04; // same bit, different ptype
pub const PFC_CONC_MPX: u8 = 0x10;
pub const PFC_DID_NOT_EXECUTE: u8 = 0x20;
pub const PFC_OBJECT_UUID: u8 = 0x80;

/// DCE/RPC PDU type (ptype). MS-RPCE §2.2.6.1 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Request = 0,
    Ping = 1,
    Response = 2,
    Fault = 3,
    Working = 4,
    Nocall = 5,
    Reject = 6,
    Ack = 7,
    ClCancel = 8,
    FAck = 9,
    CancelAck = 10,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
    Auth3 = 16,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Request,
            1 => Self::Ping,
            2 => Self::Response,
            3 => Self::Fault,
            4 => Self::Working,
            5 => Self::Nocall,
            6 => Self::Reject,
            7 => Self::Ack,
            8 => Self::ClCancel,
            9 => Self::FAck,
            10 => Self::CancelAck,
            11 => Self::Bind,
            12 => Self::BindAck,
            13 => Self::BindNak,
            14 => Self::AlterContext,
            15 => Self::AlterContextResp,
            16 => Self::Auth3,
            17 => Self::Shutdown,
            18 => Self::CoCancel,
            19 => Self::Orphaned,
            _ => return None,
        })
    }
}

/// Abstract syntax + transfer syntax pair advertised in `bind` / `bind_ack`.
/// MS-RPCE §2.2.2.13.
#[derive(Debug, Clone, Copy)]
pub struct PresentationSyntax {
    pub uuid: Uuid,
    pub version: u32,
}

/// Well-known NDR20 transfer syntax.
/// `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.
pub fn ndr20_transfer_syntax() -> PresentationSyntax {
    PresentationSyntax {
        uuid: Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b104860").expect("static uuid"),
        version: 2,
    }
}

/// A single presentation context offered in a `bind` request. The server
/// accepts or rejects each one independently in the `bind_ack`.
#[derive(Debug, Clone, Copy)]
pub struct PresentationContext {
    pub context_id: u16,
    pub abstract_syntax: PresentationSyntax,
    pub transfer_syntax: PresentationSyntax,
}

/// Encode a `bind` PDU. MS-RPCE §2.2.2.13. `auth_verifier`, if present,
/// goes at the end and its length is recorded in the common header.
pub fn encode_bind(
    call_id: u32,
    max_xmit_frag: u16,
    max_recv_frag: u16,
    assoc_group_id: u32,
    contexts: &[PresentationContext],
    auth_verifier: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if contexts.is_empty() || contexts.len() > 255 {
        return Err(DceRpcError::invalid(
            "contexts",
            format!("must be 1..=255, got {}", contexts.len()),
        ));
    }
    let mut hdr = CommonHeader::new(PacketType::Bind, call_id);

    // Reserve 16 bytes for the common header; we'll backfill lengths.
    let mut buf = Vec::with_capacity(64 + contexts.len() * 44);
    buf.resize(CommonHeader::SIZE, 0);

    buf.extend_from_slice(&max_xmit_frag.to_le_bytes());
    buf.extend_from_slice(&max_recv_frag.to_le_bytes());
    buf.extend_from_slice(&assoc_group_id.to_le_bytes());

    // p_context_elem list: count (u8) + 3 bytes padding + entries.
    buf.push(contexts.len() as u8);
    buf.extend_from_slice(&[0u8; 3]);

    for ctx in contexts {
        buf.extend_from_slice(&ctx.context_id.to_le_bytes());
        // n_transfer_syn + reserved
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(ctx.abstract_syntax.uuid.as_bytes());
        buf.extend_from_slice(&ctx.abstract_syntax.version.to_le_bytes());
        buf.extend_from_slice(ctx.transfer_syntax.uuid.as_bytes());
        buf.extend_from_slice(&ctx.transfer_syntax.version.to_le_bytes());
    }

    let auth_len = match auth_verifier {
        Some(av) => {
            buf.extend_from_slice(av);
            u16::try_from(av.len())
                .map_err(|_| DceRpcError::invalid("auth_verifier", "length exceeds u16"))?
        }
        None => 0,
    };

    // Total must fit in u16. Typical max is 4280 (Windows default).
    let frag_len = u16::try_from(buf.len()).map_err(|_| DceRpcError::FragmentTooLarge {
        size: buf.len(),
        limit: u16::MAX as usize,
    })?;
    hdr.frag_length = frag_len;
    hdr.auth_length = auth_len;

    // Backfill the common header into the first 16 bytes.
    let mut hdr_buf = Vec::with_capacity(CommonHeader::SIZE);
    hdr.encode_to(&mut hdr_buf);
    buf[..CommonHeader::SIZE].copy_from_slice(&hdr_buf);
    Ok(buf)
}

/// Encode a `request` PDU (opnum call). Stub payload is passed in as
/// already-NDR-encoded bytes. MS-RPCE §2.2.2.10.
pub fn encode_request(
    call_id: u32,
    context_id: u16,
    opnum: u16,
    stub_data: &[u8],
    auth_verifier: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut hdr = CommonHeader::new(PacketType::Request, call_id);
    let mut buf = Vec::with_capacity(CommonHeader::SIZE + 8 + stub_data.len());
    buf.resize(CommonHeader::SIZE, 0);

    let alloc_hint: u32 = u32::try_from(stub_data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&alloc_hint.to_le_bytes());
    buf.extend_from_slice(&context_id.to_le_bytes());
    buf.extend_from_slice(&opnum.to_le_bytes());

    // NB: when PFC_OBJECT_UUID is set, an object UUID goes here — not
    // needed for SRVSVC/SAMR/etc. so we don't set that flag.

    buf.extend_from_slice(stub_data);

    let auth_len = match auth_verifier {
        Some(av) => {
            buf.extend_from_slice(av);
            u16::try_from(av.len())
                .map_err(|_| DceRpcError::invalid("auth_verifier", "length exceeds u16"))?
        }
        None => 0,
    };

    let frag_len = u16::try_from(buf.len()).map_err(|_| DceRpcError::FragmentTooLarge {
        size: buf.len(),
        limit: u16::MAX as usize,
    })?;
    hdr.frag_length = frag_len;
    hdr.auth_length = auth_len;
    let mut hdr_buf = Vec::with_capacity(CommonHeader::SIZE);
    hdr.encode_to(&mut hdr_buf);
    buf[..CommonHeader::SIZE].copy_from_slice(&hdr_buf);
    Ok(buf)
}

/// Minimal view of a parsed `response` PDU — just enough for callers to get
/// at the stub payload.
#[derive(Debug, Clone)]
pub struct ResponsePdu<'a> {
    pub header: CommonHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub stub_data: &'a [u8],
    pub auth_verifier: &'a [u8],
}

/// Decode the first PDU in `buf`. Returns the parsed common header plus a
/// type-specific view. Fragment reassembly (PFC_FIRST_FRAG/PFC_LAST_FRAG) is
/// the caller's job.
pub fn peek_header(buf: &[u8]) -> Result<CommonHeader> {
    CommonHeader::decode(buf)
}

/// Parse a `response` PDU. Assumes `buf` is exactly one fragment of
/// length `header.frag_length`.
pub fn decode_response(buf: &[u8]) -> Result<ResponsePdu<'_>> {
    let header = CommonHeader::decode(buf)?;
    if header.ptype != PacketType::Response {
        return Err(DceRpcError::invalid(
            "ptype",
            format!("expected Response, got {:?}", header.ptype),
        ));
    }
    let frag_len = header.frag_length as usize;
    if buf.len() < frag_len || frag_len < CommonHeader::SIZE + 8 {
        return Err(DceRpcError::truncated(frag_len, buf.len()));
    }
    let body = &buf[..frag_len];
    let after_hdr = CommonHeader::SIZE;
    let alloc_hint = u32::from_le_bytes([
        body[after_hdr],
        body[after_hdr + 1],
        body[after_hdr + 2],
        body[after_hdr + 3],
    ]);
    let context_id = u16::from_le_bytes([body[after_hdr + 4], body[after_hdr + 5]]);
    let cancel_count = body[after_hdr + 6];
    // body[after_hdr + 7] is a reserved byte.

    let auth_len = header.auth_length as usize;
    let stub_end = frag_len
        .checked_sub(auth_len)
        .ok_or_else(|| DceRpcError::invalid("auth_length", "exceeds frag_length"))?;
    let stub_data = &body[after_hdr + 8..stub_end];
    let auth_verifier = &body[stub_end..frag_len];

    Ok(ResponsePdu {
        header,
        alloc_hint,
        context_id,
        cancel_count,
        stub_data,
        auth_verifier,
    })
}

/// `p_result_t.result` values from the BindAck per MS-RPCE §2.2.2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AckResult {
    Acceptance = 0,
    UserRejection = 1,
    ProviderRejection = 2,
    /// Encountered values outside the spec are mapped here so the caller can
    /// surface a precise error rather than silently treating them as accepted.
    Unknown = u16::MAX,
}

impl AckResult {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Acceptance,
            1 => Self::UserRejection,
            2 => Self::ProviderRejection,
            _ => Self::Unknown,
        }
    }
}

/// Parsed view of a BindAck PDU. We surface only what the client must act on:
///
///   - `max_xmit` / `max_recv` — the negotiated fragment caps; the caller
///     compares them against its own request and uses the smaller value.
///   - `assoc_group_id` — must echo what was sent (or be the server's
///     assignment if 0 was requested); we don't enforce this here.
///   - `results` — one entry per offered presentation context, in the same
///     order as the Bind. The caller iterates and aborts if any required
///     context wasn't `Acceptance`.
///   - `server_auth_verifier` — the raw `auth_verifier` blob (including the
///     8-byte `sec_trailer` prefix). For NTLMSSP this is the CHALLENGE
///     wrapper; the caller strips the trailer and feeds the remainder to
///     [`crate::auth::NtlmBinder::consume_challenge`].
#[derive(Debug, Clone)]
pub struct BindAckParsed {
    pub header: CommonHeader,
    pub max_xmit: u16,
    pub max_recv: u16,
    pub assoc_group_id: u32,
    /// `(result, reason)` per offered context. `reason` is informational —
    /// MS-RPCE §2.2.2.4 reasons are useful for diagnostics but never required
    /// to drive client behavior.
    pub results: Vec<(AckResult, u16)>,
    pub server_auth_verifier: Vec<u8>,
}

/// Decode a BindAck PDU. Layout per MS-RPCE §2.2.2.4:
///
/// ```text
///     common_header (16)
///     max_xmit_frag (u16)
///     max_recv_frag (u16)
///     assoc_group_id (u32)
///     sec_addr_length (u16)
///     sec_addr (variable, NUL-terminated, no padding inside)
///     [pad to 4-byte boundary from start of PDU]
///     n_results (u8) + 3 bytes pad
///     results[n_results]:  ack_result(u16) + ack_reason(u16) +
///                          transfer_syntax (UUID + version) — 24 bytes each
///     [auth_verifier]
/// ```
///
/// Defensive against truncation at every step. The `sec_addr` field's
/// NUL terminator IS counted in `sec_addr_length`, so a length of 0 means
/// "no secondary address", and a typical Samba reply has length 11 for
/// `\PIPE\srvsvc\0`.
pub fn decode_bind_ack(buf: &[u8]) -> Result<BindAckParsed> {
    let header = CommonHeader::decode(buf)?;
    if header.ptype != PacketType::BindAck {
        return Err(DceRpcError::invalid(
            "ptype",
            format!("expected BindAck, got {:?}", header.ptype),
        ));
    }
    let frag_len = header.frag_length as usize;
    if buf.len() < frag_len {
        return Err(DceRpcError::truncated(frag_len, buf.len()));
    }
    let body = &buf[..frag_len];
    let auth_len = header.auth_length as usize;
    let stub_end = frag_len
        .checked_sub(auth_len)
        .ok_or_else(|| DceRpcError::invalid("auth_length", "exceeds frag_length"))?;

    let mut off = CommonHeader::SIZE;
    if off + 12 > stub_end {
        return Err(DceRpcError::truncated(off + 12, stub_end));
    }
    let max_xmit = u16::from_le_bytes([body[off], body[off + 1]]);
    let max_recv = u16::from_le_bytes([body[off + 2], body[off + 3]]);
    let assoc_group_id = u32::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
    ]);
    off += 8;

    // sec_addr_length + sec_addr bytes (no NDR alignment inside this field).
    let sec_addr_len = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + sec_addr_len > stub_end {
        return Err(DceRpcError::truncated(off + sec_addr_len, stub_end));
    }
    off += sec_addr_len;

    // 4-byte alignment from the START of the PDU before the result list.
    let pad = (4 - (off % 4)) % 4;
    if off + pad > stub_end {
        return Err(DceRpcError::truncated(off + pad, stub_end));
    }
    off += pad;

    if off + 4 > stub_end {
        return Err(DceRpcError::truncated(off + 4, stub_end));
    }
    let n_results = body[off] as usize;
    // body[off+1..off+4] is reserved.
    off += 4;

    // Each result entry: 2 (result) + 2 (reason) + 20 (transfer_syntax) = 24.
    if off + n_results * 24 > stub_end {
        return Err(DceRpcError::truncated(off + n_results * 24, stub_end));
    }
    let mut results = Vec::with_capacity(n_results);
    for _ in 0..n_results {
        let result = AckResult::from_u16(u16::from_le_bytes([body[off], body[off + 1]]));
        let reason = u16::from_le_bytes([body[off + 2], body[off + 3]]);
        results.push((result, reason));
        off += 24;
    }

    let server_auth_verifier = body[stub_end..frag_len].to_vec();
    Ok(BindAckParsed {
        header,
        max_xmit,
        max_recv,
        assoc_group_id,
        results,
        server_auth_verifier,
    })
}

/// Encode an `auth3` PDU. MS-RPCE §2.2.2.5.
///
/// The body is just 4 bytes of zero padding followed by the
/// `auth_verifier` (`sec_trailer + NTLMSSP AUTHENTICATE`). The 4-byte pad
/// is mandated by the spec to keep the `auth_verifier` 4-byte aligned from
/// the start of the PDU; setting it to anything other than zero is a
/// strict-mode bug per the IDL.
pub fn encode_auth3(call_id: u32, auth_verifier: &[u8]) -> Result<Vec<u8>> {
    if auth_verifier.is_empty() {
        return Err(DceRpcError::invalid(
            "auth_verifier",
            "auth3 PDU requires a non-empty verifier",
        ));
    }
    let mut hdr = CommonHeader::new(PacketType::Auth3, call_id);
    let mut buf = Vec::with_capacity(CommonHeader::SIZE + 4 + auth_verifier.len());
    buf.resize(CommonHeader::SIZE, 0);
    buf.extend_from_slice(&[0u8; 4]); // mandatory pad
    buf.extend_from_slice(auth_verifier);

    let auth_len = u16::try_from(auth_verifier.len())
        .map_err(|_| DceRpcError::invalid("auth_verifier", "length exceeds u16"))?;
    let frag_len = u16::try_from(buf.len()).map_err(|_| DceRpcError::FragmentTooLarge {
        size: buf.len(),
        limit: u16::MAX as usize,
    })?;
    hdr.frag_length = frag_len;
    hdr.auth_length = auth_len;
    let mut hdr_buf = Vec::with_capacity(CommonHeader::SIZE);
    hdr.encode_to(&mut hdr_buf);
    buf[..CommonHeader::SIZE].copy_from_slice(&hdr_buf);
    Ok(buf)
}

/// Parse a `fault` PDU. Returns the 32-bit status. MS-RPCE §2.2.2.11.
pub fn decode_fault_status(buf: &[u8]) -> Result<u32> {
    let header = CommonHeader::decode(buf)?;
    if header.ptype != PacketType::Fault {
        return Err(DceRpcError::invalid(
            "ptype",
            format!("expected Fault, got {:?}", header.ptype),
        ));
    }
    let frag_len = header.frag_length as usize;
    // fault layout: common header (16) + alloc_hint (4) + context_id (2) +
    // cancel_count (1) + reserved (1) + status (4) + reserved2 (4)
    if buf.len() < frag_len || frag_len < CommonHeader::SIZE + 16 {
        return Err(DceRpcError::truncated(CommonHeader::SIZE + 16, buf.len()));
    }
    let s = CommonHeader::SIZE + 8;
    let status = u32::from_le_bytes([buf[s], buf[s + 1], buf[s + 2], buf[s + 3]]);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_header_roundtrip() {
        let mut h = CommonHeader::new(PacketType::Request, 0xdead_beef);
        h.frag_length = 64;
        h.auth_length = 16;
        let mut out = Vec::new();
        h.encode_to(&mut out);
        assert_eq!(out.len(), CommonHeader::SIZE);
        let parsed = CommonHeader::decode(&out).expect("decode");
        assert_eq!(parsed.ptype, PacketType::Request);
        assert_eq!(parsed.frag_length, 64);
        assert_eq!(parsed.auth_length, 16);
        assert_eq!(parsed.call_id, 0xdead_beef);
    }

    #[test]
    fn decode_rejects_unknown_rpc_vers() {
        let mut bytes = [0u8; CommonHeader::SIZE];
        bytes[0] = 7;
        bytes[2] = PacketType::Request as u8;
        let err = CommonHeader::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DceRpcError::InvalidField {
                field: "rpc_vers",
                ..
            }
        ));
    }

    #[test]
    fn bind_encodes_common_header() {
        let srvsvc = Uuid::parse("4b324fc8-1670-01d3-1278-5a47bf6ee188").unwrap();
        let ctx = PresentationContext {
            context_id: 0,
            abstract_syntax: PresentationSyntax {
                uuid: srvsvc,
                version: 3,
            },
            transfer_syntax: ndr20_transfer_syntax(),
        };
        let pdu = encode_bind(1, 4280, 4280, 0, &[ctx], None).expect("encode_bind");
        let hdr = CommonHeader::decode(&pdu).expect("decode");
        assert_eq!(hdr.ptype, PacketType::Bind);
        assert_eq!(hdr.call_id, 1);
        assert_eq!(hdr.frag_length as usize, pdu.len());
        // Expected bind body size: 16 (hdr) + 8 (max_xmit/recv/assoc) +
        // 4 (p_ctx count+pad) + 44 (one ctx element) = 72.
        assert_eq!(pdu.len(), 72);
    }

    #[test]
    fn request_stub_data_roundtrips() {
        let stub = [1u8, 2, 3, 4, 5];
        let pdu = encode_request(42, 0, 15, &stub, None).unwrap();
        let resp_like = {
            // Cheat: rewrite ptype to Response so we can reuse the decoder
            // for field-offset testing.
            let mut v = pdu.clone();
            v[2] = PacketType::Response as u8;
            v
        };
        let decoded = decode_response(&resp_like).unwrap();
        assert_eq!(decoded.stub_data, &stub);
        assert_eq!(decoded.context_id, 0);
    }

    /// Build a hand-rolled BindAck buffer the way Samba would emit it for a
    /// single accepted srvsvc context, with no auth_verifier (anonymous bind).
    fn synth_bind_ack(
        call_id: u32,
        sec_addr: &[u8],
        results: &[(u16, u16)],
        auth_verifier: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        // max_xmit / max_recv / assoc_group_id
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&0xCAFE_F00Du32.to_le_bytes());
        // sec_addr_length + sec_addr
        body.extend_from_slice(&(sec_addr.len() as u16).to_le_bytes());
        body.extend_from_slice(sec_addr);
        // 4-byte alignment from start of PDU. PDU starts at the common header.
        let pdu_off = CommonHeader::SIZE + body.len();
        let pad = (4 - (pdu_off % 4)) % 4;
        body.extend_from_slice(&vec![0u8; pad]);
        // n_results + 3 bytes pad
        body.push(results.len() as u8);
        body.extend_from_slice(&[0u8; 3]);
        // results
        for (r, why) in results {
            body.extend_from_slice(&r.to_le_bytes());
            body.extend_from_slice(&why.to_le_bytes());
            // transfer_syntax (UUID + version) — NDR20 placeholder
            body.extend_from_slice(&[0u8; 20]);
        }
        body.extend_from_slice(auth_verifier);

        let mut hdr = CommonHeader::new(PacketType::BindAck, call_id);
        hdr.frag_length = (CommonHeader::SIZE + body.len()) as u16;
        hdr.auth_length = auth_verifier.len() as u16;
        let mut out = Vec::with_capacity(hdr.frag_length as usize);
        hdr.encode_to(&mut out);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn bind_ack_decodes_anonymous_acceptance() {
        // sec_addr "\PIPE\srvsvc\0" UTF-8 (12 bytes including NUL)
        let sec_addr = b"\\PIPE\\srvsvc\0";
        let pdu = synth_bind_ack(7, sec_addr, &[(0, 0)], &[]);
        let parsed = decode_bind_ack(&pdu).expect("decode bind_ack");
        assert_eq!(parsed.header.call_id, 7);
        assert_eq!(parsed.max_xmit, 4280);
        assert_eq!(parsed.max_recv, 4280);
        assert_eq!(parsed.assoc_group_id, 0xCAFE_F00D);
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.results[0].0, AckResult::Acceptance);
        assert!(parsed.server_auth_verifier.is_empty());
    }

    #[test]
    fn bind_ack_extracts_auth_verifier() {
        // Inject a fake CHALLENGE payload behind the sec_trailer-shaped 8 bytes.
        let av = b"\x0a\x06\x00\x00\x00\x00\x00\x00fake-ntlmssp-blob";
        let pdu = synth_bind_ack(99, b"\\PIPE\\srvsvc\0", &[(0, 0)], av);
        let parsed = decode_bind_ack(&pdu).unwrap();
        assert_eq!(parsed.server_auth_verifier, av);
    }

    #[test]
    fn bind_ack_surfaces_provider_rejection() {
        let pdu = synth_bind_ack(1, b"", &[(2, 4)], &[]);
        let parsed = decode_bind_ack(&pdu).unwrap();
        assert_eq!(parsed.results[0].0, AckResult::ProviderRejection);
        assert_eq!(parsed.results[0].1, 4);
    }

    #[test]
    fn bind_ack_rejects_wrong_ptype() {
        // Build a Response PDU and try to decode it as BindAck.
        let pdu = encode_request(0, 0, 0, &[], None).unwrap();
        let mut altered = pdu.clone();
        altered[2] = PacketType::Response as u8;
        assert!(decode_bind_ack(&altered).is_err());
    }

    #[test]
    fn auth3_encodes_with_pad_and_verifier() {
        let av = vec![0xAA; 24];
        let pdu = encode_auth3(0xDEAD_BEEF, &av).unwrap();
        let hdr = CommonHeader::decode(&pdu).unwrap();
        assert_eq!(hdr.ptype, PacketType::Auth3);
        assert_eq!(hdr.call_id, 0xDEAD_BEEF);
        assert_eq!(hdr.auth_length as usize, av.len());
        assert_eq!(hdr.frag_length as usize, pdu.len());
        // 4 zero pad bytes after the header.
        assert_eq!(&pdu[CommonHeader::SIZE..CommonHeader::SIZE + 4], &[0; 4]);
        // Verifier follows.
        assert_eq!(&pdu[CommonHeader::SIZE + 4..], av.as_slice());
    }

    #[test]
    fn auth3_rejects_empty_verifier() {
        let err = encode_auth3(1, &[]).unwrap_err();
        assert!(matches!(err, DceRpcError::InvalidField { .. }));
    }
}
