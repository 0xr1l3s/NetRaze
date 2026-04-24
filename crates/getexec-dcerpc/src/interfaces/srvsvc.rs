//! MS-SRVS (Server Service) RPC interface.
//!
//! UUID  : `4b324fc8-1670-01d3-1278-5a47bf6ee188`
//! Version: 3.0
//! Pipe  : `\PIPE\srvsvc`
//!
//! Targets the minimum opnum set the rest of getexec actually needs:
//!   - opnum 15 — `NetrShareEnum` — enumerate shares
//!   - opnum 21 — `NetrServerGetInfo` — hostname + OS string (later)
//!
//! The `NetrShareEnum` request/response codecs are byte-for-byte compatible
//! with what Impacket emits in `dcerpc/v5/srvs.py` and what Samba parses on
//! `\PIPE\srvsvc`. Validation is unit-tested here against synthetic vectors
//! and integration-tested in Phase 5 against a Samba container.

use crate::error::{DceRpcError, Result};
use crate::ndr::{NdrReader, NdrWriter};
use crate::uuid::Uuid;

pub const UUID_STR: &str = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
pub const VERSION_MAJOR: u16 = 3;
pub const VERSION_MINOR: u16 = 0;
pub const PIPE: &str = "\\PIPE\\srvsvc";

/// Sanity cap for the conformant `EntriesRead` count to defend against a
/// malicious server returning `0xFFFF_FFFF` and forcing a huge allocation.
/// 64K shares is wildly more than any real server has.
const MAX_SHARES_PER_RESPONSE: u32 = 65_536;

/// Opnum table (subset). MS-SRVS §3.1.4.
#[repr(u16)]
pub enum Opnum {
    NetrShareEnum = 15,
    NetrServerGetInfo = 21,
}

pub fn uuid() -> Uuid {
    Uuid::parse(UUID_STR).expect("static uuid")
}

// ---------------------------------------------------------------------------
// NetrShareEnum — opnum 15
// ---------------------------------------------------------------------------

/// Info-level 1 (the one we actually use): name + type + remark per share.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareInfo1 {
    pub netname: String,
    pub shi1_type: u32,
    pub remark: String,
}

#[derive(Debug, Clone, Default)]
pub struct NetrShareEnumResponse {
    pub shares: Vec<ShareInfo1>,
    /// Total server-side share count (may exceed `shares.len()` if the
    /// server truncated due to `PreferedMaximumLength`).
    pub total_entries: u32,
    /// Resume handle for continuation — 0 if the enumeration is done.
    pub resume_handle: u32,
    /// Server status (0 = success, ERROR_MORE_DATA = 234, …).
    pub status: u32,
}

/// Build the NDR stub for a `NetrShareEnum(level=1)` request.
///
/// Wire layout (MS-SRVS §3.1.4.8 + IDL `case 1: LPSHARE_INFO_1_CONTAINER`):
///
/// ```text
/// inline (top-level params):
///   [unique,string] WCHAR* ServerName         ; referent + inline wstring
///   DWORD                  Level              ; 1
///   SHARE_ENUM_STRUCT ShareEnum:
///     DWORD                Level              ; 1
///     union SHARE_ENUM_UNION                  ; tag=1 → LPSHARE_INFO_1_CONTAINER
///       DWORD              tag                ; 1
///       LPSHARE_INFO_1_CONTAINER ContainerRef ; [unique] referent, NON-NULL
/// deferred of Container (always emitted, container non-null by spec):
///   DWORD                  EntriesRead        ; 0 on request side
///   LPSHARE_INFO_1_ARRAY   Buffer             ; NULL on request side
/// inline (remaining top-level params):
///   DWORD                  PreferedMaximumLength
///   DWORD*                 ResumeHandle       ; [unique] referent + value
/// ```
///
/// The **critical subtlety** is the union-arm `LPSHARE_INFO_1_CONTAINER` —
/// the union's tag=1 case is itself a *pointer*, not an inline container
/// struct. Impacket/Windows emit the Container referent inline (inside the
/// union body), and the Container's body (`EntriesRead` + Buffer pointer)
/// goes into the deferred queue. We flush that queue before writing the
/// trailing top-level params so the layout matches the ground-truth fixture
/// in `IMPACKET_REQUEST_LEVEL1_SERVER` (tests below).
///
/// Top-level `[unique]` pointers (`ServerName`, `ResumeHandle`) use raw
/// `write_referent()` + inline value because the deferred queue mechanism
/// only applies to pointers nested in a constructed type.
pub fn encode_netr_share_enum_request(
    server_name: &str,
    prefered_max_length: u32,
    resume_handle: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();

    // ServerName: top-level [unique, string] WCHAR*. Referent inline, then
    // the wstring inline immediately after.
    w.write_referent();
    w.write_conformant_varying_wstring(server_name);

    // SHARE_ENUM_STRUCT: Level=1 then the tagged-union switch.
    w.write_u32(1); // Level
    w.write_u32(1); // union tag

    // Container pointer (LPSHARE_INFO_1_CONTAINER) — always non-null per
    // the Impacket-generated fixture, even for the request side.
    w.write_unique_ptr(true, |w| {
        w.write_u32(0); // EntriesRead (request side = 0)
        w.write_null_referent(); // Buffer = NULL
    });
    // Drain Container's deferred body before the next top-level params.
    w.flush_deferred();

    // PreferedMaximumLength
    w.write_u32(prefered_max_length);

    // ResumeHandle: top-level [unique] DWORD*. Referent + inline value.
    w.write_referent();
    w.write_u32(resume_handle);

    w.finish()
}

/// Decode the full `NetrShareEnum` response stub. Mirrors the wire layout
/// produced by Samba/Windows/Impacket for level 1, with the full pointer
/// chain `Union → LPSHARE_INFO_1_CONTAINER → SHARE_INFO_1_CONTAINER →
/// LPSHARE_INFO_1_ARRAY` expanded:
///
/// ```text
/// inline (top-level):
///   DWORD          Level                         ; echoed = 1
///   DWORD          tag                           ; == Level
///   [unique]       ContainerRef                  ; LPSHARE_INFO_1_CONTAINER
/// deferred of Container (if ContainerRef != 0):
///   DWORD          EntriesRead
///   [unique]       BufferRef                     ; LPSHARE_INFO_1_ARRAY
/// deferred of Buffer (if BufferRef != 0):
///   DWORD          MaxCount                      ; conformance, == EntriesRead
///   SHARE_INFO_1[MaxCount]                       ; inline bodies
///     each body:   netname_ref | shi1_type | remark_ref
/// deferred of each body (in array order):
///   [string]WCHAR  netname
///   [string]WCHAR  remark
/// trailer (remaining top-level params):
///   DWORD          TotalEntries
///   [unique] DWORD ResumeHandle
///   DWORD          Status                        ; Win32 error code
/// ```
///
/// The key wire-layout gotcha fixed in this decoder: the union's tag=1
/// arm is `LPSHARE_INFO_1_CONTAINER` (a *pointer*), not `SHARE_INFO_1_CONTAINER`
/// inline. Missing that pointer level was the original decoder bug — we
/// were mis-parsing `EntriesRead` as the Container referent and shifting
/// every subsequent field.
pub fn decode_netr_share_enum_response(stub: &[u8]) -> Result<NetrShareEnumResponse> {
    let mut r = NdrReader::new(stub);

    // Top-level inline: Level + union tag + Container referent.
    let level = r.read_u32()?;
    if level != 1 {
        return Err(DceRpcError::NdrDecode(format!(
            "expected level=1 in NetrShareEnum response, got {level}"
        )));
    }
    let tag = r.read_u32()?;
    if tag != 1 {
        return Err(DceRpcError::NdrDecode(format!(
            "expected union tag=1, got {tag}"
        )));
    }
    let container_present = r.read_unique_referent()?;

    let mut shares = Vec::new();
    let mut entries_read = 0u32;
    if container_present {
        // Container's deferred body: EntriesRead + Buffer pointer.
        entries_read = r.read_u32()?;
        let buffer_present = r.read_unique_referent()?;

        if buffer_present {
            // Buffer's deferred body: max_count + inline bodies.
            let max_count = r.read_conformant_count(MAX_SHARES_PER_RESPONSE)?;
            if max_count != entries_read as usize {
                return Err(DceRpcError::NdrDecode(format!(
                    "max_count {max_count} != EntriesRead {entries_read}"
                )));
            }
            // Per-element inline: netname_ref, shi1_type, remark_ref.
            let mut inlines: Vec<(bool, u32, bool)> = Vec::with_capacity(max_count);
            for _ in 0..max_count {
                let netname_ref = r.read_unique_referent()?;
                let shi1_type = r.read_u32()?;
                let remark_ref = r.read_unique_referent()?;
                inlines.push((netname_ref, shi1_type, remark_ref));
            }
            // Per-element deferred wstrings, in array order.
            shares.reserve(max_count);
            for (nref, kind, rref) in inlines {
                let netname = if nref {
                    r.read_conformant_varying_wstring()?
                } else {
                    String::new()
                };
                let remark = if rref {
                    r.read_conformant_varying_wstring()?
                } else {
                    String::new()
                };
                shares.push(ShareInfo1 {
                    netname,
                    shi1_type: kind,
                    remark,
                });
            }
        } else if entries_read != 0 {
            // Contradictory: count says there are entries, but Buffer is NULL.
            return Err(DceRpcError::NdrDecode(format!(
                "EntriesRead={entries_read} with NULL Buffer"
            )));
        }
    }
    // If container_present == false, entries_read stays 0, shares stays empty.
    let _ = entries_read;

    // Trailer: top-level inline.
    let total_entries = r.read_u32()?;
    let resume_present = r.read_unique_referent()?;
    let resume_handle = if resume_present { r.read_u32()? } else { 0 };
    let status = r.read_u32()?;

    Ok(NetrShareEnumResponse {
        shares,
        total_entries,
        resume_handle,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndr::NdrWriter;

    #[test]
    fn interface_uuid_parses() {
        let u = uuid();
        assert_eq!(format!("{u}"), UUID_STR);
    }

    #[test]
    fn request_stub_starts_with_nonzero_referent() {
        let stub = encode_netr_share_enum_request("\\\\SERVER", 0xFFFF_FFFF, 0);
        let referent = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
        assert_ne!(referent, 0, "ServerName must be present");
    }

    /// `(netname, shi1_type, remark)` tuple for a synthetic share body —
    /// typed alias so the test helper's signature doesn't trip
    /// `clippy::type_complexity`.
    type SyntheticShare = (String, u32, String);
    /// Optional buffer payload: `Some((max_count, shares))` writes a non-null
    /// Buffer pointer with its conformant array; `None` writes NULL.
    type BufferPayload = Option<(u32, Vec<SyntheticShare>)>;

    /// Helper: emit the full level-1 response prefix (inline Level+tag+Container
    /// pointer → deferred Container body → deferred Buffer body → inline bodies
    /// → deferred wstrings), stopping just before the trailer.
    fn emit_response_shares(w: &mut NdrWriter, entries_read: u32, buffer: BufferPayload) {
        w.write_u32(1); // Level
        w.write_u32(1); // union tag

        // Container pointer (LPSHARE_INFO_1_CONTAINER) — always non-null in
        // practice (spec + Impacket ground truth).
        w.write_unique_ptr(true, move |w| {
            w.write_u32(entries_read);
            match buffer {
                None => w.write_null_referent(),
                Some((max_count, shares)) => {
                    w.write_unique_ptr(true, move |w| {
                        w.write_u32(max_count);
                        for (name, kind, remark) in shares {
                            w.write_unique_ptr(true, move |w| {
                                w.write_conformant_varying_wstring(&name);
                            });
                            w.write_u32(kind);
                            w.write_unique_ptr(true, move |w| {
                                w.write_conformant_varying_wstring(&remark);
                            });
                        }
                    });
                }
            }
        });
        // Drain ALL deferred content (Container body + Buffer body + per-share
        // wstrings) before the trailing top-level params go out.
        w.flush_deferred();
    }

    /// Build a synthetic response stub corresponding to two shares
    /// (`IPC$` IPC, `C$` disk) and verify the decoder reconstructs them
    /// exactly.
    #[test]
    fn response_decoder_two_shares_roundtrip() {
        let mut w = NdrWriter::new();
        emit_response_shares(
            &mut w,
            2,
            Some((
                2,
                vec![
                    ("IPC$".into(), 3, "Remote IPC".into()),
                    ("C$".into(), 0, "Default share".into()),
                ],
            )),
        );

        // Trailer
        w.write_u32(2); // TotalEntries
        w.write_referent(); // ResumeHandle referent
        w.write_u32(0); // ResumeHandle value
        w.write_u32(0); // Status

        let stub = w.finish();
        let resp = decode_netr_share_enum_response(&stub).expect("decode");
        assert_eq!(resp.total_entries, 2);
        assert_eq!(resp.resume_handle, 0);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.shares.len(), 2);
        assert_eq!(
            resp.shares[0],
            ShareInfo1 {
                netname: "IPC$".into(),
                shi1_type: 3,
                remark: "Remote IPC".into(),
            }
        );
        assert_eq!(
            resp.shares[1],
            ShareInfo1 {
                netname: "C$".into(),
                shi1_type: 0,
                remark: "Default share".into(),
            }
        );
    }

    /// Empty enumeration: Container present but Buffer NULL, EntriesRead=0.
    /// Mirrors what Samba/Windows/Impacket emit when a share scan yields
    /// nothing (or when we query a server that hides everything).
    #[test]
    fn response_decoder_empty_enumeration() {
        let mut w = NdrWriter::new();
        emit_response_shares(&mut w, 0, None);

        w.write_u32(0); // TotalEntries
        w.write_referent(); // ResumeHandle referent
        w.write_u32(0); // ResumeHandle value
        w.write_u32(0); // Status

        let stub = w.finish();
        let resp = decode_netr_share_enum_response(&stub).expect("decode");
        assert!(resp.shares.is_empty());
        assert_eq!(resp.total_entries, 0);
        assert_eq!(resp.status, 0);
    }

    /// Server returned ERROR_MORE_DATA — caller should be able to read both
    /// the truncated share set and the resume handle.
    #[test]
    fn response_decoder_more_data_with_resume() {
        let mut w = NdrWriter::new();
        emit_response_shares(
            &mut w,
            1,
            Some((1, vec![("public".into(), 0, "Public share".into())])),
        );

        w.write_u32(42); // TotalEntries (server has more)
        w.write_referent(); // ResumeHandle referent
        w.write_u32(0xCAFE_F00D); // ResumeHandle value (continuation cookie)
        w.write_u32(234); // ERROR_MORE_DATA

        let stub = w.finish();
        let resp = decode_netr_share_enum_response(&stub).expect("decode");
        assert_eq!(resp.total_entries, 42);
        assert_eq!(resp.resume_handle, 0xCAFE_F00D);
        assert_eq!(resp.status, 234);
        assert_eq!(resp.shares.len(), 1);
        assert_eq!(resp.shares[0].netname, "public");
    }

    /// Server-claimed `MaxCount` mismatching `EntriesRead` is a corruption
    /// signal and must fail loudly rather than silently truncating.
    #[test]
    fn response_decoder_rejects_count_mismatch() {
        let mut w = NdrWriter::new();
        w.write_u32(1);
        w.write_u32(1);
        w.write_unique_ptr(true, move |w| {
            w.write_u32(2); // EntriesRead = 2
            w.write_unique_ptr(true, move |w| {
                w.write_u32(3); // max_count = 3 (mismatch)
                for _ in 0..3 {
                    w.write_null_referent();
                    w.write_u32(0);
                    w.write_null_referent();
                }
            });
        });
        w.flush_deferred();

        w.write_u32(2); // TotalEntries
        w.write_null_referent(); // ResumeHandle = NULL
        w.write_u32(0); // Status

        let stub = w.finish();
        let err = decode_netr_share_enum_response(&stub).unwrap_err();
        assert!(matches!(err, DceRpcError::NdrDecode(_)));
    }

    /// Wrong Level in the response → caller-friendly error.
    #[test]
    fn response_decoder_rejects_wrong_level() {
        let mut w = NdrWriter::new();
        w.write_u32(2); // Level=2 (we only support 1)
        let stub = w.finish();
        assert!(decode_netr_share_enum_response(&stub).is_err());
    }

    // -----------------------------------------------------------------------
    // Impacket ground-truth fixtures. Generated by
    // `crates/getexec-dcerpc/tests/gen_srvs_fixture.py` against the canonical
    // Impacket encoder — these are byte-for-byte what a real CrackMapExec run
    // puts on the wire. Pinning them here means any drift in our encoder or
    // decoder fails fast, without needing Impacket/Python installed in CI.
    //
    // Referent IDs are random per-run in Impacket, so the constants below
    // carry whatever values the one-shot generator happened to produce.
    // That's fine: our decoder treats any non-zero referent as "pointer
    // present", and the fixture tests only assert on the semantic content.
    // -----------------------------------------------------------------------

    /// `NetrShareEnum` response stub containing two shares:
    /// `IPC$` (STYPE_IPC=3, remark "Remote IPC") and `C$` (STYPE_DISKTREE=0,
    /// remark "Default share"). 184 bytes end-to-end.
    const IMPACKET_RESPONSE_TWO_SHARES: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xde, 0xe0, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x32, 0x44, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xa8, 0xba, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x9f, 0x9f, 0x00, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1,
        0x3c, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0xab, 0xab, 0x0b, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6d, 0x00,
        0x6f, 0x00, 0x74, 0x00, 0x65, 0x00, 0x20, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x00,
        0x00, 0xab, 0xab, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0xab, 0xab, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x44, 0x00, 0x65, 0x00, 0x66, 0x00, 0x61, 0x00, 0x75, 0x00,
        0x6c, 0x00, 0x74, 0x00, 0x20, 0x00, 0x73, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00, 0x65,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc8, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    /// `NetrShareEnum` response with zero entries: Container present, Buffer
    /// NULL. 36 bytes — the canonical "nothing to see here" shape a locked-
    /// down server would emit.
    const IMPACKET_RESPONSE_EMPTY: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xdd, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x3e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Decode the Impacket-generated two-shares fixture. This is the real
    /// load-bearing regression test: it pins us against the exact wire
    /// layout CrackMapExec produces, so any drift in the Container-pointer
    /// handling (or the BFS deferred queue) gets caught immediately.
    #[test]
    fn response_decoder_impacket_fixture_two_shares() {
        let resp = decode_netr_share_enum_response(IMPACKET_RESPONSE_TWO_SHARES)
            .expect("decode impacket two-shares fixture");
        assert_eq!(resp.total_entries, 2);
        assert_eq!(resp.resume_handle, 0);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.shares.len(), 2);
        assert_eq!(
            resp.shares[0],
            ShareInfo1 {
                netname: "IPC$".into(),
                shi1_type: 3,
                remark: "Remote IPC".into(),
            }
        );
        assert_eq!(
            resp.shares[1],
            ShareInfo1 {
                netname: "C$".into(),
                shi1_type: 0,
                remark: "Default share".into(),
            }
        );
    }

    /// Decode the Impacket-generated empty-enumeration fixture. Verifies the
    /// decoder handles the Container-present-but-Buffer-NULL shape without
    /// confusing it for a truncated response.
    #[test]
    fn response_decoder_impacket_fixture_empty() {
        let resp = decode_netr_share_enum_response(IMPACKET_RESPONSE_EMPTY)
            .expect("decode impacket empty fixture");
        assert!(resp.shares.is_empty());
        assert_eq!(resp.total_entries, 0);
        assert_eq!(resp.resume_handle, 0);
        assert_eq!(resp.status, 0);
    }

    /// Our encoder must produce a request that Impacket-style decoders can
    /// round-trip back. We can't byte-compare because Impacket's referent
    /// IDs and `\xab\xab` padding bytes are implementation-specific, but we
    /// can check every semantically-significant field sits at the correct
    /// offset for the `LPSHARE_INFO_1_CONTAINER` wire layout.
    #[test]
    fn request_encoder_matches_impacket_layout() {
        let stub = encode_netr_share_enum_request("\\\\SERVER", 0xFFFF_FFFF, 0);
        assert_eq!(stub.len(), 68, "request must be 68 bytes");

        // ServerName wstring: referent @ 0-3, max @ 4-7, offset @ 8-11,
        // actual @ 12-15, 9 WCHARs @ 16-33, 2 bytes pad @ 34-35.
        assert_ne!(u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]), 0);
        assert_eq!(&stub[4..8], 9u32.to_le_bytes()); // max_count
        assert_eq!(&stub[8..12], 0u32.to_le_bytes()); // offset
        assert_eq!(&stub[12..16], 9u32.to_le_bytes()); // actual_count
        // "\\SERVER\0" in UTF-16-LE
        let expected_wstring: Vec<u8> = "\\\\SERVER\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(&stub[16..34], &expected_wstring[..]);
        // Level=1 @ 36-39 (after 2-byte pad-to-4 at 34-35).
        assert_eq!(&stub[36..40], 1u32.to_le_bytes());
        // union tag=1 @ 40-43.
        assert_eq!(&stub[40..44], 1u32.to_le_bytes());
        // Container referent @ 44-47, non-null.
        assert_ne!(
            u32::from_le_bytes([stub[44], stub[45], stub[46], stub[47]]),
            0
        );
        // Container deferred body: EntriesRead=0 @ 48-51, Buffer=NULL @ 52-55.
        assert_eq!(&stub[48..52], 0u32.to_le_bytes());
        assert_eq!(&stub[52..56], 0u32.to_le_bytes());
        // PreferedMaximumLength @ 56-59.
        assert_eq!(&stub[56..60], 0xFFFF_FFFFu32.to_le_bytes());
        // ResumeHandle referent @ 60-63 (non-null), value @ 64-67.
        assert_ne!(
            u32::from_le_bytes([stub[60], stub[61], stub[62], stub[63]]),
            0
        );
        assert_eq!(&stub[64..68], 0u32.to_le_bytes());
    }
}
