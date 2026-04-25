#!/usr/bin/env python3
"""Ground-truth byte fixtures for the SMB2 named-pipe RPC dance.

Generates Rust `pub const` byte arrays for:
  * SMB2 CREATE Request opening \\PIPE\\srvsvc on IPC$
  * SMB2 CREATE Response (server side, fabricated)
  * SMB2 IOCTL Request with FSCTL_PIPE_TRANSCEIVE wrapping a DCE/RPC Bind
    PDU (SRVSVC v3.0 / NDR20)
  * SMB2 IOCTL Response wrapping a DCE/RPC Bind Ack PDU
  * SMB2 CLOSE Request / Response

Why hand-rolled struct.pack rather than impacket.smb3structs?
  Impacket's `SMB2_CREATE` / `SMB2_IOCTL` / `SMB2_CLOSE` field names have
  shifted between 0.10 and 0.12 releases. struct.pack is more stable and
  easier to align against MS-SMB2 §2.2.13 / §2.2.31 / §2.2.15 byte offsets.
  We do still use Impacket for the DCE/RPC Bind PDU so we stay byte-exact
  against the same reference Windows DCs use.

Usage:
    python crates/netraze-protocols/tests/gen_smb_pipe_fixture.py

Re-running is idempotent — all placeholders below are pinned, so the output
matches the constants baked into the Rust integration tests.

Pinned placeholders (the matching Rust tests must use the same values):
    SESSION_ID    = 0x0000000000000001
    TREE_ID       = 0x00000001            (IPC$)
    MESSAGE_IDs   = 100..=105
    CREDIT_CHARGE = 1, CREDIT_REQUEST = 31
    FILE_ID       = 0x4141..41 / 0x4242..42 (Persistent / Volatile)
"""

import os
import struct
import sys
from uuid import UUID

# Path to a sibling impacket checkout (same convention as the rest of the
# repo's Python helpers). Adjust if your local layout differs.
HERE = os.path.dirname(os.path.abspath(__file__))
IMPACKET = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "impacket"))
if os.path.isdir(IMPACKET):
    sys.path.insert(0, IMPACKET)

# We only need Impacket for the DCE/RPC Bind / BindAck wire layouts.
try:
    from impacket.dcerpc.v5.rpcrt import (
        MSRPCBind,
        MSRPCBindAck,
        MSRPCHeader,
        CtxItem,
        CtxItemResult,
        MSRPC_BIND,
        MSRPC_BINDACK,
        PFC_FIRST_FRAG,
        PFC_LAST_FRAG,
    )
except ImportError as e:
    sys.stderr.write(
        f"impacket not importable from {IMPACKET}\n"
        f"  ({e})\n"
        "Install it (e.g. `pip install impacket`) or adjust the IMPACKET path "
        "above. The script only needs the dcerpc.v5.rpcrt structs.\n"
    )
    sys.exit(2)


# ─── Pinned values shared with the Rust tests ────────────────────────────
SESSION_ID = 0x0000_0000_0000_0001
TREE_ID = 0x0000_0001
CREDIT_CHARGE = 1
CREDIT_REQ = 31
MID_CREATE_REQ = 100
MID_CREATE_RSP = 100
MID_IOCTL_REQ = 101
MID_IOCTL_RSP = 101
MID_CLOSE_REQ = 102
MID_CLOSE_RSP = 102

FILE_ID_PERS = b"\x41" * 8
FILE_ID_VOL = b"\x42" * 8
FILE_ID_FULL = FILE_ID_PERS + FILE_ID_VOL

SMB2_HEADER_SIZE = 64
SMB2_FLAGS_SERVER_TO_REDIR = 0x0000_0001

CMD_CREATE = 0x0005
CMD_CLOSE = 0x0006
CMD_IOCTL = 0x000B

FSCTL_PIPE_TRANSCEIVE = 0x0011_C017
SMB2_0_IOCTL_IS_FSCTL = 0x0000_0001
PIPE_DESIRED_ACCESS = 0x0012_019F

PIPE_NAME = "srvsvc"
SRVSVC_UUID = UUID("4B324FC8-1670-01D3-1278-5A47BF6EE188")
SRVSVC_VER_MAJOR = 3
SRVSVC_VER_MINOR = 0
NDR20_UUID = UUID("8A885D04-1CEB-11C9-9FE8-08002B104860")
NDR20_VER = 2


def smb2_header(command: int, mid: int, *, status: int = 0, flags: int = 0,
                tree_id: int = TREE_ID, session_id: int = SESSION_ID) -> bytes:
    """Build a 64-byte SMB2 sync header (no signing, NextCommand=0)."""
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)            # StructureSize
        + struct.pack("<H", CREDIT_CHARGE) # CreditCharge
        + struct.pack("<I", status)        # Status
        + struct.pack("<H", command)       # Command
        + struct.pack("<H", CREDIT_REQ)    # CreditRequest
        + struct.pack("<I", flags)         # Flags
        + struct.pack("<I", 0)             # NextCommand
        + struct.pack("<Q", mid)           # MessageId
        + struct.pack("<I", 0)             # Reserved (process_id_high in async)
        + struct.pack("<I", tree_id)       # TreeId
        + struct.pack("<Q", session_id)    # SessionId
        + b"\x00" * 16                     # Signature
    )


def build_dcerpc_bind(call_id: int = 1) -> bytes:
    """SRVSVC v3.0 over NDR20."""
    item = CtxItem()
    item["ContextID"] = 0
    item["TransItems"] = 1
    item["Pad"] = 0
    item["AbstractSyntax"] = (
        SRVSVC_UUID.bytes_le + struct.pack("<HH", SRVSVC_VER_MAJOR, SRVSVC_VER_MINOR)
    )
    item["TransferSyntax"] = NDR20_UUID.bytes_le + struct.pack("<I", NDR20_VER)

    bind = MSRPCBind()
    bind["max_tfrag"] = 4280
    bind["max_rfrag"] = 4280
    bind["assoc_group"] = 0
    bind["ctx_num"] = 1
    bind["ctx_items"] = item.getData()

    body = bind.getData()
    hdr = MSRPCHeader()
    hdr["ver_major"] = 5
    hdr["ver_minor"] = 0
    hdr["type"] = MSRPC_BIND
    hdr["flags"] = PFC_FIRST_FRAG | PFC_LAST_FRAG
    hdr["representation"] = 0x0000_0010   # NDR little-endian, ASCII, IEEE float
    hdr["frag_len"] = 16 + len(body)
    hdr["auth_len"] = 0
    hdr["call_id"] = call_id
    return hdr.getData() + body


def build_dcerpc_bindack(call_id: int = 1) -> bytes:
    sec_addr = b"\\PIPE\\srvsvc\x00"
    sec = struct.pack("<H", len(sec_addr)) + sec_addr
    while len(sec) % 4:
        sec += b"\x00"

    res = CtxItemResult()
    res["Result"] = 0
    res["Reason"] = 0
    res["TransferSyntax"] = NDR20_UUID.bytes_le + struct.pack("<I", NDR20_VER)

    ack = MSRPCBindAck()
    ack["max_tfrag"] = 4280
    ack["max_rfrag"] = 4280
    ack["assoc_group"] = 0x0000_1234
    ack["SecondaryAddr"] = sec
    ack["ctx_num"] = 1
    ack["ctx_items"] = res.getData()

    body = ack.getData()
    hdr = MSRPCHeader()
    hdr["ver_major"] = 5
    hdr["ver_minor"] = 0
    hdr["type"] = MSRPC_BINDACK
    hdr["flags"] = PFC_FIRST_FRAG | PFC_LAST_FRAG
    hdr["representation"] = 0x0000_0010
    hdr["frag_len"] = 16 + len(body)
    hdr["auth_len"] = 0
    hdr["call_id"] = call_id
    return hdr.getData() + body


# ─── SMB2 CREATE Req/Resp for opening \PIPE\srvsvc ──────────────────────
def build_create_request() -> bytes:
    name_utf16 = PIPE_NAME.encode("utf-16-le")
    body = (
        struct.pack("<H", 57)                # StructureSize
        + b"\x00"                            # SecurityFlags
        + b"\x00"                            # RequestedOplockLevel
        + struct.pack("<I", 2)               # ImpersonationLevel = Impersonation
        + b"\x00" * 8                        # SmbCreateFlags
        + b"\x00" * 8                        # Reserved
        + struct.pack("<I", PIPE_DESIRED_ACCESS)
        + struct.pack("<I", 0)               # FileAttributes
        + struct.pack("<I", 0x07)            # ShareAccess R|W|D
        + struct.pack("<I", 1)               # CreateDisposition = FILE_OPEN
        + struct.pack("<I", 0)               # CreateOptions (no FILE_NON_DIRECTORY_FILE)
        + struct.pack("<H", SMB2_HEADER_SIZE + 56)   # NameOffset
        + struct.pack("<H", len(name_utf16))         # NameLength
        + struct.pack("<I", 0)               # CreateContextsOffset
        + struct.pack("<I", 0)               # CreateContextsLength
    )
    assert len(body) == 56, f"CREATE Req fixed body must be 56 bytes, got {len(body)}"
    return smb2_header(CMD_CREATE, MID_CREATE_REQ) + body + name_utf16


def build_create_response() -> bytes:
    body = (
        struct.pack("<H", 89)                # StructureSize
        + b"\x00"                            # OplockLevel
        + b"\x00"                            # Flags
        + struct.pack("<I", 1)               # CreateAction = FILE_OPENED
        + b"\x00" * 8                        # CreationTime
        + b"\x00" * 8                        # LastAccessTime
        + b"\x00" * 8                        # LastWriteTime
        + b"\x00" * 8                        # ChangeTime
        + struct.pack("<Q", 4096)            # AllocationSize
        + struct.pack("<Q", 0)               # EndofFile
        + struct.pack("<I", 0x80)            # FileAttributes = FILE_ATTRIBUTE_NORMAL
        + struct.pack("<I", 0)               # Reserved2
        + FILE_ID_FULL                       # FileId (16 bytes)
        + struct.pack("<I", 0)               # CreateContextsOffset
        + struct.pack("<I", 0)               # CreateContextsLength
    )
    assert len(body) == 88, f"CREATE Resp fixed body must be 88 bytes, got {len(body)}"
    # Spec §2.2.14: structure ends at 88 bytes. Add a 1-byte pad if the
    # caller wants the buffer aligned on a 2-byte boundary; not needed here.
    return smb2_header(CMD_CREATE, MID_CREATE_RSP, flags=SMB2_FLAGS_SERVER_TO_REDIR) + body


# ─── SMB2 IOCTL Req/Resp wrapping a DCE/RPC Bind ─────────────────────────
def build_ioctl_request() -> bytes:
    payload = build_dcerpc_bind(call_id=1)
    body = (
        struct.pack("<H", 57)                # StructureSize
        + struct.pack("<H", 0)               # Reserved
        + struct.pack("<I", FSCTL_PIPE_TRANSCEIVE)
        + FILE_ID_FULL                       # FileId
        + struct.pack("<I", SMB2_HEADER_SIZE + 56)  # InputOffset
        + struct.pack("<I", len(payload))    # InputCount
        + struct.pack("<I", 0)               # MaxInputResponse
        + struct.pack("<I", SMB2_HEADER_SIZE + 56)  # OutputOffset (echoed)
        + struct.pack("<I", 0)               # OutputCount (request side)
        + struct.pack("<I", 65535)           # MaxOutputResponse
        + struct.pack("<I", SMB2_0_IOCTL_IS_FSCTL)
        + struct.pack("<I", 0)               # Reserved2
    )
    assert len(body) == 56, f"IOCTL Req fixed body must be 56 bytes, got {len(body)}"
    return smb2_header(CMD_IOCTL, MID_IOCTL_REQ) + body + payload


def build_ioctl_response() -> bytes:
    payload = build_dcerpc_bindack(call_id=1)
    body = (
        struct.pack("<H", 49)                # StructureSize
        + struct.pack("<H", 0)               # Reserved
        + struct.pack("<I", FSCTL_PIPE_TRANSCEIVE)
        + FILE_ID_FULL
        + struct.pack("<I", SMB2_HEADER_SIZE + 48)  # InputOffset
        + struct.pack("<I", 0)               # InputCount
        + struct.pack("<I", SMB2_HEADER_SIZE + 48)  # OutputOffset
        + struct.pack("<I", len(payload))    # OutputCount
        + struct.pack("<I", 0)               # Flags
        + struct.pack("<I", 0)               # Reserved2
    )
    assert len(body) == 48, f"IOCTL Resp fixed body must be 48 bytes, got {len(body)}"
    return smb2_header(CMD_IOCTL, MID_IOCTL_RSP, flags=SMB2_FLAGS_SERVER_TO_REDIR) + body + payload


# ─── SMB2 CLOSE Req/Resp ────────────────────────────────────────────────
def build_close_request() -> bytes:
    body = (
        struct.pack("<H", 24)                # StructureSize
        + struct.pack("<H", 0)               # Flags
        + struct.pack("<I", 0)               # Reserved
        + FILE_ID_FULL
    )
    assert len(body) == 24
    return smb2_header(CMD_CLOSE, MID_CLOSE_REQ) + body


def build_close_response() -> bytes:
    body = (
        struct.pack("<H", 60)                # StructureSize
        + struct.pack("<H", 0)               # Flags
        + struct.pack("<I", 0)               # Reserved
        + b"\x00" * 8                        # CreationTime
        + b"\x00" * 8                        # LastAccessTime
        + b"\x00" * 8                        # LastWriteTime
        + b"\x00" * 8                        # ChangeTime
        + b"\x00" * 8                        # AllocationSize
        + b"\x00" * 8                        # EndofFile
        + struct.pack("<I", 0)               # FileAttributes
    )
    assert len(body) == 60, f"CLOSE Resp fixed body must be 60 bytes, got {len(body)}"
    return smb2_header(CMD_CLOSE, MID_CLOSE_RSP, flags=SMB2_FLAGS_SERVER_TO_REDIR) + body


def dump(name: str, blob: bytes, summary: str) -> None:
    print(f"// {summary}")
    print(f"// {name}  ({len(blob)} bytes)")
    print(f"pub const {name}: &[u8] = &[")
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        line = ", ".join(f"0x{b:02x}" for b in chunk)
        print(f"    {line},")
    print("];\n")


def main() -> None:
    dump(
        "SMB2_CREATE_REQ_BYTES",
        build_create_request(),
        r"SMB2 CREATE Request: open \PIPE\srvsvc on IPC$ tree, mid=100",
    )
    dump(
        "SMB2_CREATE_RESP_BYTES",
        build_create_response(),
        "SMB2 CREATE Response: file_id=AAAA…/BBBB…, FILE_OPENED",
    )
    dump(
        "SMB2_IOCTL_REQ_BYTES",
        build_ioctl_request(),
        "SMB2 IOCTL Request: FSCTL_PIPE_TRANSCEIVE wrapping DCE/RPC Bind (SRVSVC v3 / NDR20)",
    )
    dump(
        "SMB2_IOCTL_RESP_BYTES",
        build_ioctl_response(),
        r"SMB2 IOCTL Response: DCE/RPC Bind Ack (assoc_group=0x1234, sec_addr=\PIPE\srvsvc)",
    )
    dump(
        "SMB2_CLOSE_REQ_BYTES",
        build_close_request(),
        "SMB2 CLOSE Request: file_id=AAAA…/BBBB…",
    )
    dump(
        "SMB2_CLOSE_RESP_BYTES",
        build_close_response(),
        "SMB2 CLOSE Response: zeroed metadata",
    )


if __name__ == "__main__":
    main()
