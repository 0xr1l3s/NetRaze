#!/usr/bin/env python3
"""Generate NDR byte fixtures for `NetrShareEnum` request/response using
Impacket as the ground-truth encoder.

Run:
    py crates/getexec-dcerpc/tests/gen_srvs_fixture.py

Outputs hex dumps + Rust-ready `&[u8]` literals on stdout. Paste into
`crates/getexec-dcerpc/src/interfaces/srvsvc.rs` test module.

Not executed in CI — it's a one-off fixture generator. The resulting
bytes are pinned as constants in the Rust tests so we don't need Impacket
installed to re-run the suite.
"""

import sys, os

# Path to the impacket checkout sitting next to NetRaze/.
HERE = os.path.dirname(os.path.abspath(__file__))
IMPACKET = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "impacket"))
sys.path.insert(0, IMPACKET)

from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.dtypes import NULL


def dump(name, blob):
    """Pretty-print a Rust byte-literal for pasting into a test."""
    print(f"// {name}  ({len(blob)} bytes)")
    # 16 bytes per line, lower-case hex
    lines = []
    for i in range(0, len(blob), 16):
        chunk = blob[i : i + 16]
        hx = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append("    " + hx + ",")
    print("const " + name.upper() + ": &[u8] = &[")
    print("\n".join(lines))
    print("];\n")


# ---------------------------------------------------------------------------
# Request: NetrShareEnum(ServerName="\\\\SERVER", Level=1, PreferredMax=0xFFFFFFFF,
# ResumeHandle=0)
# ---------------------------------------------------------------------------
req = srvs.NetrShareEnum()
req["ServerName"] = "\\\\SERVER\x00"
req["PreferedMaximumLength"] = 0xFFFFFFFF
req["ResumeHandle"] = 0

# Empty container on the request side — Level=1 with count=0 buffer=NULL.
req["InfoStruct"]["Level"] = 1
req["InfoStruct"]["ShareInfo"]["tag"] = 1
req["InfoStruct"]["ShareInfo"]["Level1"]["EntriesRead"] = 0
req["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"] = NULL

dump("impacket_request_level1_server", req.getData())


# ---------------------------------------------------------------------------
# Response: synthesized with 2 shares ("IPC$" IPC type 3, "C$" disk type 0).
# ---------------------------------------------------------------------------
resp = srvs.NetrShareEnumResponse()
resp["InfoStruct"]["Level"] = 1
resp["InfoStruct"]["ShareInfo"]["tag"] = 1
resp["InfoStruct"]["ShareInfo"]["Level1"]["EntriesRead"] = 2

s1 = srvs.SHARE_INFO_1()
s1["shi1_netname"] = "IPC$\x00"
s1["shi1_type"] = 3
s1["shi1_remark"] = "Remote IPC\x00"

s2 = srvs.SHARE_INFO_1()
s2["shi1_netname"] = "C$\x00"
s2["shi1_type"] = 0
s2["shi1_remark"] = "Default share\x00"

lpbuf = srvs.LPSHARE_INFO_1_ARRAY()
lpbuf["Data"] = [s1, s2]
resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"] = lpbuf

resp["TotalEntries"] = 2
resp["ResumeHandle"] = 0
resp["ErrorCode"] = 0

dump("impacket_response_two_shares", resp.getData())


# ---------------------------------------------------------------------------
# Response: empty enumeration (Buffer=NULL).
# ---------------------------------------------------------------------------
empty = srvs.NetrShareEnumResponse()
empty["InfoStruct"]["Level"] = 1
empty["InfoStruct"]["ShareInfo"]["tag"] = 1
empty["InfoStruct"]["ShareInfo"]["Level1"]["EntriesRead"] = 0
empty["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"] = NULL
empty["TotalEntries"] = 0
empty["ResumeHandle"] = 0
empty["ErrorCode"] = 0

dump("impacket_response_empty", empty.getData())
