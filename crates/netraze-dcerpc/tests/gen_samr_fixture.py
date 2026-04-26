#!/usr/bin/env python3
"""
Generate pinned byte fixtures for MS-SAMR opnums using Impacket.

Run this script in an environment with Impacket installed:
    pip install impacket
    python crates/netraze-dcerpc/tests/gen_samr_fixture.py

The generated hex arrays are baked into samr.rs unit tests so that CI
(even without Python/Impacket) can detect NDR encoder/decoder drift.
"""

import sys

# Impacket is an optional dev dependency; fail gracefully if absent.
try:
    from impacket.dcerpc.v5 import samr
    from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING, RPC_SID
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUniConformantArray
except ImportError as e:
    print(f"Impacket not installed: {e}")
    sys.exit(1)


def bytes_to_rust_hex(name: str, data: bytes) -> str:
    """Render a byte slice as a Rust `&[u8]` const."""
    hex_str = " ".join(f"0x{b:02x}," for b in data)
    return f"const {name}: &[u8] = &[\n    {hex_str}\n];\n"


def build_samr_connect2_request() -> bytes:
    """SamrConnect2 request stub (opnum 62)."""
    req = samr.SamrConnect2()
    req['ServerName'] = "NETRAZE-SAMBA"
    return req.getData()


def build_samr_enumerate_domains_request() -> bytes:
    """SamrEnumerateDomainsInSamServer request stub (opnum 6)."""
    req = samr.SamrEnumerateDomainsInSamServer()
    req['ServerHandle'] = b'\xab' * 20
    req['EnumerationContext'] = 0
    req['Buffer'] = None
    req['PreferedMaximumLength'] = 0x1000
    req['CountReturned'] = None
    return req.getData()


def build_samr_enumerate_domains_response() -> bytes:
    """Synthetic SamrEnumerateDomainsInSamServer response with 2 domains."""
    resp = samr.SamrEnumerateDomainsInSamServerResponse()
    resp['EnumerationContext'] = 0
    # Build a minimal SAMPR_ENUMERATION_BUFFER with 2 entries.
    buf = samr.SAMPR_ENUMERATION_BUFFER()
    buf['EntriesRead'] = 2

    e1 = samr.SAMPR_RID_ENUMERATION()
    e1['RelativeId'] = 1000
    e1['Name'] = RPC_UNICODE_STRING()
    e1['Name']['Data'] = 'NETRAZE'

    e2 = samr.SAMPR_RID_ENUMERATION()
    e2['RelativeId'] = 1001
    e2['Name'] = RPC_UNICODE_STRING()
    e2['Name']['Data'] = 'Builtin'

    buf['Buffer'] = samr.SAMPR_ENUMERATION_ARRAY()
    buf['Buffer']['Data'] = [e1, e2]
    resp['Buffer'] = buf
    resp['CountReturned'] = 2
    resp['ErrorCode'] = 0
    return resp.getData()


def build_samr_lookup_domain_request() -> bytes:
    """SamrLookupDomain request stub (opnum 5)."""
    req = samr.SamrLookupDomain()
    req['ServerHandle'] = b'\xab' * 20
    req['Name'] = RPC_UNICODE_STRING()
    req['Name']['Data'] = 'NETRAZE'
    return req.getData()


def build_samr_open_domain_request() -> bytes:
    """SamrOpenDomain request stub (opnum 7)."""
    req = samr.SamrOpenDomain()
    req['ServerHandle'] = b'\xab' * 20
    req['DesiredAccess'] = samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ
    req['DomainId'] = RPC_SID()
    # S-1-5-21-1111111111-2222222222-3333333333
    req['DomainId'].setData(b'\x01\x03\x00\x00\x00\x00\x00\x05'
                            b'\x15\x00\x00\x00'
                            b'\x42\x66\x6e\x42'
                            b'\x44\x84\x4d\x84'
                            b'\x35\x57\x13\x4d')
    return req.getData()


def build_samr_enumerate_users_request() -> bytes:
    """SamrEnumerateUsersInDomain request stub (opnum 13)."""
    req = samr.SamrEnumerateUsersInDomain()
    req['DomainHandle'] = b'\xcd' * 20
    req['EnumerationContext'] = 0
    req['UserAccountControl'] = samr.USER_NORMAL_ACCOUNT
    req['Buffer'] = None
    req['PreferedMaximumLength'] = 0x1000
    req['CountReturned'] = None
    return req.getData()


def build_samr_enumerate_users_response() -> bytes:
    """Synthetic SamrEnumerateUsersInDomain response with 2 users."""
    resp = samr.SamrEnumerateUsersInDomainResponse()
    resp['EnumerationContext'] = 0
    buf = samr.SAMPR_ENUMERATION_BUFFER()
    buf['EntriesRead'] = 2

    e1 = samr.SAMPR_RID_ENUMERATION()
    e1['RelativeId'] = 1000
    e1['Name'] = RPC_UNICODE_STRING()
    e1['Name']['Data'] = 'alice'

    e2 = samr.SAMPR_RID_ENUMERATION()
    e2['RelativeId'] = 1001
    e2['Name'] = RPC_UNICODE_STRING()
    e2['Name']['Data'] = 'bob'

    buf['Buffer'] = samr.SAMPR_ENUMERATION_ARRAY()
    buf['Buffer']['Data'] = [e1, e2]
    resp['Buffer'] = buf
    resp['CountReturned'] = 2
    resp['ErrorCode'] = 0
    return resp.getData()


def main():
    fixtures = [
        ("IMPACKET_REQUEST_SAMR_CONNECT2", build_samr_connect2_request()),
        ("IMPACKET_REQUEST_ENUM_DOMAINS", build_samr_enumerate_domains_request()),
        ("IMPACKET_RESPONSE_ENUM_DOMAINS", build_samr_enumerate_domains_response()),
        ("IMPACKET_REQUEST_LOOKUP_DOMAIN", build_samr_lookup_domain_request()),
        ("IMPACKET_REQUEST_OPEN_DOMAIN", build_samr_open_domain_request()),
        ("IMPACKET_REQUEST_ENUM_USERS", build_samr_enumerate_users_request()),
        ("IMPACKET_RESPONSE_ENUM_USERS", build_samr_enumerate_users_response()),
    ]

    print("// Auto-generated by gen_samr_fixture.py — do not hand-edit.")
    print("// Paste these constants into samr.rs unit tests.\n")
    for name, data in fixtures:
        print(bytes_to_rust_hex(name, data))


if __name__ == "__main__":
    main()
