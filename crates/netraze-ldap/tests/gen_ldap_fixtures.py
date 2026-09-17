#!/usr/bin/env python3
"""Generate the LDAP BER fixtures pinned by the Rust unit tests.

Run with Impacket 0.13.0 on PYTHONPATH. The output is deliberately Rust byte
arrays so refreshing a fixture remains an explicit, reviewable operation.
"""

from impacket.ldap.ldapasn1 import (
    BindRequest,
    BindResponse,
    LDAPMessage,
    PartialAttribute,
    SearchRequest,
    SearchResultDone,
    SearchResultEntry,
    SimplePagedResultsControl,
)
from pyasn1.codec.ber import encoder


def ldap_message(message_id, operation, controls=None):
    message = LDAPMessage()
    message["messageID"] = message_id
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    if controls:
        message["controls"].setComponents(*controls)
    return encoder.encode(message)


def rust_array(name, value):
    octets = ", ".join(f"0x{octet:02x}" for octet in value)
    print(f"const {name}: &[u8] = &[{octets}];")


bind = BindRequest()
bind["version"] = 3
bind["name"] = ""
bind["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
bind["authentication"]["sasl"]["credentials"] = b"\x01\x02\x03"
rust_array("SASL_BIND", ldap_message(1, bind))

bind_response = BindResponse()
bind_response["resultCode"] = "saslBindInProgress"
bind_response["matchedDN"] = ""
bind_response["diagnosticMessage"] = ""
bind_response["serverSaslCreds"] = b"\x04\x05"
rust_array("SASL_BIND_RESPONSE", ldap_message(1, bind_response))

root_dse = SearchRequest()
root_dse["baseObject"] = ""
root_dse["scope"] = "baseObject"
root_dse["derefAliases"] = "neverDerefAliases"
root_dse["sizeLimit"] = 0
root_dse["timeLimit"] = 0
root_dse["typesOnly"] = False
root_dse["filter"]["present"] = "objectClass"
root_dse["attributes"].setComponents("defaultNamingContext")
rust_array("ROOT_DSE_SEARCH", ldap_message(2, root_dse))

search = SearchRequest()
search["baseObject"] = "DC=example,DC=test"
search["scope"] = "wholeSubtree"
search["derefAliases"] = "neverDerefAliases"
search["sizeLimit"] = 0
search["timeLimit"] = 0
search["typesOnly"] = False
search["filter"]["equalityMatch"]["attributeDesc"] = "sAMAccountType"
search["filter"]["equalityMatch"]["assertionValue"] = b"805306368"
search["attributes"].setComponents(
    "sAMAccountName", "userAccountControl", "adminCount"
)
page = SimplePagedResultsControl(size=1000, cookie=b"next")
rust_array("PAGED_USER_SEARCH", ldap_message(3, search, [page]))

entry = SearchResultEntry()
entry["objectName"] = "CN=Alice,DC=example,DC=test"
sam_name = PartialAttribute()
sam_name["type"] = "sAMAccountName"
sam_name["vals"].setComponents(b"alice")
account_control = PartialAttribute()
account_control["type"] = "userAccountControl"
account_control["vals"].setComponents(b"514")
admin_count = PartialAttribute()
admin_count["type"] = "adminCount"
admin_count["vals"].setComponents(b"1")
entry["attributes"].setComponents(sam_name, account_control, admin_count)
rust_array("USER_ENTRY", ldap_message(3, entry))

done = SearchResultDone()
done["resultCode"] = "success"
done["matchedDN"] = ""
done["diagnosticMessage"] = ""
empty_page = SimplePagedResultsControl(size=0, cookie=b"")
rust_array("SEARCH_DONE", ldap_message(3, done, [empty_page]))
