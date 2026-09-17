//! Narrow LDAP-module facade over the RFC 4511 model from `rasn-ldap`.

pub(crate) use rasn_ldap::{
    AttributeValueAssertion, AuthenticationChoice, BindRequest, BindResponse, Control, Filter,
    LdapMessage, LdapString, MatchingRuleAssertion, ProtocolOp, ResultCode, SaslCredentials,
    SearchRequest, SearchRequestDerefAliases, SearchRequestScope, SearchResultEntry,
    SubstringChoice, SubstringFilter, UnbindRequest,
};

use rasn::prelude::{AsnType, Decode, Decoder, Encode, OctetString};

/// BER payload carried by Microsoft's simple paged-results control.
#[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq)]
pub(crate) struct PagedResultsValue {
    pub size: u32,
    pub cookie: OctetString,
}
