//! Narrow internal facade over the RFC 4511 model from `rasn-ldap`.

pub(crate) use rasn_ldap::{
    AuthenticationChoice, BindRequest, BindResponse, Filter, LdapMessage, LdapString, ProtocolOp,
    ResultCode, SaslCredentials, UnbindRequest,
};
