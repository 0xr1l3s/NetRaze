//! Bounded asynchronous LDAP transport and NTLM SASL bind.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use crate::ntlm::{
    NegState, NtlmClient, NtlmCredential, NtlmSecurityContext, ntlm_mech_types_der,
    parse_neg_token_resp,
};
use rasn::types::OctetString;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::message::{
    AuthenticationChoice, BindRequest, BindResponse, LdapMessage, LdapString, ProtocolOp,
    ResultCode, SaslCredentials, SearchRequest, SearchRequestDerefAliases, SearchRequestScope,
    SearchResultEntry, UnbindRequest,
};
use super::{controls, search::parse_filter};

const DEFAULT_LDAP_PORT: u16 = 389;
const READ_CHUNK_SIZE: usize = 8 * 1024;
const MAX_PAGE_LOOPS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapClientConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub max_pdu_size: usize,
    pub page_size: u32,
}

impl LdapClientConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        Self {
            endpoint: with_default_port(&endpoint, DEFAULT_LDAP_PORT),
            connect_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(20),
            max_pdu_size: 16 * 1024 * 1024,
            page_size: 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapEntry {
    pub dn: String,
    pub attributes: BTreeMap<String, Vec<Vec<u8>>>,
}

impl LdapEntry {
    #[must_use]
    pub fn values(&self, attribute: &str) -> Option<&[Vec<u8>]> {
        self.attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
            .map(|(_, values)| values.as_slice())
    }

    #[must_use]
    pub fn first_utf8(&self, attribute: &str) -> Option<&str> {
        self.values(attribute)?
            .first()
            .and_then(|value| std::str::from_utf8(value).ok())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchOutcome {
    pub entries: Vec<LdapEntry>,
    pub referrals: Vec<String>,
}

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("LDAP connection failed: {0}")]
    Connect(String),
    #[error("LDAP operation timed out")]
    Timeout,
    #[error("LDAP I/O failed: {0}")]
    Io(String),
    #[error("LDAP BER error: {0}")]
    Ber(String),
    #[error("LDAP PDU exceeds configured maximum ({length} > {maximum})")]
    OversizedPdu { length: usize, maximum: usize },
    #[error("LDAP response message ID mismatch: expected {expected}, got {actual}")]
    MessageIdMismatch { expected: u32, actual: u32 },
    #[error("LDAP server sent an unsolicited notification")]
    UnsolicitedNotification,
    #[error("unexpected LDAP operation: {0}")]
    UnexpectedOperation(String),
    #[error("LDAP result {code}: {diagnostic}")]
    Result { code: String, diagnostic: String },
    #[error("NTLM SASL bind failed: {0}")]
    Ntlm(String),
    #[error("LDAP client state error: {0}")]
    State(String),
}

impl From<std::io::Error> for LdapError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

pub struct LdapClient {
    stream: TcpStream,
    config: LdapClientConfig,
    next_message_id: u32,
    read_buffer: Vec<u8>,
    security_context: Option<NtlmSecurityContext>,
    usable: bool,
}

impl core::fmt::Debug for LdapClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LdapClient")
            .field("config", &self.config)
            .field("next_message_id", &self.next_message_id)
            .field("protected", &self.security_context.is_some())
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

impl LdapClient {
    pub async fn connect(config: LdapClientConfig) -> Result<Self, LdapError> {
        let stream = timeout(config.connect_timeout, TcpStream::connect(&config.endpoint))
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|error| LdapError::Connect(error.to_string()))?;
        Ok(Self {
            stream,
            config,
            next_message_id: 1,
            read_buffer: Vec::new(),
            security_context: None,
            usable: true,
        })
    }

    /// Authenticate with GSS-SPNEGO/NTLMv2 and require integrity plus confidentiality.
    pub async fn bind_ntlm(
        &mut self,
        username: &str,
        domain: &str,
        credential: NtlmCredential,
    ) -> Result<(), LdapError> {
        if self.security_context.is_some() {
            return Err(LdapError::State("connection is already bound".into()));
        }
        let mut ntlm = NtlmClient::new(username, domain, credential);
        let negotiate = ntlm
            .negotiate_token()
            .map_err(|error| LdapError::Ntlm(error.to_string()))?;
        let first = self.bind_exchange(negotiate).await?;
        if first.result_code != ResultCode::SaslBindInProgress {
            return Err(result_error(first.result_code, &first.diagnostic_message));
        }
        let challenge = first
            .server_sasl_creds
            .ok_or_else(|| LdapError::Ntlm("server omitted its SPNEGO challenge".into()))?;
        let authenticate = ntlm
            .authenticate_token(&challenge)
            .map_err(|error| LdapError::Ntlm(error.to_string()))?;
        let second = self.bind_exchange(authenticate.spnego_token).await?;
        if second.result_code != ResultCode::Success {
            return Err(result_error(second.result_code, &second.diagnostic_message));
        }

        let context = authenticate.security_context;
        if let Some(server_credentials) = second.server_sasl_creds {
            let response = parse_neg_token_resp(&server_credentials)
                .map_err(|error| LdapError::Ntlm(error.to_string()))?;
            if response.state == Some(NegState::Reject) {
                return Err(LdapError::Ntlm(
                    "server rejected SPNEGO authentication".into(),
                ));
            }
            if let Some(mic) = response.mech_list_mic {
                context
                    .verify_mech_list_mic(&ntlm_mech_types_der(), &mic)
                    .map_err(|error| LdapError::Ntlm(error.to_string()))?;
            }
        }
        self.security_context = Some(context);
        Ok(())
    }

    pub async fn root_dse(&mut self) -> Result<LdapEntry, LdapError> {
        let mut outcome = self
            .search_with_scope(
                "",
                "(objectClass=*)",
                &["defaultNamingContext"],
                SearchRequestScope::BaseObject,
                false,
            )
            .await?;
        if outcome.entries.len() != 1 {
            return Err(LdapError::UnexpectedOperation(format!(
                "RootDSE returned {} entries",
                outcome.entries.len()
            )));
        }
        Ok(outcome.entries.remove(0))
    }

    pub async fn search(
        &mut self,
        base_dn: &str,
        filter: &str,
        attributes: &[&str],
    ) -> Result<SearchOutcome, LdapError> {
        self.search_with_scope(
            base_dn,
            filter,
            attributes,
            SearchRequestScope::WholeSubtree,
            true,
        )
        .await
    }

    async fn search_with_scope(
        &mut self,
        base_dn: &str,
        filter: &str,
        attributes: &[&str],
        scope: SearchRequestScope,
        paged: bool,
    ) -> Result<SearchOutcome, LdapError> {
        if self.security_context.is_none() {
            return Err(LdapError::State(
                "search requires an authenticated sign-and-seal context".into(),
            ));
        }
        let filter = parse_filter(filter).map_err(LdapError::Ber)?;
        let attributes = attributes
            .iter()
            .map(|attribute| LdapString::from(*attribute))
            .collect::<Vec<_>>();
        let mut outcome = SearchOutcome::default();
        let mut cookie = Vec::new();
        let mut seen_cookies = HashSet::new();

        for page in 0..MAX_PAGE_LOOPS {
            let request = SearchRequest::new(
                LdapString::from(base_dn),
                scope,
                SearchRequestDerefAliases::NeverDerefAliases,
                0,
                0,
                false,
                filter.clone(),
                attributes.clone(),
            );
            let message_id = self.allocate_message_id();
            let mut message = LdapMessage::new(message_id, ProtocolOp::SearchRequest(request));
            if paged {
                message.controls = Some(vec![
                    controls::paged_results_control(self.config.page_size, &cookie)
                        .map_err(LdapError::Ber)?,
                ]);
            }
            let (entries, referrals, next_cookie) = self.search_page(message_id, message).await?;
            outcome.entries.extend(entries);
            outcome.referrals.extend(referrals);
            if !paged || next_cookie.is_empty() {
                return Ok(outcome);
            }
            record_paging_cookie(&mut seen_cookies, &next_cookie)?;
            cookie = next_cookie;
            if page + 1 == MAX_PAGE_LOOPS {
                break;
            }
        }
        Err(LdapError::State(
            "LDAP paging exceeded the 10000-page safety limit".into(),
        ))
    }

    async fn search_page(
        &mut self,
        message_id: u32,
        message: LdapMessage,
    ) -> Result<(Vec<LdapEntry>, Vec<String>, Vec<u8>), LdapError> {
        let operation_timeout = self.config.operation_timeout;
        timeout(operation_timeout, async {
            self.send_message(&message).await?;
            let mut entries = Vec::new();
            let mut referrals = Vec::new();
            loop {
                let response = self.receive_message().await?;
                self.validate_message_id(message_id, response.message_id)?;
                match response.protocol_op {
                    ProtocolOp::SearchResEntry(entry) => entries.push(convert_entry(entry)),
                    ProtocolOp::SearchResRef(reference) => {
                        referrals.extend(reference.0.into_iter().map(|uri| uri.0));
                    }
                    ProtocolOp::SearchResDone(done) => {
                        let result = done.0;
                        if let Some(result_referrals) = &result.referral {
                            referrals.extend(result_referrals.iter().map(|uri| uri.0.clone()));
                        }
                        if !matches!(
                            result.result_code,
                            ResultCode::Success | ResultCode::Referral
                        ) {
                            return Err(result_error(
                                result.result_code,
                                &result.diagnostic_message,
                            ));
                        }
                        let cookie = paging_cookie(response.controls.as_deref())?;
                        return Ok((entries, referrals, cookie));
                    }
                    operation => {
                        self.usable = false;
                        return Err(LdapError::UnexpectedOperation(format!("{operation:?}")));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            self.usable = false;
            LdapError::Timeout
        })?
    }

    /// Send RFC 4511 Unbind and close the stream. Unbind intentionally has no response.
    pub async fn unbind(&mut self) -> Result<(), LdapError> {
        if !self.usable {
            return Ok(());
        }
        let message_id = self.allocate_message_id();
        let message = LdapMessage::new(message_id, ProtocolOp::UnbindRequest(UnbindRequest));
        let operation_timeout = self.config.operation_timeout;
        let result = match timeout(operation_timeout, self.send_message(&message)).await {
            Ok(result) => result,
            Err(_) => {
                self.usable = false;
                return Err(LdapError::Timeout);
            }
        };
        if result.is_ok() {
            self.stream.shutdown().await?;
        }
        self.usable = false;
        result
    }

    async fn bind_exchange(&mut self, token: Vec<u8>) -> Result<BindResponse, LdapError> {
        let request = BindRequest::new(
            3,
            LdapString::from(""),
            AuthenticationChoice::Sasl(SaslCredentials::new(
                LdapString::from("GSS-SPNEGO"),
                Some(OctetString::from(token)),
            )),
        );
        let message_id = self.allocate_message_id();
        let message = LdapMessage::new(message_id, ProtocolOp::BindRequest(request));
        let operation_timeout = self.config.operation_timeout;
        let response = timeout(operation_timeout, async {
            self.send_message(&message).await?;
            self.receive_message().await
        })
        .await
        .map_err(|_| {
            self.usable = false;
            LdapError::Timeout
        })??;
        self.validate_message_id(message_id, response.message_id)?;
        match response.protocol_op {
            ProtocolOp::BindResponse(response) => Ok(response),
            operation => {
                self.usable = false;
                Err(LdapError::UnexpectedOperation(format!("{operation:?}")))
            }
        }
    }

    pub(crate) async fn send_message(&mut self, message: &LdapMessage) -> Result<(), LdapError> {
        let encoded =
            rasn::ber::encode(message).map_err(|error| LdapError::Ber(error.to_string()))?;
        if encoded.len() > self.config.max_pdu_size {
            return Err(LdapError::OversizedPdu {
                length: encoded.len(),
                maximum: self.config.max_pdu_size,
            });
        }
        let wire = if let Some(context) = self.security_context.as_mut() {
            let protected = context
                .wrap(&encoded)
                .map_err(|error| LdapError::Ntlm(error.to_string()))?;
            if protected.len() > self.config.max_pdu_size {
                return Err(LdapError::OversizedPdu {
                    length: protected.len(),
                    maximum: self.config.max_pdu_size,
                });
            }
            let length = u32::try_from(protected.len()).map_err(|_| LdapError::OversizedPdu {
                length: protected.len(),
                maximum: u32::MAX as usize,
            })?;
            let mut framed = Vec::with_capacity(4 + protected.len());
            framed.extend_from_slice(&length.to_be_bytes());
            framed.extend_from_slice(&protected);
            framed
        } else {
            encoded
        };
        if let Err(error) = self.stream.write_all(&wire).await {
            self.usable = false;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) async fn receive_message(&mut self) -> Result<LdapMessage, LdapError> {
        let encoded = if self.security_context.is_some() {
            let mut length_bytes = [0; 4];
            self.read_exact(&mut length_bytes).await?;
            let length = u32::from_be_bytes(length_bytes) as usize;
            if length > self.config.max_pdu_size {
                self.usable = false;
                return Err(LdapError::OversizedPdu {
                    length,
                    maximum: self.config.max_pdu_size,
                });
            }
            let mut protected = vec![0; length];
            self.read_exact(&mut protected).await?;
            match self
                .security_context
                .as_mut()
                .expect("checked above")
                .unwrap(&protected)
            {
                Ok(encoded) => encoded,
                Err(error) => {
                    self.usable = false;
                    return Err(LdapError::Ntlm(error.to_string()));
                }
            }
        } else {
            self.receive_ber_frame().await?
        };
        match rasn::ber::decode(&encoded) {
            Ok(message) => Ok(message),
            Err(error) => {
                self.usable = false;
                Err(LdapError::Ber(error.to_string()))
            }
        }
    }

    async fn receive_ber_frame(&mut self) -> Result<Vec<u8>, LdapError> {
        loop {
            let frame_length = match ber_frame_length(&self.read_buffer, self.config.max_pdu_size) {
                Ok(frame_length) => frame_length,
                Err(error) => {
                    self.usable = false;
                    return Err(error);
                }
            };
            match frame_length {
                Some(length) => {
                    let remainder = self.read_buffer.split_off(length);
                    return Ok(std::mem::replace(&mut self.read_buffer, remainder));
                }
                None => {
                    let mut chunk = [0; READ_CHUNK_SIZE];
                    let read = self.stream.read(&mut chunk).await.map_err(|error| {
                        self.usable = false;
                        LdapError::Io(error.to_string())
                    })?;
                    if read == 0 {
                        self.usable = false;
                        return Err(LdapError::Io(if self.read_buffer.is_empty() {
                            "connection closed".into()
                        } else {
                            "connection closed during LDAP PDU".into()
                        }));
                    }
                    self.read_buffer.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }

    async fn read_exact(&mut self, output: &mut [u8]) -> Result<(), LdapError> {
        if let Err(error) = self.stream.read_exact(output).await {
            self.usable = false;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn allocate_message_id(&mut self) -> u32 {
        let current = self.next_message_id;
        self.next_message_id = self.next_message_id.checked_add(1).unwrap_or(1);
        current
    }

    pub(crate) fn validate_message_id(
        &mut self,
        expected: u32,
        actual: u32,
    ) -> Result<(), LdapError> {
        if actual == 0 {
            self.usable = false;
            return Err(LdapError::UnsolicitedNotification);
        }
        if actual != expected {
            self.usable = false;
            return Err(LdapError::MessageIdMismatch { expected, actual });
        }
        Ok(())
    }
}

pub(crate) fn ber_frame_length(buffer: &[u8], maximum: usize) -> Result<Option<usize>, LdapError> {
    if buffer.is_empty() {
        return Ok(None);
    }
    if buffer[0] != 0x30 {
        return Err(LdapError::Ber("LDAPMessage must be a BER SEQUENCE".into()));
    }
    let Some(&first_length) = buffer.get(1) else {
        return Ok(None);
    };
    let (content_length, header_length) = if first_length < 0x80 {
        (usize::from(first_length), 2)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 {
            return Err(LdapError::Ber(
                "indefinite BER length is not allowed".into(),
            ));
        }
        if count > core::mem::size_of::<usize>() {
            return Err(LdapError::Ber("BER length is too wide".into()));
        }
        if buffer.len() < 2 + count {
            return Ok(None);
        }
        if buffer[2] == 0 {
            return Err(LdapError::Ber("non-minimal BER length".into()));
        }
        let mut length = 0_usize;
        for byte in &buffer[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| LdapError::Ber("BER length overflow".into()))?;
        }
        if length < 0x80 {
            return Err(LdapError::Ber("non-minimal BER long-form length".into()));
        }
        (length, 2 + count)
    };
    let total = header_length
        .checked_add(content_length)
        .ok_or_else(|| LdapError::Ber("BER PDU length overflow".into()))?;
    if total > maximum {
        return Err(LdapError::OversizedPdu {
            length: total,
            maximum,
        });
    }
    Ok((buffer.len() >= total).then_some(total))
}

fn result_error(code: ResultCode, diagnostic: &LdapString) -> LdapError {
    LdapError::Result {
        code: format!("{code:?}"),
        diagnostic: diagnostic.to_string(),
    }
}

fn convert_entry(entry: SearchResultEntry) -> LdapEntry {
    let attributes = entry
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.r#type.0,
                attribute
                    .vals
                    .to_vec()
                    .into_iter()
                    .map(|value| value.to_vec())
                    .collect(),
            )
        })
        .collect();
    LdapEntry {
        dn: entry.object_name.0,
        attributes,
    }
}

fn paging_cookie(controls: Option<&[super::message::Control]>) -> Result<Vec<u8>, LdapError> {
    let Some(controls) = controls else {
        return Ok(Vec::new());
    };
    let Some(control) = controls
        .iter()
        .find(|control| control.control_type.as_ref() == controls::OID_PAGED_RESULTS.as_bytes())
    else {
        return Ok(Vec::new());
    };
    let value = control
        .control_value
        .as_deref()
        .ok_or_else(|| LdapError::Ber("paged-results response omitted controlValue".into()))?;
    controls::decode_paged_cookie(value).map_err(LdapError::Ber)
}

fn record_paging_cookie(seen: &mut HashSet<Vec<u8>>, cookie: &[u8]) -> Result<(), LdapError> {
    if !seen.insert(cookie.to_vec()) {
        return Err(LdapError::State(
            "server repeated an LDAP paging cookie".into(),
        ));
    }
    Ok(())
}

fn with_default_port(endpoint: &str, port: u16) -> String {
    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            return if endpoint.len() == end + 1 {
                format!("{endpoint}:{port}")
            } else {
                endpoint.to_owned()
            };
        }
    }
    match endpoint.matches(':').count() {
        0 => format!("{endpoint}:{port}"),
        1 => endpoint.to_owned(),
        _ => format!("[{endpoint}]:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::SetOf;
    use rasn_ldap::{LdapResult, PartialAttribute, SearchResultDone, SearchResultReference};
    use tokio::net::TcpListener;

    // Generated by tests/gen_ldap_fixtures.py with Impacket 0.13.0. These pin
    // the application/context tags and the nested paged-control BER shape.
    const SASL_BIND: &[u8] = &[
        0x30, 0x1d, 0x02, 0x01, 0x01, 0x60, 0x18, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x11, 0x04,
        0x0a, 0x47, 0x53, 0x53, 0x2d, 0x53, 0x50, 0x4e, 0x45, 0x47, 0x4f, 0x04, 0x03, 0x01, 0x02,
        0x03,
    ];
    const SASL_BIND_RESPONSE: &[u8] = &[
        0x30, 0x10, 0x02, 0x01, 0x01, 0x61, 0x0b, 0x0a, 0x01, 0x0e, 0x04, 0x00, 0x04, 0x00, 0x87,
        0x02, 0x04, 0x05,
    ];
    const ROOT_DSE_SEARCH: &[u8] = &[
        0x30, 0x3b, 0x02, 0x01, 0x02, 0x63, 0x36, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65,
        0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x16, 0x04, 0x14, 0x64, 0x65, 0x66, 0x61,
        0x75, 0x6c, 0x74, 0x4e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78,
        0x74,
    ];
    const PAGED_USER_SEARCH: &[u8] = &[
        0x30, 0x81, 0xa1, 0x02, 0x01, 0x03, 0x63, 0x72, 0x04, 0x12, 0x44, 0x43, 0x3d, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x44, 0x43, 0x3d, 0x74, 0x65, 0x73, 0x74, 0x0a, 0x01,
        0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa3, 0x1b,
        0x04, 0x0e, 0x73, 0x41, 0x4d, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x54, 0x79, 0x70,
        0x65, 0x04, 0x09, 0x38, 0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x36, 0x38, 0x30, 0x30, 0x04,
        0x0e, 0x73, 0x41, 0x4d, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65,
        0x04, 0x12, 0x75, 0x73, 0x65, 0x72, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x43, 0x6f,
        0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x04, 0x0a, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x43, 0x6f, 0x75,
        0x6e, 0x74, 0xa0, 0x28, 0x30, 0x26, 0x04, 0x16, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30,
        0x2e, 0x31, 0x31, 0x33, 0x35, 0x35, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x33, 0x31, 0x39,
        0x04, 0x0c, 0x30, 0x0a, 0x02, 0x02, 0x03, 0xe8, 0x04, 0x04, 0x6e, 0x65, 0x78, 0x74,
    ];
    const USER_ENTRY: &[u8] = &[
        0x30, 0x6f, 0x02, 0x01, 0x03, 0x64, 0x6a, 0x04, 0x1b, 0x43, 0x4e, 0x3d, 0x41, 0x6c, 0x69,
        0x63, 0x65, 0x2c, 0x44, 0x43, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x44,
        0x43, 0x3d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x4b, 0x30, 0x19, 0x04, 0x0e, 0x73, 0x41, 0x4d,
        0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x31, 0x07, 0x04, 0x05,
        0x61, 0x6c, 0x69, 0x63, 0x65, 0x30, 0x1b, 0x04, 0x12, 0x75, 0x73, 0x65, 0x72, 0x41, 0x63,
        0x63, 0x6f, 0x75, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x31, 0x05, 0x04,
        0x03, 0x35, 0x31, 0x34, 0x30, 0x11, 0x04, 0x0a, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x43, 0x6f,
        0x75, 0x6e, 0x74, 0x31, 0x03, 0x04, 0x01, 0x31,
    ];
    const SEARCH_DONE: &[u8] = &[
        0x30, 0x31, 0x02, 0x01, 0x03, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0xa0,
        0x23, 0x30, 0x21, 0x04, 0x16, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x31,
        0x33, 0x35, 0x35, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x33, 0x31, 0x39, 0x04, 0x07, 0x30,
        0x05, 0x02, 0x01, 0x00, 0x04, 0x00,
    ];

    #[test]
    fn impacket_ldap_fixtures_decode_and_reencode_exactly() {
        for fixture in [
            SASL_BIND,
            SASL_BIND_RESPONSE,
            ROOT_DSE_SEARCH,
            PAGED_USER_SEARCH,
            USER_ENTRY,
            SEARCH_DONE,
        ] {
            let message: LdapMessage = rasn::ber::decode(fixture).unwrap();
            assert_eq!(rasn::ber::encode(&message).unwrap(), fixture);
        }

        let bind_response: LdapMessage = rasn::ber::decode(SASL_BIND_RESPONSE).unwrap();
        let ProtocolOp::BindResponse(bind_response) = bind_response.protocol_op else {
            panic!("fixture did not decode as BindResponse");
        };
        assert_eq!(bind_response.result_code, ResultCode::SaslBindInProgress);
        assert_eq!(
            bind_response.server_sasl_creds.as_deref(),
            Some(&[4, 5][..])
        );

        let done: LdapMessage = rasn::ber::decode(SEARCH_DONE).unwrap();
        assert_eq!(
            paging_cookie(done.controls.as_deref()).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn ber_framing_waits_for_split_header_and_payload() {
        assert_eq!(ber_frame_length(&[0x30], 1024).unwrap(), None);
        assert_eq!(ber_frame_length(&[0x30, 3, 1], 1024).unwrap(), None);
        assert_eq!(
            ber_frame_length(&[0x30, 3, 1, 2, 3], 1024).unwrap(),
            Some(5)
        );
    }

    #[test]
    fn ber_framing_leaves_coalesced_data_to_the_caller() {
        assert_eq!(
            ber_frame_length(&[0x30, 1, 0, 0x30, 1, 0], 1024).unwrap(),
            Some(3)
        );
    }

    #[test]
    fn ber_framing_accepts_long_form_lengths() {
        let mut frame = vec![0x30, 0x81, 0x80];
        frame.resize(131, 0);
        assert_eq!(ber_frame_length(&frame, 1024).unwrap(), Some(131));
    }

    #[test]
    fn ber_framing_rejects_indefinite_nonminimal_and_oversized_lengths() {
        assert!(ber_frame_length(&[0x30, 0x80], 1024).is_err());
        assert!(ber_frame_length(&[0x30, 0x81, 0x7f], 1024).is_err());
        assert!(matches!(
            ber_frame_length(&[0x30, 0x82, 0x10, 0x00], 1024),
            Err(LdapError::OversizedPdu { .. })
        ));
    }

    #[test]
    fn default_endpoint_handles_hostnames_and_ipv6() {
        assert_eq!(with_default_port("dc.example", 389), "dc.example:389");
        assert_eq!(with_default_port("dc.example:1389", 389), "dc.example:1389");
        assert_eq!(with_default_port("::1", 389), "[::1]:389");
        assert_eq!(with_default_port("[::1]", 389), "[::1]:389");
    }

    #[test]
    fn paging_rejects_a_repeated_cookie() {
        let mut seen = HashSet::new();
        record_paging_cookie(&mut seen, b"same").unwrap();
        assert!(record_paging_cookie(&mut seen, b"same").is_err());
    }

    #[tokio::test]
    async fn message_id_violations_poison_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = LdapClient::connect(LdapClientConfig::new(address.to_string()))
            .await
            .unwrap();
        let _peer = accept.await.unwrap();

        assert!(client.validate_message_id(7, 8).is_err());
        assert!(!client.usable);
    }

    #[tokio::test]
    async fn ntlm_bind_advances_and_correlates_message_ids() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let first = read_test_ber(&mut socket).await;
            let first: LdapMessage = rasn::ber::decode(&first).unwrap();
            assert_eq!(first.message_id, 1);

            let challenge = test_challenge();
            let first_response = BindResponse::new(
                ResultCode::SaslBindInProgress,
                LdapString::from(""),
                LdapString::from(""),
                None,
                Some(OctetString::from(crate::ntlm::wrap_spnego_resp(&challenge))),
            );
            write_test_message(
                &mut socket,
                LdapMessage::new(1, ProtocolOp::BindResponse(first_response)),
            )
            .await;

            let second = read_test_ber(&mut socket).await;
            let second: LdapMessage = rasn::ber::decode(&second).unwrap();
            assert_eq!(second.message_id, 2);
            let final_response = BindResponse::new(
                ResultCode::Success,
                LdapString::from(""),
                LdapString::from(""),
                None,
                None,
            );
            write_test_message(
                &mut socket,
                LdapMessage::new(2, ProtocolOp::BindResponse(final_response)),
            )
            .await;
        });

        let mut client = LdapClient::connect(LdapClientConfig::new(address.to_string()))
            .await
            .unwrap();
        client
            .bind_ntlm(
                "alice",
                "EXAMPLE",
                NtlmCredential::Password("password".into()),
            )
            .await
            .unwrap();
        assert!(client.security_context.is_some());
        assert_eq!(client.next_message_id, 3);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn protected_search_iterates_pages_and_returns_referrals() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = [0x33; 16];
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut protection = NtlmSecurityContext::new_server(key);

            for (expected_id, expected_cookie, next_cookie, username) in [
                (1, Vec::new(), b"next".to_vec(), "alice"),
                (2, b"next".to_vec(), Vec::new(), "bob"),
            ] {
                let request = read_test_protected(&mut socket, &mut protection).await;
                let request: LdapMessage = rasn::ber::decode(&request).unwrap();
                assert_eq!(request.message_id, expected_id);
                assert_eq!(
                    paging_cookie(request.controls.as_deref()).unwrap(),
                    expected_cookie
                );

                let entry = SearchResultEntry::new(
                    LdapString::from(format!("CN={username},DC=example,DC=test")),
                    vec![PartialAttribute::new(
                        LdapString::from("sAMAccountName"),
                        SetOf::from_vec(vec![OctetString::from(username.as_bytes().to_vec())]),
                    )],
                );
                write_test_protected(
                    &mut socket,
                    &mut protection,
                    LdapMessage::new(expected_id, ProtocolOp::SearchResEntry(entry)),
                )
                .await;
                if expected_id == 1 {
                    write_test_protected(
                        &mut socket,
                        &mut protection,
                        LdapMessage::new(
                            expected_id,
                            ProtocolOp::SearchResRef(SearchResultReference(vec![
                                LdapString::from("ldap://other.example.test/DC=example,DC=test"),
                            ])),
                        ),
                    )
                    .await;
                }
                let done = SearchResultDone(LdapResult::new(
                    ResultCode::Success,
                    LdapString::from(""),
                    LdapString::from(""),
                ));
                let mut response = LdapMessage::new(expected_id, ProtocolOp::SearchResDone(done));
                response.controls = Some(vec![
                    controls::paged_results_control(1000, &next_cookie).unwrap(),
                ]);
                write_test_protected(&mut socket, &mut protection, response).await;
            }
        });

        let mut client = LdapClient::connect(LdapClientConfig::new(address.to_string()))
            .await
            .unwrap();
        client.security_context = Some(NtlmSecurityContext::new(key));
        let outcome = client
            .search(
                "DC=example,DC=test",
                "(sAMAccountType=805306368)",
                &["sAMAccountName"],
            )
            .await
            .unwrap();
        assert_eq!(
            outcome
                .entries
                .iter()
                .filter_map(|entry| entry.first_utf8("samaccountname"))
                .collect::<Vec<_>>(),
            ["alice", "bob"]
        );
        assert_eq!(
            outcome.referrals,
            ["ldap://other.example.test/DC=example,DC=test"]
        );
        server.await.unwrap();
    }

    fn test_challenge() -> Vec<u8> {
        let target_info = [0_u8; 4];
        let mut challenge = Vec::with_capacity(60);
        challenge.extend_from_slice(b"NTLMSSP\0");
        challenge.extend_from_slice(&2_u32.to_le_bytes());
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&crate::ntlm::NEGOTIATE_FLAGS.to_le_bytes());
        challenge.extend_from_slice(&[0x11; 8]);
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        challenge.extend_from_slice(&56_u32.to_le_bytes());
        challenge.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
        challenge.extend_from_slice(&target_info);
        challenge
    }

    async fn read_test_ber(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 2];
        stream.read_exact(&mut header).await.unwrap();
        let mut output = header.to_vec();
        let length = if header[1] < 0x80 {
            usize::from(header[1])
        } else {
            let count = usize::from(header[1] & 0x7f);
            let mut length_bytes = vec![0; count];
            stream.read_exact(&mut length_bytes).await.unwrap();
            output.extend_from_slice(&length_bytes);
            length_bytes
                .into_iter()
                .fold(0_usize, |value, byte| value * 256 + usize::from(byte))
        };
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        output.extend_from_slice(&body);
        output
    }

    async fn write_test_message(stream: &mut TcpStream, message: LdapMessage) {
        let encoded = rasn::ber::encode(&message).unwrap();
        stream.write_all(&encoded).await.unwrap();
    }

    async fn read_test_protected(
        stream: &mut TcpStream,
        context: &mut NtlmSecurityContext,
    ) -> Vec<u8> {
        let mut length = [0; 4];
        stream.read_exact(&mut length).await.unwrap();
        let mut protected = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut protected).await.unwrap();
        context.unwrap(&protected).unwrap()
    }

    async fn write_test_protected(
        stream: &mut TcpStream,
        context: &mut NtlmSecurityContext,
        message: LdapMessage,
    ) {
        let encoded = rasn::ber::encode(&message).unwrap();
        let protected = context.wrap(&encoded).unwrap();
        stream
            .write_all(&(protected.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&protected).await.unwrap();
    }
}
