//! Bounded asynchronous LDAP transport and NTLM SASL bind.

use std::collections::BTreeMap;
use std::time::Duration;

use netraze_ntlm::{
    NegState, NtlmClient, NtlmCredential, NtlmSecurityContext, ntlm_mech_types_der,
    parse_neg_token_resp,
};
use rasn::types::OctetString;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::message::{
    AuthenticationChoice, BindRequest, BindResponse, LdapMessage, LdapString, ProtocolOp,
    ResultCode, SaslCredentials, UnbindRequest,
};

const DEFAULT_LDAP_PORT: u16 = 389;
const READ_CHUNK_SIZE: usize = 8 * 1024;

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

        let mut context = authenticate.security_context;
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
                    .verify(&ntlm_mech_types_der(), &mic)
                    .map_err(|error| LdapError::Ntlm(error.to_string()))?;
            }
        }
        self.security_context = Some(context);
        Ok(())
    }

    pub async fn root_dse(&mut self) -> Result<LdapEntry, LdapError> {
        Err(LdapError::State(
            "RootDSE search is initialized in the search phase".into(),
        ))
    }

    pub async fn search(
        &mut self,
        _base_dn: &str,
        _filter: &str,
        _attributes: &[&str],
    ) -> Result<SearchOutcome, LdapError> {
        Err(LdapError::State(
            "LDAP search is initialized in the search phase".into(),
        ))
    }

    /// Send RFC 4511 Unbind and close the stream. Unbind intentionally has no response.
    pub async fn unbind(&mut self) -> Result<(), LdapError> {
        if !self.usable {
            return Ok(());
        }
        let message_id = self.allocate_message_id();
        let message = LdapMessage::new(message_id, ProtocolOp::UnbindRequest(UnbindRequest));
        let operation_timeout = self.config.operation_timeout;
        let result = timeout(operation_timeout, self.send_message(&message))
            .await
            .map_err(|_| LdapError::Timeout)?;
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
            operation => Err(LdapError::UnexpectedOperation(format!("{operation:?}"))),
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
            self.security_context
                .as_mut()
                .expect("checked above")
                .unwrap(&protected)
                .map_err(|error| LdapError::Ntlm(error.to_string()))?
        } else {
            self.receive_ber_frame().await?
        };
        rasn::ber::decode(&encoded).map_err(|error| LdapError::Ber(error.to_string()))
    }

    async fn receive_ber_frame(&mut self) -> Result<Vec<u8>, LdapError> {
        loop {
            match ber_frame_length(&self.read_buffer, self.config.max_pdu_size)? {
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

    pub(crate) fn validate_message_id(&self, expected: u32, actual: u32) -> Result<(), LdapError> {
        if actual == 0 {
            return Err(LdapError::UnsolicitedNotification);
        }
        if actual != expected {
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
    use tokio::net::TcpListener;

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
                Some(OctetString::from(netraze_ntlm::wrap_spnego_resp(
                    &challenge,
                ))),
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

    fn test_challenge() -> Vec<u8> {
        let target_info = [0_u8; 4];
        let mut challenge = Vec::with_capacity(52);
        challenge.extend_from_slice(b"NTLMSSP\0");
        challenge.extend_from_slice(&2_u32.to_le_bytes());
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&netraze_ntlm::NEGOTIATE_FLAGS.to_le_bytes());
        challenge.extend_from_slice(&[0x11; 8]);
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        challenge.extend_from_slice(&48_u32.to_le_bytes());
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
}
