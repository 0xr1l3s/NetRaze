//! Stateful NTLMv2/SPNEGO client handshake.

use rand::RngCore;

use super::message::{
    NtlmCredential, NtlmError, build_authenticate_with_key, build_negotiate, compute_ntlmv2,
    parse_challenge,
};
use super::security::NtlmSecurityContext;
use super::spnego::{
    NegState, ntlm_mech_types_der, parse_neg_token_resp, wrap_spnego_init,
    wrap_spnego_resp_with_mic,
};

#[derive(Debug)]
pub struct NtlmAuthenticateResult {
    pub spnego_token: Vec<u8>,
    pub security_context: NtlmSecurityContext,
}

#[derive(Debug)]
pub struct NtlmClient {
    username: String,
    domain: String,
    credential: NtlmCredential,
    negotiate_message: Option<Vec<u8>>,
}

impl NtlmClient {
    #[must_use]
    pub fn new(
        username: impl Into<String>,
        domain: impl Into<String>,
        credential: NtlmCredential,
    ) -> Self {
        Self {
            username: username.into(),
            domain: domain.into(),
            credential,
            negotiate_message: None,
        }
    }

    pub fn negotiate_token(&mut self) -> Result<Vec<u8>, NtlmError> {
        if self.negotiate_message.is_some() {
            return Err(NtlmError::State("negotiate token already generated".into()));
        }
        let negotiate = build_negotiate();
        let token = wrap_spnego_init(&negotiate);
        self.negotiate_message = Some(negotiate);
        Ok(token)
    }

    pub fn authenticate_token(
        &mut self,
        server_spnego_token: &[u8],
    ) -> Result<NtlmAuthenticateResult, NtlmError> {
        let negotiate = self
            .negotiate_message
            .take()
            .ok_or_else(|| NtlmError::State("authenticate called before negotiate".into()))?;
        let response = parse_neg_token_resp(server_spnego_token)?;
        if response.state == Some(NegState::Reject) {
            return Err(NtlmError::State("SPNEGO negotiation rejected".into()));
        }
        let challenge_bytes = response
            .response_token
            .ok_or_else(|| NtlmError::Spnego("server omitted NTLM challenge".into()))?;
        let challenge = parse_challenge(&challenge_bytes)?;
        let auth = compute_ntlmv2(
            &self.credential.nt_hash()?,
            &self.username,
            &self.domain,
            &challenge,
        )?;
        let mut exported_session_key = [0; 16];
        rand::thread_rng().fill_bytes(&mut exported_session_key);
        let type_three = build_authenticate_with_key(
            &auth,
            &self.username,
            &self.domain,
            challenge.negotiate_flags,
            exported_session_key,
            Some((&negotiate, &challenge_bytes)),
        );
        let security_context = NtlmSecurityContext::new(exported_session_key);
        let mech_list_mic = security_context.sign_mech_list_mic(&ntlm_mech_types_der())?;
        Ok(NtlmAuthenticateResult {
            spnego_token: wrap_spnego_resp_with_mic(&type_three, Some(&mech_list_mic)),
            security_context,
        })
    }
}
