//! Stateful NTLM sign-and-seal context (MS-NLMP §3.4).

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

use crate::message::NtlmError;

type HmacMd5 = Hmac<Md5>;

const CLIENT_SIGNING: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGNING: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEALING: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEALING: &[u8] = b"session key to server-to-client sealing key magic constant\0";

#[derive(Clone)]
pub(crate) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty() && key.len() <= 256, "valid RC4 key length");
        let mut state = core::array::from_fn(|index| index as u8);
        let mut j = 0_u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        Self { state, i: 0, j: 0 }
    }

    pub(crate) fn transform(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let index =
                self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
            *byte ^= self.state[usize::from(index)];
        }
    }
}

/// One NTLM connection's independent client-to-server and server-to-client state.
#[derive(Clone)]
pub struct NtlmSecurityContext {
    send_signing_key: [u8; 16],
    receive_signing_key: [u8; 16],
    send_sealing: Rc4,
    receive_sealing: Rc4,
    send_sequence: u32,
    receive_sequence: u32,
}

impl core::fmt::Debug for NtlmSecurityContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NtlmSecurityContext")
            .field("send_sequence", &self.send_sequence)
            .field("receive_sequence", &self.receive_sequence)
            .finish_non_exhaustive()
    }
}

impl NtlmSecurityContext {
    #[must_use]
    pub fn new(exported_session_key: [u8; 16]) -> Self {
        Self::with_role(exported_session_key, false)
    }

    /// Construct the peer orientation; useful for protocol tests and mock servers.
    #[must_use]
    pub fn new_server(exported_session_key: [u8; 16]) -> Self {
        Self::with_role(exported_session_key, true)
    }

    fn with_role(key: [u8; 16], server: bool) -> Self {
        let client_signing = derive_key(&key, CLIENT_SIGNING);
        let server_signing = derive_key(&key, SERVER_SIGNING);
        let client_sealing = derive_key(&key, CLIENT_SEALING);
        let server_sealing = derive_key(&key, SERVER_SEALING);
        if server {
            Self {
                send_signing_key: server_signing,
                receive_signing_key: client_signing,
                send_sealing: Rc4::new(&server_sealing),
                receive_sealing: Rc4::new(&client_sealing),
                send_sequence: 0,
                receive_sequence: 0,
            }
        } else {
            Self {
                send_signing_key: client_signing,
                receive_signing_key: server_signing,
                send_sealing: Rc4::new(&client_sealing),
                receive_sealing: Rc4::new(&server_sealing),
                send_sequence: 0,
                receive_sequence: 0,
            }
        }
    }

    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NtlmError> {
        let sequence = self.send_sequence;
        let checksum = checksum(&self.send_signing_key, sequence, plaintext)?;
        let mut sealed = plaintext.to_vec();
        self.send_sealing.transform(&mut sealed);
        let mut encrypted_checksum = checksum;
        self.send_sealing.transform(&mut encrypted_checksum);
        self.send_sequence = self.send_sequence.wrapping_add(1);

        let mut output = Vec::with_capacity(16 + sealed.len());
        output.extend_from_slice(&1_u32.to_le_bytes());
        output.extend_from_slice(&encrypted_checksum);
        output.extend_from_slice(&sequence.to_le_bytes());
        output.extend_from_slice(&sealed);
        Ok(output)
    }

    pub fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, NtlmError> {
        if token.len() < 16 {
            return Err(NtlmError::TooShort(token.len()));
        }
        if token[..4] != 1_u32.to_le_bytes() {
            return Err(NtlmError::BadSignature);
        }
        let sequence = u32::from_le_bytes(token[12..16].try_into().expect("length checked"));
        if sequence != self.receive_sequence {
            return Err(NtlmError::Integrity);
        }
        let mut trial = self.receive_sealing.clone();
        let mut plaintext = token[16..].to_vec();
        trial.transform(&mut plaintext);
        let mut actual = <[u8; 8]>::try_from(&token[4..12]).expect("length checked");
        trial.transform(&mut actual);
        let expected = checksum(&self.receive_signing_key, sequence, &plaintext)?;
        if !constant_time_eq(&actual, &expected) {
            return Err(NtlmError::Integrity);
        }
        self.receive_sealing = trial;
        self.receive_sequence = self.receive_sequence.wrapping_add(1);
        Ok(plaintext)
    }

    /// Produce the NTLM MIC token used by SPNEGO's `mechListMIC` field.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, NtlmError> {
        let sequence = self.send_sequence;
        let mut digest = checksum(&self.send_signing_key, sequence, message)?;
        self.send_sealing.transform(&mut digest);
        self.send_sequence = self.send_sequence.wrapping_add(1);
        let mut signature = Vec::with_capacity(16);
        signature.extend_from_slice(&1_u32.to_le_bytes());
        signature.extend_from_slice(&digest);
        signature.extend_from_slice(&sequence.to_le_bytes());
        Ok(signature)
    }

    /// Sign a SPNEGO mechanism list without consuming application RC4 state.
    pub fn sign_mech_list_mic(&self, message: &[u8]) -> Result<Vec<u8>, NtlmError> {
        let mut snapshot = self.clone();
        snapshot.sign(message)
    }

    pub fn verify(&mut self, message: &[u8], signature: &[u8]) -> Result<(), NtlmError> {
        if signature.len() != 16 || signature[..4] != 1_u32.to_le_bytes() {
            return Err(NtlmError::BadSignature);
        }
        let sequence = u32::from_le_bytes(signature[12..16].try_into().expect("length checked"));
        if sequence != self.receive_sequence {
            return Err(NtlmError::Integrity);
        }
        let mut trial = self.receive_sealing.clone();
        let mut actual = <[u8; 8]>::try_from(&signature[4..12]).expect("length checked");
        trial.transform(&mut actual);
        let expected = checksum(&self.receive_signing_key, sequence, message)?;
        if !constant_time_eq(&actual, &expected) {
            return Err(NtlmError::Integrity);
        }
        self.receive_sealing = trial;
        self.receive_sequence = self.receive_sequence.wrapping_add(1);
        Ok(())
    }

    /// Verify a SPNEGO mechanism-list MIC without consuming application state.
    pub fn verify_mech_list_mic(&self, message: &[u8], signature: &[u8]) -> Result<(), NtlmError> {
        let mut snapshot = self.clone();
        snapshot.verify(message, signature)
    }

    #[must_use]
    pub const fn send_sequence(&self) -> u32 {
        self.send_sequence
    }

    #[must_use]
    pub const fn receive_sequence(&self) -> u32 {
        self.receive_sequence
    }
}

fn derive_key(session_key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(session_key);
    digest.update(magic);
    digest.finalize().into()
}

fn checksum(key: &[u8], sequence: u32, message: &[u8]) -> Result<[u8; 8], NtlmError> {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key)
        .map_err(|error| NtlmError::Crypto(error.to_string()))?;
    mac.update(&sequence.to_le_bytes());
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    Ok(digest[..8].try_into().expect("eight-byte slice"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-NLMP §4.2.4.4 sign-and-seal known-answer vector.
    #[test]
    fn sign_and_seal_matches_ms_nlmp_vector() {
        let mut context = NtlmSecurityContext::new([0x55; 16]);
        let plaintext = [
            0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x78, 0x00, 0x74, 0x00,
        ];
        let wrapped = context.wrap(&plaintext).unwrap();
        assert_eq!(
            &wrapped[..16],
            &[
                1, 0, 0, 0, 0x7f, 0xb3, 0x8e, 0xc5, 0xc5, 0x5d, 0x49, 0x76, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            &wrapped[16..],
            &[
                0x54, 0xe5, 0x01, 0x65, 0xbf, 0x19, 0x36, 0xdc, 0x99, 0x60, 0x20, 0xc1, 0x81, 0x1b,
                0x0f, 0x06, 0xfb, 0x5f
            ]
        );
    }

    #[test]
    fn mech_list_mic_does_not_advance_application_state() {
        let context = NtlmSecurityContext::new([0x55; 16]);
        let _ = context.sign_mech_list_mic(b"mechTypes").unwrap();
        assert_eq!(context.send_sequence(), 0);
        let mut after_mic = context;
        let mut fresh = NtlmSecurityContext::new([0x55; 16]);
        assert_eq!(
            after_mic.wrap(b"first").unwrap(),
            fresh.wrap(b"first").unwrap()
        );
    }
}
