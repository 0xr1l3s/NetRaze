//! LDAP-first user enumeration with SAMR fallback.

use core::future::Future;

use crate::ldap::{LdapClient, LdapClientConfig};
use crate::ntlm::NtlmCredential;
use crate::smb::connection::SmbCredential;
use netraze_core::UserInfo;

/// Enumerate users through LDAP when secret-bearing credentials are available,
/// falling back to the existing SAMR implementation on LDAP failure.
pub async fn enum_users(target: &str, credential: &SmbCredential) -> Result<Vec<UserInfo>, String> {
    let ldap_endpoint = ldap_endpoint(target);
    dispatch(
        credential,
        |ntlm_credential| async {
            let config = LdapClientConfig::new(ldap_endpoint);
            let mut client = LdapClient::connect(config)
                .await
                .map_err(|error| error.to_string())?;
            if let Err(error) = client
                .bind_ntlm(&credential.username, &credential.domain, ntlm_credential)
                .await
            {
                let _ = client.unbind().await;
                return Err(error.to_string());
            }
            let users = client
                .enumerate_ad_users()
                .await
                .map_err(|error| error.to_string());
            let _ = client.unbind().await;
            users
        },
        || crate::smb::users::enum_users(target, credential),
    )
    .await
}

async fn dispatch<L, LFuture, S, SFuture>(
    credential: &SmbCredential,
    ldap: L,
    samr: S,
) -> Result<Vec<UserInfo>, String>
where
    L: FnOnce(NtlmCredential) -> LFuture,
    LFuture: Future<Output = Result<Vec<UserInfo>, String>>,
    S: FnOnce() -> SFuture,
    SFuture: Future<Output = Result<Vec<UserInfo>, String>>,
{
    let Some(ntlm_credential) = ldap_credential(credential) else {
        return samr().await;
    };
    match ldap(ntlm_credential).await {
        Ok(users) => Ok(users),
        Err(ldap_error) => {
            let ldap_error = sanitize_error(&ldap_error, credential);
            tracing::warn!(error = %ldap_error, "LDAP user enumeration failed; falling back to SAMR");
            match samr().await {
                Ok(users) => Ok(users),
                Err(samr_error) => Err(format!(
                    "LDAP user enumeration failed ({ldap_error}); SAMR fallback failed ({samr_error})"
                )),
            }
        }
    }
}

fn ldap_credential(credential: &SmbCredential) -> Option<NtlmCredential> {
    if credential.username.is_empty() {
        return None;
    }
    if let Some(hash) = credential.nt_hash {
        return Some(NtlmCredential::NtHash(hash));
    }
    (!credential.password.is_empty()).then(|| NtlmCredential::Password(credential.password.clone()))
}

fn ldap_endpoint(target: &str) -> String {
    if let Some(close) = target.find(']').filter(|_| target.starts_with('[')) {
        return format!("{}:389", &target[..=close]);
    }
    if target.matches(':').count() > 1 {
        return format!("[{target}]:389");
    }
    let host = target
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(target, |(host, _)| host);
    format!("{host}:389")
}

fn sanitize_error(error: &str, credential: &SmbCredential) -> String {
    let mut sanitized = error.to_owned();
    if !credential.password.is_empty() {
        sanitized = sanitized.replace(&credential.password, "<redacted>");
    }
    if let Some(hash) = credential.nt_hash {
        let hex = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        sanitized = sanitized.replace(&hex, "<redacted>");
        sanitized = sanitized.replace(&hex.to_uppercase(), "<redacted>");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use netraze_core::UserEnumerationSource;

    use super::*;

    #[tokio::test]
    async fn password_credentials_prefer_ldap_and_zero_users_is_success() {
        let samr_calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&samr_calls);
        let result = dispatch(
            &SmbCredential::new("alice", "EXAMPLE", "secret"),
            |_| async { Ok(Vec::new()) },
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Err("must not run".into()) }
            },
        )
        .await
        .unwrap();
        assert!(result.is_empty());
        assert_eq!(samr_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn anonymous_and_guest_credentials_go_directly_to_samr() {
        for credential in [
            SmbCredential::new("", "", ""),
            SmbCredential::new("guest", "", ""),
        ] {
            let ldap_calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&ldap_calls);
            let users = dispatch(
                &credential,
                move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { Err("must not run".into()) }
                },
                || async { Ok(vec![user("samr", UserEnumerationSource::Samr)]) },
            )
            .await
            .unwrap();
            assert_eq!(users[0].source, UserEnumerationSource::Samr);
            assert_eq!(ldap_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn ldap_failure_falls_back_and_combines_errors_without_secrets() {
        let credential = SmbCredential::new("alice", "EXAMPLE", "very-secret");
        let users = dispatch(
            &credential,
            |_| async { Err("bind rejected very-secret".into()) },
            || async { Ok(vec![user("samr", UserEnumerationSource::Samr)]) },
        )
        .await
        .unwrap();
        assert_eq!(users[0].source, UserEnumerationSource::Samr);

        let error = dispatch(
            &credential,
            |_| async { Err("bind rejected very-secret".into()) },
            || async { Err("access denied".into()) },
        )
        .await
        .unwrap_err();
        assert!(error.contains("<redacted>"));
        assert!(!error.contains("very-secret"));
        assert!(error.contains("access denied"));
    }

    #[test]
    fn derives_ldap_port_without_reusing_an_smb_override() {
        assert_eq!(ldap_endpoint("dc.example.test"), "dc.example.test:389");
        assert_eq!(ldap_endpoint("10.0.0.1:1445"), "10.0.0.1:389");
        assert_eq!(ldap_endpoint("[::1]:1445"), "[::1]:389");
        assert_eq!(ldap_endpoint("::1"), "[::1]:389");
    }

    fn user(name: &str, source: UserEnumerationSource) -> UserInfo {
        UserInfo {
            name: name.into(),
            privilege_level: 1,
            flags: 0,
            disabled: false,
            locked: false,
            source,
        }
    }
}
