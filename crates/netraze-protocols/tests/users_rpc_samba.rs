//! Phase B.3 — Live integration test for [`users::enum_users`] against the
//! Samba container in `tests/samba/`.
//!
//! Validates the full SAMR pipeline:
//!
//! ```text
//! Smb2Session::connect_with_password
//!   -> tree_connect IPC$
//!   -> SmbPipeTransport::open(samr)
//!   -> RpcChannel::bind_authenticated (NTLMSSP PKT_PRIVACY)
//!   -> SamrConnect2 -> SamrEnumerateDomainsInSamServer
//!   -> SamrLookupDomain -> SamrOpenDomain
//!   -> SamrEnumerateUsersInDomain (loop resume)
//!   -> SamrCloseHandle x2
//! ```
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test users_rpc_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::connection::SmbCredential;

const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "wonderland";
const TEST_DOMAIN: &str = "NETRAZE";

fn samba_addr() -> String {
    std::env::var("NETRAZE_SAMBA_ADDR").unwrap_or_else(|_| DEFAULT_SAMBA_ADDR.to_owned())
}

fn samba_reachable() -> bool {
    let addr = samba_addr();
    let sock = addr.parse::<std::net::SocketAddr>().ok().or_else(|| {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs().ok().and_then(|mut i| i.next())
    });
    match sock {
        Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn users_rpc_lists_samba_users() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md.",
            samba_addr()
        );
    }

    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let users = netraze_protocols::smb::users::enum_users(&samba_addr(), &cred)
        .await
        .expect("enum_users against live Samba");

    // Samba container is configured with at least 'alice'.
    let names: Vec<String> = users.iter().map(|u| u.name.to_lowercase()).collect();
    assert!(
        names.contains(&"alice".to_string()),
        "expected 'alice' in user list, got: {names:?}"
    );

    // v1 fields are defaulted since we don't call SamrQueryInformationUser.
    let alice = users
        .iter()
        .find(|u| u.name.eq_ignore_ascii_case("alice"))
        .unwrap();
    assert_eq!(alice.privilege_level, 0);
    assert_eq!(alice.disabled, false);
    assert_eq!(alice.locked, false);
}
