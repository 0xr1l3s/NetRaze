//! Phase E — Live wire smoke for the portable smbexec backend against the
//! Samba container in `tests/samba/`.
//!
//! Samba has no real SCM, so actual command execution can't be exercised
//! here — that needs an authorized Windows target with admin credentials
//! (user-driven, see Plan.md). What this test pins is everything up to the
//! SCM boundary: session setup, IPC$ tree connect, `\PIPE\svcctl` open and
//! the NTLMSSP bind, plus the guarantee that whatever the server answers
//! surfaces as a readable error with a full trace instead of a panic or a
//! hang.
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test exec_samba -- --ignored
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::exec;

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

/// The whole smbexec chain must complete (or fail) within this bound — the
/// 120 s ADMIN$ poll loop only runs if service creation somehow succeeded,
/// which can't happen on Samba.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Session → IPC$ → svcctl bind; no panic, no hang, readable errors.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn exec_samba_fails_cleanly_without_scm() {
    assert!(
        samba_reachable(),
        "Samba container not running — see tests/samba/README.md"
    );
    let addr = samba_addr();
    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);

    // Shared trace buffer so we can dump what happened even if the call
    // times out (the future is dropped on timeout — the trace it returned
    // would be lost).
    let live_trace: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let log_buf = live_trace.clone();
    let logger = move |line: &str| {
        if let Ok(mut buf) = log_buf.lock() {
            buf.push(line.to_owned());
        }
    };

    let (result, trace) = match tokio::time::timeout(
        SMOKE_TIMEOUT,
        exec::execute_command_live(&addr, Some(&cred), "echo netraze-smoke", &logger),
    )
    .await
    {
        Ok(out) => out,
        Err(_) => {
            let dump = live_trace
                .lock()
                .map(|b| trace_dump(&b))
                .unwrap_or_default();
            panic!(
                "execute_command_live did not finish within {}s — trace so far:\n{}",
                SMOKE_TIMEOUT.as_secs(),
                dump
            );
        }
    };

    // The trace always starts with the exec banner and logs every step it
    // got through before the server said no.
    assert!(
        trace
            .first()
            .map(|l| l.starts_with("exec start"))
            .unwrap_or(false),
        "trace must start with the exec banner, got: {}",
        trace_dump(&trace)
    );

    match result {
        Err(e) => {
            // Expected on Samba: the chain stops at the svcctl pipe / SCM
            // boundary with a readable error, never an empty one.
            assert!(!e.is_empty(), "error message must be populated");
            // The failure must happen before the poll loop — Samba has no
            // SCM, so reaching the poll phase would mean we somehow created
            // a service, which this harness cannot do.
            assert!(
                !trace.iter().any(|l| l.starts_with("poll#")),
                "poll loop must not run on Samba — trace:\n{}",
                trace_dump(&trace)
            );
        }
        Ok(output) => {
            // Samba cannot execute anything; a success here would mean the
            // chain silently did nothing. Allow only an empty output with a
            // trace that explains itself.
            assert!(
                output.is_empty(),
                "unexpected command output from Samba: {output}"
            );
        }
    }
}

fn trace_dump(trace: &[String]) -> String {
    if trace.is_empty() {
        "<empty trace>".to_owned()
    } else {
        trace.join("\n")
    }
}
