//! Phase D — Live integration test for [`browser`] file operations against
//! the Samba container in `tests/samba/`.
//!
//! Exercises the full SMB2 file pipeline end-to-end on the writable
//! `private` share (alice, `read only = no`):
//!
//! ```text
//! Smb2Session::connect_with_password
//!   → tree_connect private → CREATE/WRITE/READ/QUERY_DIRECTORY/SET_INFO
//! ```
//!
//! Every artifact lives under a random `__netraze_test_<prefix>_<hex>__`
//! name so parallel runs can't collide, and every test cleans up after
//! itself so the tmpfs share stays pristine.
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test browser_ops_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::browser;
use netraze_protocols::smb::connection::SmbCredential;

const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "wonderland";
const TEST_DOMAIN: &str = "NETRAZE";
/// Writable share pinned in `tests/samba/smb.conf` (alice, `read only = no`).
const WRITABLE_SHARE: &str = "private";

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

fn cred() -> SmbCredential {
    SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
}

fn require_samba() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md.",
            samba_addr()
        );
    }
}

/// mkdir → listed as a dir → rmdir → gone.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn browser_ops_directory_lifecycle() {
    require_samba();
    let addr = samba_addr();
    let cred = cred();
    let dir = browser::__test_leaf("dir");

    // Not there yet.
    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, "")
        .await
        .expect("list share root");
    assert!(
        !listing.iter().any(|e| e.name == dir),
        "test dir {dir} should not pre-exist"
    );

    // Create → visible as a directory.
    browser::create_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect("create_directory");
    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, "")
        .await
        .expect("list after mkdir");
    let entry = listing
        .iter()
        .find(|e| e.name == dir)
        .expect("created dir must be listed");
    assert!(entry.is_dir, "created entry must be a directory");

    // Delete → gone.
    browser::delete_remote_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect("delete_remote_directory");
    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, "")
        .await
        .expect("list after rmdir");
    assert!(
        !listing.iter().any(|e| e.name == dir),
        "deleted dir must be gone"
    );
}

/// upload → listed with the right size → download → byte-identical →
/// delete file → gone. Payload is non-ASCII to prove byte fidelity
/// end-to-end (UTF-8 on the local side, opaque bytes over the wire).
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn browser_ops_upload_download_round_trip() {
    require_samba();
    let addr = samba_addr();
    let cred = cred();
    let name = browser::__test_leaf("file");

    // Local source file with a non-ASCII payload.
    let payload: Vec<u8> = "Zählerstände: π ≈ 3.14159 — \u{1F9EA}\n"
        .repeat(37)
        .into_bytes();
    let local_src = std::env::temp_dir().join(format!("{name}.src"));
    std::fs::write(&local_src, &payload).expect("write local source");

    // Upload → listed with correct size.
    browser::upload_file(
        &addr,
        &cred,
        WRITABLE_SHARE,
        &name,
        local_src.to_str().unwrap(),
    )
    .await
    .expect("upload_file");
    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, "")
        .await
        .expect("list after upload");
    let entry = listing
        .iter()
        .find(|e| e.name == name)
        .expect("uploaded file must be listed");
    assert!(!entry.is_dir);
    assert_eq!(entry.size, payload.len() as u64, "size must round-trip");

    // Download → byte-identical.
    let local_dst = std::env::temp_dir().join(format!("{name}.dst"));
    browser::download_file(
        &addr,
        &cred,
        WRITABLE_SHARE,
        &name,
        local_dst.to_str().unwrap(),
    )
    .await
    .expect("download_file");
    let downloaded = std::fs::read(&local_dst).expect("read downloaded file");
    assert_eq!(downloaded, payload, "downloaded bytes must match upload");

    // Delete file → gone. Clean up local artifacts regardless.
    let deleted = browser::delete_remote_file(&addr, &cred, WRITABLE_SHARE, &name).await;
    let _ = std::fs::remove_file(&local_src);
    let _ = std::fs::remove_file(&local_dst);
    deleted.expect("delete_remote_file");
    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, "")
        .await
        .expect("list after delete");
    assert!(
        !listing.iter().any(|e| e.name == name),
        "deleted file must be gone"
    );
}

/// Negatives: a listing of a non-existent path errors, and a double mkdir
/// surfaces a readable NAME_COLLISION message (parity with the Windows
/// `CreateDirectoryW` ERROR_ALREADY_EXISTS behavior the old backend
/// surfaced).
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn browser_ops_negative_paths() {
    require_samba();
    let addr = samba_addr();
    let cred = cred();
    let dir = browser::__test_leaf("neg");

    // Listing a non-existent directory must fail (not silently return
    // empty — the desktop navigates on this signal).
    let missing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect_err("listing a missing dir must error");
    assert!(
        !missing.is_empty(),
        "error message must be populated, got empty"
    );

    // mkdir twice: first ok, second a readable collision error.
    browser::create_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect("first mkdir");
    let collision = browser::create_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect_err("second mkdir must fail");
    assert!(
        collision.contains("NAME_COLLISION"),
        "collision error must be readable, got: {collision}"
    );

    // Cleanup.
    browser::delete_remote_directory(&addr, &cred, WRITABLE_SHARE, &dir)
        .await
        .expect("cleanup rmdir");
}

/// Listing order: directories first, then case-insensitive alphabetical —
/// the Windows `FindFirstFileW` backend's ordering, which the desktop tree
/// rendering depends on.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn browser_ops_listing_order_dirs_first_case_insensitive() {
    require_samba();
    let addr = samba_addr();
    let cred = cred();
    let root = browser::__test_leaf("order");

    browser::create_directory(&addr, &cred, WRITABLE_SHARE, &root)
        .await
        .expect("mkdir root");
    for d in ["beta", "Alpha"] {
        browser::create_directory(&addr, &cred, WRITABLE_SHARE, &format!("{root}\\{d}"))
            .await
            .expect("mkdir sub");
    }
    for f in ["zeta.txt", "CHARLIE.txt", "mike.txt"] {
        let src = std::env::temp_dir().join(format!("{}_{f}", browser::__test_leaf("lf")));
        std::fs::write(&src, b"x").expect("write local");
        browser::upload_file(
            &addr,
            &cred,
            WRITABLE_SHARE,
            &format!("{root}\\{f}"),
            src.to_str().unwrap(),
        )
        .await
        .expect("upload");
        let _ = std::fs::remove_file(&src);
    }

    let listing = browser::list_directory(&addr, &cred, WRITABLE_SHARE, &root)
        .await
        .expect("list");
    let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["Alpha", "beta", "CHARLIE.txt", "mike.txt", "zeta.txt"],
        "dirs first, case-insensitive alphabetical within each group"
    );

    // Cleanup (children first — dirs are deleted empty-only).
    for f in ["zeta.txt", "CHARLIE.txt", "mike.txt"] {
        browser::delete_remote_file(&addr, &cred, WRITABLE_SHARE, &format!("{root}\\{f}"))
            .await
            .expect("cleanup file");
    }
    for d in ["beta", "Alpha"] {
        browser::delete_remote_directory(&addr, &cred, WRITABLE_SHARE, &format!("{root}\\{d}"))
            .await
            .expect("cleanup dir");
    }
    browser::delete_remote_directory(&addr, &cred, WRITABLE_SHARE, &root)
        .await
        .expect("cleanup root");
}

/// Read-only share-root listing against an arbitrary live host (e.g. a real
/// Windows box). Unlike the tests above there is no Samba harness and no
/// writable-share assumption — this is the interop probe for Windows-only
/// server strictness (e.g. CREATE NameOffset validation on the share root).
///
/// Everything comes from env vars so no host or credential ever lands in the
/// repo; the test self-skips unless ALL of these are set:
///
/// ```text
/// NETRAZE_LIVE_HOST   host[:port] (default port 445)
/// NETRAZE_LIVE_SHARE  share name to list
/// NETRAZE_LIVE_USER   username
/// NETRAZE_LIVE_PASS   password
/// NETRAZE_LIVE_DOMAIN optional domain / workgroup
/// ```
///
/// ```shell
/// NETRAZE_LIVE_HOST=... NETRAZE_LIVE_SHARE=... NETRAZE_LIVE_USER=... \
/// NETRAZE_LIVE_PASS=... cargo test -p netraze-protocols --test \
///     browser_ops_samba browser_ops_live_host -- --ignored
/// ```
#[tokio::test]
#[ignore = "requires a live host via NETRAZE_LIVE_* env vars (read-only listing)"]
async fn browser_ops_live_host_lists_share_root() {
    let host = std::env::var("NETRAZE_LIVE_HOST").ok();
    let share = std::env::var("NETRAZE_LIVE_SHARE").ok();
    let user = std::env::var("NETRAZE_LIVE_USER").ok();
    let pass = std::env::var("NETRAZE_LIVE_PASS").ok();
    if host.is_none() || share.is_none() || user.is_none() || pass.is_none() {
        // No live host configured — this is the normal case for the Samba
        // suite run, so skip silently (the Samba tests above already cover
        // the harness scenario).
        return;
    }
    let host = host.unwrap();
    let share = share.unwrap();
    let domain = std::env::var("NETRAZE_LIVE_DOMAIN").unwrap_or_default();
    let cred = SmbCredential::new(&user.unwrap(), &domain, &pass.unwrap());

    // Share root (empty rel_path) — the exact case that Windows rejects with
    // STATUS_INVALID_PARAMETER when CREATE NameOffset is 0.
    let root = browser::list_directory(&host, &cred, &share, "")
        .await
        .expect("list share root on live host");
    for e in &root {
        assert!(!e.name.is_empty(), "entry names must be non-empty");
        assert_ne!(e.name, ".", "dot entries must be filtered");
        assert_ne!(e.name, "..", "dot entries must be filtered");
    }

    // If the root has a subdirectory, navigate one level in to prove
    // non-empty rel_path listing works too.
    if let Some(dir) = root.iter().find(|e| e.is_dir) {
        browser::list_directory(&host, &cred, &share, &dir.name)
            .await
            .expect("list subdirectory on live host");
    }
}
