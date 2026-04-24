//! Remote command execution over SMB (smbexec-style via SCM).
//!
//! This module is currently *instrumented for diagnostics*: every significant
//! step appends a line to an internal trace that is returned to the caller.
//! External / Win32-service-hosted children (`whoami`, `ipconfig`, ...) return
//! 0 bytes on some hosts while cmd builtins work; the trace is here to tell us
//! exactly where the chain breaks.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows::Win32::Storage::FileSystem::DeleteFileW;
use windows::Win32::System::Services::*;
use windows::core::PCWSTR;

use super::connection;
use super::smb2::{Smb2Session, SmbReadError};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn gen_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", ts)
}

/// Map a well-known Win32 error code to a symbolic name (best-effort).
fn win32_name(code: i32) -> &'static str {
    match code {
        2 => "ERROR_FILE_NOT_FOUND",
        3 => "ERROR_PATH_NOT_FOUND",
        5 => "ERROR_ACCESS_DENIED",
        32 => "ERROR_SHARING_VIOLATION",
        33 => "ERROR_LOCK_VIOLATION",
        53 => "ERROR_BAD_NETDEV",
        64 => "ERROR_NETNAME_DELETED",
        67 => "ERROR_BAD_NET_NAME",
        225 => "ERROR_VIRUS_INFECTED",
        231 => "ERROR_PIPE_BUSY",
        1326 => "ERROR_LOGON_FAILURE",
        _ => "?",
    }
}

fn io_err_summary(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{} (os_err={} {})", e, code, win32_name(code)),
        None => format!("{} (no os_err)", e),
    }
}

/// Open the SCM + service and query current state. Returns a short tag like
/// `RUNNING`, `START_PENDING`, `STOPPED`, or `err`. Never blocks long.
fn query_service_state(target: &str, svc_name: &str) -> &'static str {
    let target_w = wide(&format!("\\\\{target}"));
    let svc_name_w = wide(svc_name);
    unsafe {
        let scm = match OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CONNECT) {
            Ok(h) => h,
            Err(_) => return "scm_err",
        };
        let svc = match OpenServiceW(scm, PCWSTR(svc_name_w.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return "open_err";
            }
        };
        let mut status = SERVICE_STATUS::default();
        let q = QueryServiceStatus(svc, &mut status);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        if q.is_err() {
            return "query_err";
        }
        match status.dwCurrentState {
            SERVICE_STOPPED => "STOPPED",
            SERVICE_START_PENDING => "START_PENDING",
            SERVICE_STOP_PENDING => "STOP_PENDING",
            SERVICE_RUNNING => "RUNNING",
            SERVICE_CONTINUE_PENDING => "CONTINUE_PENDING",
            SERVICE_PAUSE_PENDING => "PAUSE_PENDING",
            SERVICE_PAUSED => "PAUSED",
            _ => "UNKNOWN",
        }
    }
}

/// Execute a single shell command on the target and return captured stdout+stderr.
/// Every significant step is pushed to `trace` AND streamed to `live_log` so
/// diagnostic output reaches the UI in real time even if the function hangs.
pub fn execute_command_live(
    target: &str,
    credential: Option<&connection::SmbCredential>,
    command: &str,
    live_log: &dyn Fn(&str),
) -> (Result<String, String>, Vec<String>) {
    let mut trace: Vec<String> = Vec::new();
    macro_rules! log {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            live_log(&line);
            eprintln!("[smb::exec] {line}");
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

    if let Err(e) = connection::connect_ipc(target, Some(cred)) {
        log!("connect_ipc FAILED: {e}");
        return (Err(format!("Session setup failed: {e}")), trace);
    }
    log!("connect_ipc OK");

    // Open a raw SMB2 session dedicated to reading the output file. This
    // bypasses the Windows SMB redirector's metadata cache (mup.sys) which
    // otherwise returns stale `size=0` for up to ~40s after the file is
    // written on the server. Mirrors impacket's `getFile` used by NetExec.
    let mut smb2 = match if let Some(h) = cred.nt_hash {
        Smb2Session::connect(target, &h, &cred.username, &cred.domain)
    } else {
        Smb2Session::connect_with_password(target, &cred.username, &cred.domain, &cred.password)
    } {
        Ok(s) => {
            log!("smb2 raw session OK");
            s
        }
        Err(e) => {
            log!("smb2 raw session FAILED: {e}");
            let _ = connection::disconnect_ipc(target);
            return (Err(format!("SMB2 session failed: {e}")), trace);
        }
    };

    let nonce = gen_nonce();
    let svc_name = format!("netraze_{nonce}");
    let out_name = format!("__out_{nonce}");
    let bat_name = format!("__run_{nonce}.bat");

    log!("nonce={nonce} svc={svc_name}");

    // NetExec-style binpath: we do NOT upload anything via SMB. The whole
    // batch-creation lives inline in the service binpath. When SCM spawns
    // cmd.exe with this line it:
    //   1. `echo <cmd> ^> \\%COMPUTERNAME%\ADMIN$\Temp\<out> 2^>^&1 > %TEMP%\<bat>`
    //      writes the literal text "<cmd> > \\...\out 2>&1" into a .bat file
    //      on the target (because the carets escape the redirection, making
    //      those chars part of the echoed text — only the final `> %TEMP%\...`
    //      is a real redirection applied by the outer cmd).
    //   2. `%COMSPEC% /Q /c %TEMP%\<bat>` runs that batch, which executes the
    //      user's command and redirects stdout+stderr to the UNC path.
    //   3. `%COMSPEC% /Q /c del %TEMP%\<bat>` cleans up.
    //
    // This is literally what `nxc ... -x` does via impacket's SCM RPC path
    // (see NetExec/nxc/protocols/smb/smbexec.py::execute_remote).
    let bin_path = format!(
        "%COMSPEC% /Q /c echo {command} ^> \\\\%COMPUTERNAME%\\ADMIN$\\Temp\\{out_name} 2^>^&1 \
         > %TEMP%\\{bat_name} & %COMSPEC% /Q /c %TEMP%\\{bat_name} & %COMSPEC% /Q /c del %TEMP%\\{bat_name}"
    );
    log!("bin_path={bin_path}");

    let target_w = wide(&format!("\\\\{target}"));
    let scm =
        match unsafe { OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CREATE_SERVICE) }
        {
            Ok(h) => {
                log!("OpenSCManager OK");
                h
            }
            Err(e) => {
                log!("OpenSCManager FAILED: {e}");
                return (Err(format!("OpenSCManager: {e}")), trace);
            }
        };

    let svc_name_w = wide(&svc_name);
    let bin_path_w = wide(&bin_path);

    let svc = unsafe {
        CreateServiceW(
            scm,
            PCWSTR(svc_name_w.as_ptr()),
            PCWSTR(svc_name_w.as_ptr()),
            SERVICE_ALL_ACCESS,
            ENUM_SERVICE_TYPE(SERVICE_WIN32_OWN_PROCESS.0),
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            PCWSTR(bin_path_w.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    let svc = match svc {
        Ok(h) => {
            log!("CreateService OK");
            h
        }
        Err(e) => {
            log!("CreateService FAILED: {e}");
            unsafe {
                let _ = CloseServiceHandle(scm);
            }
            return (Err(format!("CreateService failed: {e}")), trace);
        }
    };

    // 3. Fire StartServiceW on a detached thread so polling can begin
    //    immediately. StartServiceW blocks ~30s for fake services.
    let target_for_thread = target.to_string();
    let svc_name_for_thread = svc_name.clone();
    let (start_tx, start_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let target_w = wide(&format!("\\\\{target_for_thread}"));
        let svc_name_w = wide(&svc_name_for_thread);
        unsafe {
            match OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CONNECT) {
                Ok(scm2) => {
                    match OpenServiceW(scm2, PCWSTR(svc_name_w.as_ptr()), SERVICE_START) {
                        Ok(svc2) => {
                            let r = StartServiceW(svc2, None);
                            let _ = start_tx.send(match r {
                                Ok(_) => "StartService(thread) -> Ok".into(),
                                Err(e) => format!("StartService(thread) -> Err: {e}"),
                            });
                            let _ = CloseServiceHandle(svc2);
                        }
                        Err(e) => {
                            let _ = start_tx.send(format!("OpenService(thread) Err: {e}"));
                        }
                    }
                    let _ = CloseServiceHandle(scm2);
                }
                Err(e) => {
                    let _ = start_tx.send(format!("OpenSCManager(thread) Err: {e}"));
                }
            }
        }
    });
    log!("StartService dispatched on detached thread");

    // 4. Poll the output file. Trace every attempt so we can see whether the
    //    file appears, what size it reports, and how reads fail if they do.
    let deadline = Instant::now() + Duration::from_secs(120);
    let poll_start = Instant::now();
    let mut stable_bytes: Vec<u8> = Vec::new();
    let mut prev_len: Option<usize> = None;
    let mut saw_file = false;
    let mut saw_nonempty = false;
    let mut attempt = 0u32;
    let mut exit_reason = String::from("deadline");

    let rel_path = format!("Temp\\{out_name}");
    loop {
        if Instant::now() >= deadline {
            break;
        }
        attempt += 1;
        std::thread::sleep(Duration::from_millis(400));
        let elapsed_ms = poll_start.elapsed().as_millis();

        let state_str = query_service_state(target, &svc_name);

        // Fresh SMB2 CREATE → READ → CLOSE on every iteration. Each CREATE
        // goes to the server, so there's no local metadata cache interfering.
        match smb2.read_full_file(target, "ADMIN$", &rel_path) {
            Ok(bytes) => {
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
            Err(SmbReadError::NotFound) => {
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} not_found");
            }
            Err(SmbReadError::SharingViolation) => {
                saw_file = true;
                log!("poll#{attempt} t+{elapsed_ms}ms svc={state_str} sharing_violation");
            }
            Err(e) => {
                log!(
                    "poll#{attempt} t+{elapsed_ms}ms svc={state_str} smb2 ERR: {}",
                    e.as_str()
                );
            }
        }
    }

    log!(
        "poll exit: reason={exit_reason} saw_file={saw_file} saw_nonempty={saw_nonempty} \
         prev_len={:?} stable_bytes.len={}",
        prev_len,
        stable_bytes.len()
    );

    // Drain any pending thread message.
    while let Ok(msg) = start_rx.try_recv() {
        log!("{msg}");
    }

    // 5. Cleanup.
    let stop_res =
        unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut SERVICE_STATUS::default()) };
    log!("ControlService(STOP) -> {:?}", stop_res);
    let del_res = unsafe { DeleteService(svc) };
    log!("DeleteService -> {:?}", del_res);
    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    let unc_out = format!("\\\\{target}\\ADMIN$\\Temp\\{out_name}");
    let out_w = wide(&unc_out);
    let del_out = unsafe { DeleteFileW(PCWSTR(out_w.as_ptr())) };
    log!("DeleteFile(out) -> {:?}", del_out);
    // Batch file on target lived in %TEMP% — cmd.exe's chained `del` already
    // removed it; nothing to do here.

    if !stable_bytes.is_empty() {
        log!("returning {} bytes", stable_bytes.len());
        return (Ok(decode_output(&stable_bytes)), trace);
    }

    if !saw_file {
        return (
            Err("Command produced no output file on target. See trace.".into()),
            trace,
        );
    }

    // File appeared but we never captured non-empty stable content.
    log!("returning empty — file was seen but never had readable non-empty stable content");
    (Ok(String::new()), trace)
}

/// Backwards-compatible wrapper: returns just the command output or an error.
pub fn execute_command(
    target: &str,
    credential: Option<&connection::SmbCredential>,
    command: &str,
) -> Result<String, String> {
    execute_command_live(target, credential, command, &|_| {}).0
}

/// Convenience wrapper that collects the trace into a `Vec<String>` without
/// streaming — kept for callers that want the trace at the end.
pub fn execute_command_traced(
    target: &str,
    credential: Option<&connection::SmbCredential>,
    command: &str,
) -> (Result<String, String>, Vec<String>) {
    execute_command_live(target, credential, command, &|_| {})
}

/// cmd.exe on Windows emits text in the console's active codepage.
/// When stdout is redirected (our case), most tools write in the OEM codepage
/// (CP850 on Western-European Windows) regardless of `chcp`. We try UTF-8
/// first (handles ASCII and explicit UTF-8 output), then decode via
/// `MultiByteToWideChar(CP850)` which is the standard OEM page for FR/DE/ES.
fn decode_output(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    decode_codepage(bytes, 850).unwrap_or_else(|| bytes.iter().map(|&b| b as char).collect())
}

fn decode_codepage(bytes: &[u8], codepage: u32) -> Option<String> {
    use windows::Win32::Globalization::MultiByteToWideChar;
    if bytes.is_empty() {
        return Some(String::new());
    }
    unsafe {
        let needed = MultiByteToWideChar(codepage, Default::default(), bytes, None);
        if needed <= 0 {
            return None;
        }
        let mut buf = vec![0u16; needed as usize];
        let written = MultiByteToWideChar(codepage, Default::default(), bytes, Some(&mut buf));
        if written <= 0 {
            return None;
        }
        buf.truncate(written as usize);
        Some(String::from_utf16_lossy(&buf))
    }
}
