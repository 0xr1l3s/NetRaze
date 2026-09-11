//! Minimal raw SMB2 client for pass-the-hash authentication.
//!
//! Implements just enough of the SMB2 protocol to:
//! 1. Negotiate dialect
//! 2. Session Setup with NTLMSSP (NTLMv2 from NT hash)
//! 3. Tree Connect (for admin check)

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::ntlm;

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB2_HEADER_SIZE: usize = 64;

const SMB2_NEGOTIATE: u16 = 0;
const SMB2_SESSION_SETUP: u16 = 1;
const SMB2_LOGOFF: u16 = 2;
const SMB2_TREE_CONNECT: u16 = 3;
const SMB2_TREE_DISCONNECT: u16 = 4;
const SMB2_CREATE: u16 = 5;
const SMB2_CLOSE: u16 = 6;
const SMB2_READ: u16 = 8;
const SMB2_WRITE: u16 = 9;
const SMB2_IOCTL: u16 = 11;
const SMB2_QUERY_DIRECTORY: u16 = 14; // 0x000E — 12 is CANCEL, which servers never answer
const SMB2_SET_INFO: u16 = 17; // 0x0011 — 15 is CHANGE_NOTIFY, which blocks until notified

/// MS-FSCC §2.3 — bidirectional named-pipe transceive. Carrier for DCE/RPC
/// PDUs over SMB2 (\PIPE\srvsvc, \PIPE\samr, \PIPE\svcctl, \PIPE\wkssvc).
/// This is the Phase 3 unblocker.
pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

/// MS-SMB2 §2.2.31 — IOCTL Request flag indicating the CtlCode is an FSCTL
/// (as opposed to a device-specific IOCTL code).
pub const SMB2_0_IOCTL_IS_FSCTL: u32 = 0x0000_0001;

/// DesiredAccess we ask for when opening a named pipe over IPC$:
/// FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA
/// | FILE_WRITE_EA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
/// | READ_CONTROL | SYNCHRONIZE — matches what Windows / Impacket request.
const PIPE_DESIRED_ACCESS: u32 = 0x0012_019F;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_PENDING: u32 = 0x00000103;
pub const STATUS_MORE_PROCESSING: u32 = 0xC0000016;
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC0000034;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000003A;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC0000043;
pub const STATUS_END_OF_FILE: u32 = 0xC0000011;
pub const STATUS_PIPE_DISCONNECTED: u32 = 0xC000_00B0;
pub const STATUS_PIPE_BROKEN: u32 = 0xC000_014B;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

// ── CreateDisposition values (MS-SMB2 §2.2.13 / MS-FSCC §2.4) ──
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE_IF: u32 = 5;

// ── CreateOptions values ──
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// ── DesiredAccess bits used by the file-op primitives below ──
/// FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
const FILE_READ_ACCESS_ALL: u32 = 0x0012_0089;
/// FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
const FILE_WRITE_ACCESS_BASIC: u32 = 0x0010_0102;
/// FILE_LIST_DIRECTORY | SYNCHRONIZE
const FILE_LIST_DIRECTORY_ACCESS: u32 = 0x0010_0001;
/// DELETE | SYNCHRONIZE
const FILE_DELETE_ACCESS: u32 = 0x0011_0000;

/// Error from a raw SMB2 file read.
#[derive(Debug, Clone)]
pub enum SmbReadError {
    NotFound,
    SharingViolation,
    NameCollision,
    DirectoryNotEmpty,
    AccessDenied,
    /// The server signalled the end of a directory enumeration. Only surfaced
    /// as an error by callers that expected at least one entry; the
    /// query-directory loop treats it as a normal terminator.
    NoMoreFiles,
    Other(u32, String),
}

impl SmbReadError {
    pub fn as_str(&self) -> String {
        match self {
            SmbReadError::NotFound => "NOT_FOUND".into(),
            SmbReadError::SharingViolation => "SHARING_VIOLATION".into(),
            SmbReadError::NameCollision => "NAME_COLLISION (already exists)".into(),
            SmbReadError::DirectoryNotEmpty => "DIRECTORY_NOT_EMPTY".into(),
            SmbReadError::AccessDenied => "ACCESS_DENIED".into(),
            SmbReadError::NoMoreFiles => "NO_MORE_FILES".into(),
            SmbReadError::Other(s, ctx) => format!("0x{s:08x} ({ctx})"),
        }
    }
}

/// Parameters for the shared SMB2 CREATE builder. Every hand-rolled CREATE in
/// this module (read, probe, pipe open, directory ops, delete-on-close)
/// funnels through [`build_create_body`] with one of these — the wire layout
/// is identical, only these four DWORDs differ.
#[derive(Debug, Clone, Copy)]
pub struct CreateParams {
    pub desired_access: u32,
    /// R|W|D (`0x07`) for everything except exclusive opens.
    pub share_access: u32,
    /// `FILE_OPEN` (1) / `FILE_CREATE` (2) / `FILE_OVERWRITE_IF` (5).
    pub disposition: u32,
    /// `FILE_DIRECTORY_FILE` (0x01) / `FILE_NON_DIRECTORY_FILE` (0x40) / 0.
    pub create_options: u32,
}

/// One entry from an SMB2 QUERY_DIRECTORY response
/// (FILE_BOTH_DIRECTORY_INFORMATION).
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Open handle on an SMB2 named pipe. Carries the IPC$ tree id and the
/// 16-byte pipe FileId — enough to drive `pipe_transceive` and `pipe_close`
/// with no further state. `Copy` because both fields are POD.
#[derive(Debug, Clone, Copy)]
pub struct PipeHandle {
    pub file_id: [u8; 16],
    pub tree_id: u32,
}

/// A minimal raw SMB2 session for pass-the-hash authentication.
pub struct Smb2Session {
    stream: TcpStream,
    session_id: u64,
    message_id: u64,
    /// NTLMv2 ExportedSessionKey captured during `session_setup`. Required by
    /// `RpcChannel::bind_authenticated` to derive the NTLMSSP seal/sign keys
    /// for DCE/RPC PKT_PRIVACY over the named-pipe transport. `None` until
    /// the handshake completes; cleared by `logoff`.
    session_key: Option<[u8; 16]>,
    /// Set from the server's Negotiate response SecurityMode bit
    /// `SMB2_NEGOTIATE_SIGNING_REQUIRED (0x0002)` — see [MS-SMB2 §2.2.4].
    /// Domain controllers always set it. When true, every post-session-setup
    /// request (`send_packet` with a live `session_key`) is signed per
    /// MS-SMB2 §3.2.5.1 — a signing-required server drops unsigned requests
    /// with STATUS_ACCESS_DENIED, which used to surface as a baffling
    /// "TreeConnect IPC$: ACCESS_DENIED" right after a successful login.
    signing_required: bool,
}

impl Smb2Session {
    /// Connect to `target` and authenticate using NT hash (pass-the-hash).
    ///
    /// `target` may be:
    /// - a bare host (`dc01.corp.lan`, `10.0.0.5`) — port 445 is assumed
    /// - a `host:port` string — used verbatim (required by the Samba
    ///   integration harness which binds the test container on 1445 so it
    ///   doesn't collide with the OS SMB client on dev machines)
    pub fn connect(
        target: &str,
        nt_hash: &[u8; 16],
        username: &str,
        domain: &str,
    ) -> Result<Self, String> {
        // One shared host:port normaliser (see `targets::with_default_port`)
        // — bare hosts get 445, `host:port` / `[ipv6]:port` are kept verbatim,
        // bare IPv6 literals get bracketed.
        let addr = crate::targets::with_default_port(target, 445);
        let sock_addr = addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolve failed: {e}"))?
            .next()
            .ok_or("No address resolved")?;

        let stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))
            .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let mut session = Smb2Session {
            stream,
            session_id: 0,
            message_id: 0,
            session_key: None,
            signing_required: false,
        };

        session.negotiate()?;
        session.session_setup(nt_hash, username, domain)?;

        Ok(session)
    }

    /// Connect using a password (computes NT hash via MD4).
    pub fn connect_with_password(
        target: &str,
        username: &str,
        domain: &str,
        password: &str,
    ) -> Result<Self, String> {
        let hash = super::ntlm::nt_hash_from_password(password)?;
        Self::connect(target, &hash, username, domain)
    }

    /// Open → Read all → Close a file on a share. Fresh CREATE on every call —
    /// no client-side metadata cache. Mirrors impacket's `getFile`.
    pub fn read_full_file(
        &mut self,
        target: &str,
        share: &str,
        rel_path: &str,
    ) -> Result<Vec<u8>, SmbReadError> {
        let tid = self
            .tree_connect(target, share)
            .map_err(|e| SmbReadError::Other(0, format!("tree_connect: {e}")))?;

        let (fid, eof) = match self.create_open_read(tid, rel_path) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.tree_disconnect(tid);
                return Err(e);
            }
        };

        let mut out = Vec::with_capacity(eof as usize);
        let mut offset: u64 = 0;
        while offset < eof {
            let remaining = (eof - offset).min(60 * 1024) as u32;
            match self.read_chunk(tid, &fid, offset, remaining) {
                Ok(chunk) => {
                    if chunk.is_empty() {
                        break;
                    }
                    offset += chunk.len() as u64;
                    out.extend_from_slice(&chunk);
                }
                Err(SmbReadError::Other(s, _)) if s == STATUS_END_OF_FILE => break,
                Err(e) => {
                    let _ = self.close_file(tid, &fid);
                    let _ = self.tree_disconnect(tid);
                    return Err(e);
                }
            }
        }

        let _ = self.close_file(tid, &fid);
        let _ = self.tree_disconnect(tid);
        Ok(out)
    }

    /// Create (or truncate) → Write all → Close a file on a share. The
    /// portable counterpart of `read_full_file`, used by the cross-platform
    /// share browser's upload path. Chunks at 60 KiB per WRITE to stay under
    /// every server's negotiated MaxWriteSize (Samba defaults ~1 MiB, Windows
    /// legacy redirectors capped at 64 KiB minus header overhead).
    pub fn write_full_file(
        &mut self,
        target: &str,
        share: &str,
        rel_path: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let tid = self
            .tree_connect(target, share)
            .map_err(|e| format!("tree_connect: {e}"))?;

        let (fid, _) = match self.create_open(
            tid,
            rel_path,
            &CreateParams {
                desired_access: FILE_WRITE_ACCESS_BASIC,
                share_access: 0x0000_0007, // R|W|D
                disposition: FILE_OVERWRITE_IF,
                create_options: FILE_NON_DIRECTORY_FILE,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.tree_disconnect(tid);
                return Err(e.as_str());
            }
        };

        let mut offset: u64 = 0;
        for chunk in data.chunks(60 * 1024) {
            if let Err(e) = self.write_chunk(tid, &fid, offset, chunk) {
                let _ = self.close_file(tid, &fid);
                let _ = self.tree_disconnect(tid);
                return Err(e);
            }
            offset += chunk.len() as u64;
        }

        let _ = self.close_file(tid, &fid);
        let _ = self.tree_disconnect(tid);
        Ok(())
    }

    /// List the entries of a directory on a share via SMB2 QUERY_DIRECTORY
    /// with `FILE_BOTH_DIRECTORY_INFORMATION` (MS-SMB2 §2.2.33 / §2.2.34).
    ///
    /// `rel_path` is the directory relative to the share root — `""` is the
    /// share root itself. `pattern` is the wildcard (`"*"` lists everything,
    /// `"*.txt"` filters server-side). `.` and `..` entries are dropped.
    /// Loops until the server returns `STATUS_NO_MORE_FILES`.
    pub fn query_directory(
        &mut self,
        target: &str,
        share: &str,
        rel_path: &str,
        pattern: &str,
    ) -> Result<Vec<DirEntry>, SmbReadError> {
        let tid = self
            .tree_connect(target, share)
            .map_err(|e| SmbReadError::Other(0, format!("tree_connect: {e}")))?;

        // Opening the directory itself (FILE_DIRECTORY_FILE, FILE_OPEN).
        let (fid, _) = match self.create_open(
            tid,
            rel_path,
            &CreateParams {
                desired_access: FILE_LIST_DIRECTORY_ACCESS,
                share_access: 0x0000_0007, // R|W|D — Windows refuses dir opens without it
                disposition: FILE_OPEN,
                create_options: FILE_DIRECTORY_FILE,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.tree_disconnect(tid);
                return Err(e);
            }
        };

        let mut entries = Vec::new();
        // First request carries SMB2_RESTART_SCANS so the server rewinds any
        // stale enumeration cursor; continuations must NOT set it (they'd
        // restart the scan forever).
        let mut restart = true;
        loop {
            let batch = self.query_directory_batch(tid, &fid, pattern, restart);
            restart = false;
            match batch {
                Ok(Some(mut batch)) => {
                    if batch.is_empty() {
                        // Defensive: a SUCCESS response with zero entries
                        // would loop forever otherwise.
                        break;
                    }
                    entries.append(&mut batch);
                }
                Ok(None) => break, // STATUS_NO_MORE_FILES — enumeration done
                Err(e) => {
                    let _ = self.close_file(tid, &fid);
                    let _ = self.tree_disconnect(tid);
                    return Err(e);
                }
            }
        }

        let _ = self.close_file(tid, &fid);
        let _ = self.tree_disconnect(tid);
        Ok(entries)
    }

    /// One QUERY_DIRECTORY round-trip. `Ok(None)` means the server answered
    /// `STATUS_NO_MORE_FILES` — a normal terminator, not an error.
    fn query_directory_batch(
        &mut self,
        tree_id: u32,
        file_id: &[u8; 16],
        pattern: &str,
        restart_scan: bool,
    ) -> Result<Option<Vec<DirEntry>>, SmbReadError> {
        let (body, pattern_utf16) = build_query_directory_body(file_id, pattern, restart_scan);
        let hdr = self.build_header(SMB2_QUERY_DIRECTORY, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + pattern_utf16.len().max(1));
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        if pattern_utf16.is_empty() {
            packet.push(0); // 1-byte dummy buffer — SMB2 forbids zero-length buffers
        } else {
            packet.extend_from_slice(&pattern_utf16);
        }

        self.send_packet(&packet)
            .map_err(|e| SmbReadError::Other(0, format!("send query_dir: {e}")))?;
        let resp = self
            .recv_packet()
            .map_err(|e| SmbReadError::Other(0, format!("recv query_dir: {e}")))?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status == STATUS_NO_MORE_FILES {
            return Ok(None);
        }
        if status != STATUS_SUCCESS {
            return Err(match status {
                STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => {
                    SmbReadError::NotFound
                }
                STATUS_ACCESS_DENIED => SmbReadError::AccessDenied,
                s => SmbReadError::Other(s, "query_dir".into()),
            });
        }

        let buffer =
            parse_query_directory_response(&resp).map_err(|e| SmbReadError::Other(0, e))?;
        let entries = parse_file_both_entries(&buffer)
            .map_err(|e| SmbReadError::Other(0, format!("query_dir buffer: {e}")))?;
        Ok(Some(entries))
    }

    /// Create a directory on a share (FILE_CREATE + FILE_DIRECTORY_FILE).
    /// Fails with `NameCollision` when the directory already exists.
    pub fn create_directory(
        &mut self,
        target: &str,
        share: &str,
        rel_path: &str,
    ) -> Result<(), String> {
        let tid = self
            .tree_connect(target, share)
            .map_err(|e| format!("tree_connect: {e}"))?;

        let result = self.create_open(
            tid,
            rel_path,
            &CreateParams {
                desired_access: FILE_LIST_DIRECTORY_ACCESS,
                share_access: 0x0000_0007,
                disposition: FILE_CREATE,
                create_options: FILE_DIRECTORY_FILE,
            },
        );
        if let Ok((fid, _)) = result {
            let _ = self.close_file(tid, &fid);
        }
        let _ = self.tree_disconnect(tid);

        match result {
            Ok(_) => Ok(()),
            Err(SmbReadError::NameCollision) => {
                Err("NAME_COLLISION: directory already exists".into())
            }
            Err(e) => Err(e.as_str()),
        }
    }

    /// Delete a file or an **empty** directory on a share via the
    /// DELETE_ON_CLOSE disposition: CREATE with `DELETE` access, SET_INFO
    /// `FileDispositionInformation(13) = TRUE`, then CLOSE — the deletion
    /// itself happens server-side when the handle closes. Non-empty
    /// directories fail with `DIRECTORY_NOT_EMPTY` (same contract as
    /// `DeleteFileW` / `RemoveDirectoryW`).
    pub fn delete_on_close(
        &mut self,
        target: &str,
        share: &str,
        rel_path: &str,
    ) -> Result<(), String> {
        let tid = self
            .tree_connect(target, share)
            .map_err(|e| format!("tree_connect: {e}"))?;

        // No FILE_NON_DIRECTORY_FILE: the path may be either a file or a dir.
        let (fid, _) = match self.create_open(
            tid,
            rel_path,
            &CreateParams {
                desired_access: FILE_DELETE_ACCESS,
                share_access: 0x0000_0007,
                disposition: FILE_OPEN,
                create_options: 0,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.tree_disconnect(tid);
                return Err(e.as_str());
            }
        };

        let set_result = self.set_delete_disposition(tid, &fid);
        let _ = self.close_file(tid, &fid);
        let _ = self.tree_disconnect(tid);

        match set_result {
            Ok(()) => Ok(()),
            Err(SmbReadError::DirectoryNotEmpty) => {
                Err("DIRECTORY_NOT_EMPTY: directory has entries".into())
            }
            Err(e) => Err(e.as_str()),
        }
    }

    /// SET_INFO `FileDispositionInformation = TRUE` on an open handle — arms
    /// the DELETE_ON_CLOSE disposition. The actual removal happens when the
    /// handle closes (the caller's responsibility).
    fn set_delete_disposition(
        &mut self,
        tree_id: u32,
        file_id: &[u8; 16],
    ) -> Result<(), SmbReadError> {
        let body = build_set_info_disposition_body(file_id);
        let hdr = self.build_header(SMB2_SET_INFO, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + 1);
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.push(0x01); // Buffer: BOOLEAN Delete = TRUE

        self.send_packet(&packet)
            .map_err(|e| SmbReadError::Other(0, format!("send set_info: {e}")))?;
        let resp = self
            .recv_packet()
            .map_err(|e| SmbReadError::Other(0, format!("recv set_info: {e}")))?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(match status {
                STATUS_ACCESS_DENIED => SmbReadError::AccessDenied,
                STATUS_DIRECTORY_NOT_EMPTY => SmbReadError::DirectoryNotEmpty,
                s => SmbReadError::Other(s, "set_info".into()),
            });
        }
        Ok(())
    }

    /// SMB2 WRITE: append `data` at `offset` on a *file* handle (the pipe
    /// variant lives in `pipe_write` — pipes ignore the offset).
    fn write_chunk(
        &mut self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        data: &[u8],
    ) -> Result<(), String> {
        let body = build_write_body(file_id, offset, data.len() as u32);
        let hdr = self.build_header(SMB2_WRITE, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + data.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(data);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(format!("write: 0x{status:08x}"));
        }
        Ok(())
    }

    /// SMB2 CREATE with caller-supplied parameters. Returns
    /// `(FileId, EndOfFile)` — the single funnel every open (read, write,
    /// probe, directory ops, delete-on-close) goes through.
    fn create_open(
        &mut self,
        tree_id: u32,
        rel_path: &str,
        params: &CreateParams,
    ) -> Result<([u8; 16], u64), SmbReadError> {
        let (body, name_utf16) = build_create_body(params, rel_path);
        let hdr = self.build_header(SMB2_CREATE, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + name_utf16.len().max(1));
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        if name_utf16.is_empty() {
            packet.push(0); // 1-byte dummy buffer — SMB2 forbids zero-length buffers
        } else {
            packet.extend_from_slice(&name_utf16);
        }

        self.send_packet(&packet)
            .map_err(|e| SmbReadError::Other(0, format!("send create: {e}")))?;
        let resp = self
            .recv_packet()
            .map_err(|e| SmbReadError::Other(0, format!("recv create: {e}")))?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(map_create_status(status));
        }

        if resp.len() < SMB2_HEADER_SIZE + 88 {
            return Err(SmbReadError::Other(0, "create resp too short".into()));
        }

        let body_off = SMB2_HEADER_SIZE;
        // EndOfFile at body offset 48 (8 bytes). AllocationSize is at 40 —
        // reading that returns 0 for small files since the allocation unit is
        // only materialised after a flush; we need the logical file size.
        let eof = u64::from_le_bytes(resp[body_off + 48..body_off + 56].try_into().unwrap());
        // FileId at body offset 64 (16 bytes: persistent+volatile)
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&resp[body_off + 64..body_off + 80]);
        Ok((fid, eof))
    }

    /// SMB2 CREATE: open file for read, return (FileId, EndOfFile).
    fn create_open_read(
        &mut self,
        tree_id: u32,
        rel_path: &str,
    ) -> Result<([u8; 16], u64), SmbReadError> {
        self.create_open(
            tree_id,
            rel_path,
            &CreateParams {
                desired_access: FILE_READ_ACCESS_ALL,
                share_access: 0x0000_0007, // R|W|D
                disposition: FILE_OPEN,
                create_options: FILE_NON_DIRECTORY_FILE,
            },
        )
    }

    /// SMB2 READ: read up to `length` bytes from `offset`.
    fn read_chunk(
        &mut self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, SmbReadError> {
        let hdr = self.build_header(SMB2_READ, tree_id);

        let mut body = vec![0u8; 48];
        body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
        body[2] = 0x50; // Padding (arbitrary dummy byte)
        // body[3] Flags = 0
        body[4..8].copy_from_slice(&length.to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..32].copy_from_slice(file_id);
        // MinimumCount / Channel / RemainingBytes / ChannelInfo* = 0

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.push(0); // 1-byte buffer

        self.send_packet(&packet)
            .map_err(|e| SmbReadError::Other(0, format!("send read: {e}")))?;
        let resp = self
            .recv_packet()
            .map_err(|e| SmbReadError::Other(0, format!("recv read: {e}")))?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(match status {
                STATUS_END_OF_FILE => SmbReadError::Other(STATUS_END_OF_FILE, "eof".into()),
                s => SmbReadError::Other(s, "read".into()),
            });
        }

        if resp.len() < SMB2_HEADER_SIZE + 16 {
            return Err(SmbReadError::Other(0, "read resp too short".into()));
        }
        let body_off = SMB2_HEADER_SIZE;
        let data_offset = resp[body_off + 2] as usize; // from start of header
        let data_length =
            u32::from_le_bytes(resp[body_off + 4..body_off + 8].try_into().unwrap()) as usize;

        if data_offset + data_length > resp.len() {
            return Err(SmbReadError::Other(0, "read data out of bounds".into()));
        }
        Ok(resp[data_offset..data_offset + data_length].to_vec())
    }

    /// SMB2 CLOSE.
    fn close_file(&mut self, tree_id: u32, file_id: &[u8; 16]) -> Result<(), String> {
        let hdr = self.build_header(SMB2_CLOSE, tree_id);
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&24u16.to_le_bytes()); // StructureSize
        // Flags=0, Reserved=0
        body[8..24].copy_from_slice(file_id);

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);

        self.send_packet(&packet)?;
        let _ = self.recv_packet()?;
        Ok(())
    }

    /// Try to connect to ADMIN$ to check admin access.
    pub fn check_admin(&mut self, target: &str) -> bool {
        match self.tree_connect(target, "ADMIN$") {
            Ok(tid) => {
                let _ = self.tree_disconnect(tid);
                true
            }
            Err(_) => false,
        }
    }

    /// SMB2 Tree Connect.
    pub fn tree_connect(&mut self, target: &str, share: &str) -> Result<u32, String> {
        let path = format!("\\\\{}\\{}", target, share);
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let hdr = self.build_header(SMB2_TREE_CONNECT, 0);

        // TreeConnect request: StructureSize=9, Reserved/Flags=0, PathOffset, PathLength
        let path_offset = (SMB2_HEADER_SIZE + 8) as u16;
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes());
        body[4..6].copy_from_slice(&path_offset.to_le_bytes());
        body[6..8].copy_from_slice(&(path_utf16.len() as u16).to_le_bytes());

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&path_utf16);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(explain_tree_connect_failure(share, status));
        }

        let tree_id = u32::from_le_bytes(resp[36..40].try_into().unwrap());
        Ok(tree_id)
    }

    /// SMB2 Tree Disconnect.
    pub fn tree_disconnect(&mut self, tree_id: u32) -> Result<(), String> {
        let hdr = self.build_header(SMB2_TREE_DISCONNECT, tree_id);
        let body = [4u8, 0, 0, 0]; // StructureSize=4, Reserved=0

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);

        self.send_packet(&packet)?;
        let _ = self.recv_packet()?;
        Ok(())
    }

    /// Open `\PIPE\<name>` on an already-connected IPC$ tree.
    ///
    /// `tree_id` must come from a prior `tree_connect(target, "IPC$")`.
    /// `name` is the bare pipe leaf with no leading backslash — `"srvsvc"`,
    /// `"samr"`, `"svcctl"`, `"wkssvc"`, etc.
    ///
    /// Returns a `PipeHandle` you pass to `pipe_transceive` and `pipe_close`.
    /// Phase 3 of the cross-platform portage plan: this is the carrier
    /// every Phase 4-6 RPC interface (MS-SRVS, MS-SAMR, MS-SVCCTL, MS-WKSSVC,
    /// MS-WINREG) rides on.
    pub fn pipe_open(&mut self, tree_id: u32, name: &str) -> Result<PipeHandle, String> {
        let (body, name_utf16) = build_pipe_create_body(name);
        let hdr = self.build_header(SMB2_CREATE, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + name_utf16.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&name_utf16);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(format!("pipe_open(\\PIPE\\{name}): 0x{status:08x}"));
        }

        let file_id = parse_pipe_create_response(&resp)?;
        Ok(PipeHandle { file_id, tree_id })
    }

    /// SMB2 IOCTL with `FSCTL_PIPE_TRANSCEIVE`: write `request` to the pipe
    /// and return whatever the server writes back, all in one round-trip.
    ///
    /// This is intentionally synchronous and one-shot — DCE/RPC fragmentation
    /// happens at a higher layer (in `netraze-dcerpc`), not here. The wire
    /// `MaxOutputResponse` we ask for is `u16::MAX` worth of bytes, which is
    /// what Windows pipes negotiate by default; bigger responses come back
    /// as multiple PDU fragments and the caller drives the loop.
    pub fn pipe_transceive(
        &mut self,
        handle: &PipeHandle,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        let body = build_pipe_transceive_body(&handle.file_id, request.len() as u32);
        let hdr = self.build_header(SMB2_IOCTL, handle.tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + request.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(request);

        self.send_packet(&packet)?;

        // Some servers (Samba in particular) may return STATUS_PENDING on
        // FSCTL_PIPE_TRANSCEIVE before the final response is ready. Loop
        // until we get a definitive status.
        loop {
            let resp = self.recv_packet()?;
            let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
            if status == STATUS_SUCCESS {
                return parse_pipe_transceive_response(&resp);
            }
            if status != STATUS_PENDING {
                return Err(format!("pipe_transceive: 0x{status:08x}"));
            }
        }
    }

    /// SMB2 WRITE on a pipe handle: push `data` to the server with no read
    /// side. We still consume the WRITE Response (just to ack the bytes
    /// written and keep `message_id` in sync) but never queue a read for
    /// reply data — there isn't any.
    ///
    /// Used exclusively by the DCE/RPC layer for AUTH3 PDUs, which are
    /// one-way per MS-RPCE §2.2.2.5. Sending an AUTH3 via
    /// `pipe_transceive` would deadlock: the IOCTL's read half blocks
    /// waiting for response bytes that the server will never produce.
    pub fn pipe_write(&mut self, handle: &PipeHandle, data: &[u8]) -> Result<(), String> {
        let body = build_write_body(&handle.file_id, 0, data.len() as u32);
        let hdr = self.build_header(SMB2_WRITE, handle.tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + data.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        packet.extend_from_slice(data);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(format!("pipe_write: 0x{status:08x}"));
        }
        Ok(())
    }

    /// SMB2 CLOSE on a pipe handle. Idempotent at the protocol level — the
    /// server returns `STATUS_FILE_CLOSED` (0xC0000128) on a double-close,
    /// which we surface as an error so the caller can spot the bug.
    pub fn pipe_close(&mut self, handle: &PipeHandle) -> Result<(), String> {
        let body = build_pipe_close_body(&handle.file_id);
        let hdr = self.build_header(SMB2_CLOSE, handle.tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len());
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(format!("pipe_close: 0x{status:08x}"));
        }
        Ok(())
    }

    /// Probe whether the current session can write to `share` via `tree_id`.
    ///
    /// Opens the share **root directory** (`""` on the tree) with
    /// `DesiredAccess = FILE_WRITE_DATA` and `FILE_DIRECTORY_FILE`. The root
    /// always exists, so the answer is a pure access check with no
    /// name-resolution ambiguity, and opening a directory for write modifies
    /// nothing:
    ///
    /// - `STATUS_SUCCESS` → write access granted → `Ok(true)`.
    /// - `STATUS_ACCESS_DENIED` (0xC0000022) → `Ok(false)`. Read-only.
    /// - Any other status is propagated as `Err` so the caller can log /
    ///   classify it; the share-access detection layer maps Err→Read as a
    ///   safe default.
    ///
    /// Earlier versions probed a random non-existent *file*, reading
    /// `STATUS_OBJECT_NAME_NOT_FOUND` as "writable" — that assumes the ACL
    /// check precedes the existence check, which holds on Windows but not on
    /// Samba ≥ 4.23 (it answers NAME_NOT_FOUND on read-only shares too,
    /// classifying them as writable). The root-directory probe returns the
    /// correct classification on both; verified against Impacket on the
    /// Samba 4.23.8 harness.
    ///
    /// Mirrors `check_share_access` in the Windows-native `shares.rs` but
    /// runs identically on every OS via raw SMB2.
    pub fn probe_write(&mut self, tree_id: u32) -> Result<bool, String> {
        let (body, _name_utf16) = build_create_body(
            &CreateParams {
                // DesiredAccess = FILE_WRITE_DATA (0x02). The whole point of the
                // probe is to ask the server "would you give me write?" — anything
                // beyond that bit risks tripping unrelated ACL checks.
                desired_access: 0x0000_0002,
                share_access: 0x0000_0007, // R|W|D
                disposition: FILE_OPEN,
                create_options: FILE_DIRECTORY_FILE,
            },
            "",
        );
        let hdr = self.build_header(SMB2_CREATE, tree_id);

        let mut packet = Vec::with_capacity(hdr.len() + body.len() + 1);
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        // Empty path buffer: SMB2 requires a 1-byte zero pad when the name
        // is absent (same as a create with no name).
        packet.push(0);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        match status {
            STATUS_SUCCESS => Ok(true),
            STATUS_ACCESS_DENIED => Ok(false),
            other => Err(format!("probe_write: 0x{other:08x}")),
        }
    }

    /// Send SMB2 Logoff.
    pub fn logoff(&mut self) {
        if self.session_id == 0 {
            return;
        }
        let hdr = self.build_header(SMB2_LOGOFF, 0);
        let body = [4u8, 0, 0, 0];
        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        let _ = self.send_packet(&packet);
        let _ = self.recv_packet();
        // Drop the session key — any subsequent RPC bind would have nothing
        // valid to seal with anyway, and we don't want a stale key sitting
        // in memory after the session is closed.
        self.session_key = None;
    }

    /// NTLMv2 ExportedSessionKey for this session, or `None` if the handshake
    /// hasn't completed (or if `logoff` was called). DCE/RPC layers (Phase A
    /// and beyond) seed `NtlmAuthenticator` from this value to derive the
    /// PKT_PRIVACY seal/sign keys.
    pub fn exported_session_key(&self) -> Option<[u8; 16]> {
        self.session_key
    }

    // ── Internal protocol methods ──

    fn negotiate(&mut self) -> Result<(), String> {
        let hdr = self.build_header(SMB2_NEGOTIATE, 0);

        let dialects: &[u16] = &[0x0202, 0x0210];
        let mut body = vec![0u8; 36 + dialects.len() * 2];
        body[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        body[2..4].copy_from_slice(&(dialects.len() as u16).to_le_bytes());
        body[4..6].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
        for (i, d) in dialects.iter().enumerate() {
            body[36 + i * 2..38 + i * 2].copy_from_slice(&d.to_le_bytes());
        }

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        if status != STATUS_SUCCESS {
            return Err(format!("Negotiate failed: 0x{status:08x}"));
        }
        if resp.len() < SMB2_HEADER_SIZE + 65 {
            return Err("Negotiate response too short".into());
        }

        // MS-SMB2 §2.2.4 — SecurityMode at body offset 2. Bit 0x0002 means
        // the server *requires* signing: it will silently drop every
        // unsigned request once the session is authenticated.
        self.signing_required = negotiate_signing_required(&resp)?;

        Ok(())
    }

    fn session_setup(
        &mut self,
        nt_hash: &[u8; 16],
        username: &str,
        domain: &str,
    ) -> Result<(), String> {
        // === Round 1: NTLMSSP Negotiate ===
        let negotiate_msg = ntlm::build_negotiate();
        let spnego1 = ntlm::wrap_spnego_init(&negotiate_msg);

        let hdr1 = self.build_header(SMB2_SESSION_SETUP, 0);
        let body1 = self.build_session_setup_body(&spnego1);

        let mut packet1 = Vec::new();
        packet1.extend_from_slice(&hdr1);
        packet1.extend_from_slice(&body1);
        packet1.extend_from_slice(&spnego1);

        self.send_packet(&packet1)?;
        let resp1 = self.recv_packet()?;

        let status1 = u32::from_le_bytes(resp1[8..12].try_into().unwrap());
        if status1 != STATUS_MORE_PROCESSING {
            return Err(format!("Session Setup round 1 failed: 0x{status1:08x}"));
        }

        // Capture SessionId from response
        self.session_id = u64::from_le_bytes(resp1[40..48].try_into().unwrap());

        // Extract NTLMSSP Challenge from SPNEGO in response
        let resp_body = &resp1[SMB2_HEADER_SIZE..];
        let sec_offset = u16::from_le_bytes(resp_body[4..6].try_into().unwrap()) as usize;
        let sec_len = u16::from_le_bytes(resp_body[6..8].try_into().unwrap()) as usize;

        if sec_offset + sec_len > resp1.len() {
            return Err("Security buffer out of bounds".into());
        }
        let spnego_data = &resp1[sec_offset..sec_offset + sec_len];

        let challenge_data =
            ntlm::extract_ntlmssp(spnego_data).ok_or("No NTLMSSP in server challenge response")?;
        let challenge = ntlm::parse_challenge(challenge_data)?;

        // === Round 2: NTLMv2 Authenticate ===
        let auth = ntlm::compute_ntlmv2(nt_hash, username, domain, &challenge)?;
        let (auth_msg, exported_session_key) =
            ntlm::build_authenticate(&auth, username, domain, challenge.negotiate_flags);
        let spnego2 = ntlm::wrap_spnego_resp(&auth_msg);

        let hdr2 = self.build_header(SMB2_SESSION_SETUP, 0);
        let body2 = self.build_session_setup_body(&spnego2);

        let mut packet2 = Vec::new();
        packet2.extend_from_slice(&hdr2);
        packet2.extend_from_slice(&body2);
        packet2.extend_from_slice(&spnego2);

        self.send_packet(&packet2)?;
        let resp2 = self.recv_packet()?;

        let status2 = u32::from_le_bytes(resp2[8..12].try_into().unwrap());
        if status2 != STATUS_SUCCESS {
            self.session_id = 0;
            return Err(format!("Authentication failed: 0x{status2:08x}"));
        }

        // MS-SMB2 §2.2.6 — `SessionFlags` at body offset 2 (2 bytes). Value
        // `0x0001 = SMB2_SESSION_FLAG_IS_GUEST`, `0x0002 = SMB2_SESSION_FLAG_IS_NULL`.
        //
        // This is the load-bearing fix for the "tree_connect IPC$ returns
        // 0xC0000022" footgun: Windows servers happily complete session_setup
        // with STATUS_SUCCESS when an account binds as guest (typical when
        // the password/domain combo is wrong but the box has guest enabled),
        // then refuse IPC$ tree_connect because guest can't bind there.
        // Without this check, the failure surfaces as a confusing
        // ACCESS_DENIED on tree_connect *after* "auth succeeded".
        if resp2.len() >= SMB2_HEADER_SIZE + 4 {
            let session_flags = u16::from_le_bytes(
                resp2[SMB2_HEADER_SIZE + 2..SMB2_HEADER_SIZE + 4]
                    .try_into()
                    .unwrap(),
            );
            if session_flags & 0x0001 != 0 {
                self.session_id = 0;
                return Err(format!(
                    "auth downgraded to GUEST for {domain}\\{username} \
                     — credentials are invalid (wrong password / wrong domain) \
                     or the server's account policy refused them. \
                     IPC$ and every authenticated share will be denied."
                ));
            }
            if session_flags & 0x0002 != 0 {
                self.session_id = 0;
                return Err(format!(
                    "auth downgraded to ANONYMOUS for {domain}\\{username} \
                     — server treated us as a null session. \
                     IPC$ tree_connect will be denied on any hardened host."
                ));
            }
        }

        // Stash the ExportedSessionKey now that the server has confirmed the
        // AUTHENTICATE message. `RpcChannel::bind_authenticated` will read it
        // back via `exported_session_key()` to build its NTLMSSP authenticator.
        self.session_key = Some(exported_session_key);

        Ok(())
    }

    fn build_session_setup_body(&self, security_buffer: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&25u16.to_le_bytes()); // StructureSize
        body[3] = 1; // SecurityMode: signing enabled
        let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
        body[12..14].copy_from_slice(&sec_offset.to_le_bytes());
        body[14..16].copy_from_slice(&(security_buffer.len() as u16).to_le_bytes());
        body
    }

    fn build_header(&mut self, command: u16, tree_id: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; SMB2_HEADER_SIZE];
        hdr[0..4].copy_from_slice(SMB2_MAGIC);
        hdr[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        hdr[6..8].copy_from_slice(&1u16.to_le_bytes()); // CreditCharge
        hdr[12..14].copy_from_slice(&command.to_le_bytes());
        hdr[14..16].copy_from_slice(&31u16.to_le_bytes()); // CreditRequest
        let mid = self.message_id;
        self.message_id += 1;
        hdr[24..32].copy_from_slice(&mid.to_le_bytes());
        hdr[36..40].copy_from_slice(&tree_id.to_le_bytes());
        hdr[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        hdr
    }

    /// Send one SMB2 request, signing it first when the server requires it.
    ///
    /// Signing gate (MS-SMB2 §3.2.5.1, mirroring Impacket `sendSMB` /
    /// `signSMB` in `smb3.py`): sign iff the session key exists AND the
    /// server's Negotiate SecurityMode demanded it. The `session_key` gate
    /// alone is enough to leave NEGOTIATE and both SESSION_SETUP rounds
    /// unsigned — the key only materialises after round 2 — while every
    /// later request (TREE_CONNECT, CREATE, IOCTL, …, LOGOFF) gets signed.
    /// LOGOFF is sent before `logoff()` clears the key, so it is covered.
    ///
    /// Server *response* signatures are not verified — same deliberate
    /// choice Impacket makes; out of scope until something needs it.
    fn send_packet(&mut self, data: &[u8]) -> Result<(), String> {
        let wire: Vec<u8> = match (self.signing_required, self.session_key) {
            (true, Some(key)) => {
                let mut signed = data.to_vec();
                sign_smb2_message(&mut signed, &key)?;
                signed
            }
            _ => data.to_vec(),
        };
        let len = wire.len() as u32;
        let nb = [0u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        self.stream
            .write_all(&nb)
            .and_then(|_| self.stream.write_all(&wire))
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("Send failed: {e}"))
    }

    fn recv_packet(&mut self) -> Result<Vec<u8>, String> {
        let mut nb = [0u8; 4];
        self.stream
            .read_exact(&mut nb)
            .map_err(|e| format!("Recv header failed: {e}"))?;
        let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | (nb[3] as usize);
        if len > 1024 * 1024 {
            return Err("Response too large".into());
        }
        let mut data = vec![0u8; len];
        self.stream
            .read_exact(&mut data)
            .map_err(|e| format!("Recv data failed: {e}"))?;
        if data.len() < SMB2_HEADER_SIZE || &data[0..4] != SMB2_MAGIC {
            return Err("Invalid SMB2 response".into());
        }
        Ok(data)
    }
}

impl Drop for Smb2Session {
    fn drop(&mut self) {
        self.logoff();
    }
}

// ──────────────────────── Diagnostic helpers ─────────────────────────

/// Map an NTSTATUS returned on a TreeConnect failure to an actionable
/// human-readable explanation. Tells the operator *what to try next*
/// rather than dumping a raw `0xc0000022` and walking away.
///
/// We deliberately concentrate the operator-facing wisdom here (rather
/// than scattering it across each call site) because TreeConnect is the
/// single place where credential / signing / share-permission problems
/// surface for the first time in any SMB workflow.
fn explain_tree_connect_failure(share: &str, status: u32) -> String {
    match status {
        // STATUS_ACCESS_DENIED — by far the most common failure on IPC$
        // and the one that historically just produced "0xc0000022" with
        // no context. The cause is almost never that the share itself is
        // ACL-locked: it's that the SMB session is degraded or the
        // server policy refuses our auth class.
        0xC000_0022 => format!(
            "TreeConnect {share}: ACCESS_DENIED (0xC0000022). \
             Likely causes — check in this order: \
             (1) credentials are wrong → session was downgraded to GUEST \
             (we should have caught this at session_setup but some servers \
             return SUCCESS without setting the GUEST flag); \
             (2) the user account exists but doesn't have local logon rights \
             on this host (typical: domain user on a workgroup box, or vice versa); \
             (3) the server requires SMB signing and rejected ours \
             (we sign automatically when the server demands it — see \
             `sign_smb2_message`; unlikely unless the session key was \
             derived from a mismatched credential); \
             (4) the server has 'Restrict NTLM: Incoming NTLM traffic' set to deny — \
             retry with Kerberos or from a host that's allowed; \
             (5) the share is genuinely ACL-restricted (rare for IPC$). \
             Verify with: smbclient -L //{share} -U user%pass"
        ),
        // STATUS_BAD_NETWORK_NAME — share doesn't exist on this server
        0xC000_00CC => format!(
            "TreeConnect {share}: BAD_NETWORK_NAME (0xC00000CC). \
             The share doesn't exist on this server. \
             Common typos: ADMIN$ vs admin$ (case-insensitive on Windows but \
             pinned-name shares like a custom 'Backup' may be case-sensitive on Samba). \
             Run enum_shares first to see the real share inventory."
        ),
        // STATUS_BAD_NETWORK_PATH — UNC path malformed (ports leaking, etc.)
        0xC000_00BE => format!(
            "TreeConnect {share}: BAD_NETWORK_PATH (0xC00000BE). \
             Server can't parse the UNC path — usually means the target string \
             includes a port suffix (\"host:445\") that leaked into the UNC. \
             Strip the port before calling tree_connect."
        ),
        // STATUS_LOGON_FAILURE — re-authentication required
        0xC000_006D => format!(
            "TreeConnect {share}: LOGON_FAILURE (0xC000006D). \
             Server invalidated our session; reconnect required. \
             Check the account isn't locked or password-expired."
        ),
        // STATUS_NETWORK_SESSION_EXPIRED
        0xC000_035C => format!(
            "TreeConnect {share}: SESSION_EXPIRED (0xC000035C). \
             SMB session timed out server-side. Reconnect."
        ),
        // STATUS_USER_SESSION_DELETED
        0xC000_00CB => format!(
            "TreeConnect {share}: USER_SESSION_DELETED (0xC00000CB). \
             Server tore down our session, often because of admin policy \
             or signing mismatch on the prior op. Reconnect."
        ),
        // STATUS_NOT_SUPPORTED — usually signing-required mismatch
        0xC000_00BB => format!(
            "TreeConnect {share}: NOT_SUPPORTED (0xC00000BB). \
             Historically meant 'server requires SMB signing and we're not signing' \
             — signing is implemented now, so if this appears the likely cause is \
             a dialect/capability mismatch in the Negotiate exchange."
        ),
        // Generic — print the raw code so the operator can look it up
        _ => format!(
            "TreeConnect {share}: 0x{status:08x} \
             (no specific hint — look up the NTSTATUS in MS-ERREF)"
        ),
    }
}

// ──────────────────────── Signing helpers ──────────────────────────
//
// Pure functions — no `&self`, no IO — so the wire transformation can be
// unit-tested without a TcpStream (same pattern as the pipe helpers below).

/// SMB2_FLAGS_SIGNED (MS-SMB2 §2.2.2.4, bit 3 of the Flags field).
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

/// Sign an outgoing SMB2 request in place for dialects 2.0.2 / 2.1
/// (MS-SMB2 §3.2.5.1.1):
///
/// 1. Set `SMB2_FLAGS_SIGNED` in the header Flags — the flag itself is
///    covered by the signature, so it must be flipped *before* the MAC.
/// 2. Zero the 16-byte Signature field (48..64).
/// 3. Signature = `HMAC-SHA256(SessionKey, entire SMB2 message)[:16]`.
///
/// The NetBIOS length prefix added by `send_packet` is NOT part of the
/// MAC. The signing key is the **raw** NTLMv2 ExportedSessionKey — the
/// HMAC-SHA256 KDF and AES-CMAC of SMB 3.x don't apply, and we only
/// offer dialects 0x0202/0x0210 in `negotiate`. Mirrors Impacket
/// `smb3.py:signSMB`.
fn sign_smb2_message(message: &mut [u8], session_key: &[u8; 16]) -> Result<(), String> {
    if message.len() < SMB2_HEADER_SIZE {
        return Err(format!(
            "cannot sign: message is {} bytes, shorter than the {}-byte SMB2 header",
            message.len(),
            SMB2_HEADER_SIZE
        ));
    }
    // 1. SIGNED flag first — it's inside the MAC input.
    let flags = u32::from_le_bytes(message[16..20].try_into().unwrap()) | SMB2_FLAGS_SIGNED;
    message[16..20].copy_from_slice(&flags.to_le_bytes());
    // 2. Zero the signature field.
    message[48..SMB2_HEADER_SIZE].fill(0);
    // 3. HMAC-SHA256 over the whole message, truncate to 16 bytes.
    let mac = super::crypto::hmac_sha256(session_key, message)?;
    message[48..SMB2_HEADER_SIZE].copy_from_slice(&mac[..16]);
    Ok(())
}

/// Extract the server's signing-required preference from a Negotiate
/// response (MS-SMB2 §2.2.4 — SecurityMode at body offset 2, bit 0x0002).
/// Separated from `negotiate` so the parsing is unit-testable.
fn negotiate_signing_required(resp: &[u8]) -> Result<bool, String> {
    if resp.len() < SMB2_HEADER_SIZE + 4 {
        return Err("Negotiate response too short".into());
    }
    let security_mode = u16::from_le_bytes(
        resp[SMB2_HEADER_SIZE + 2..SMB2_HEADER_SIZE + 4]
            .try_into()
            .unwrap(),
    );
    Ok(security_mode & 0x0002 != 0)
}

// ─────────────────────────── Pipe helpers ───────────────────────────
//
// Pure functions — no `&self`, no IO — so we can unit-test the wire layouts
// without a TcpStream. The `pipe_*` methods on `Smb2Session` are thin
// orchestration wrappers around these.

/// Build the fixed 56-byte CREATE Request body for any open — file, directory
/// or pipe — parameterised by `params` (MS-SMB2 §2.2.13).
///
/// `rel_path` is the path relative to the tree root (share or IPC$). Returns
/// `(body, name_utf16)` so the caller appends the name buffer after the body
/// when assembling the full SMB2 packet. For an empty `rel_path` (share root)
/// NameOffset still points past the fixed body and NameLength is 0 — Windows
/// rejects NameOffset=0 with STATUS_INVALID_PARAMETER even when the name is
/// empty; the caller appends a 1-byte dummy buffer (SMB2 forbids zero-length
/// buffers).
fn build_create_body(params: &CreateParams, rel_path: &str) -> (Vec<u8>, Vec<u8>) {
    let name_utf16: Vec<u8> = rel_path
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut body = vec![0u8; 56];
    body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
    // body[2]      SecurityFlags=0
    // body[3]      RequestedOplockLevel=0
    body[4..8].copy_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel=Impersonation
    // body[8..16]  SmbCreateFlags=0
    // body[16..24] Reserved=0
    body[24..28].copy_from_slice(&params.desired_access.to_le_bytes());
    // body[28..32] FileAttributes=0 (directories are selected via CreateOptions)
    body[32..36].copy_from_slice(&params.share_access.to_le_bytes());
    body[36..40].copy_from_slice(&params.disposition.to_le_bytes());
    body[40..44].copy_from_slice(&params.create_options.to_le_bytes());
    // Always point past the fixed body (64-byte header + 56-byte body), even
    // for the empty share-root name: Windows validates this field regardless
    // of NameLength and returns STATUS_INVALID_PARAMETER on 0.
    let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
    body[44..46].copy_from_slice(&name_offset.to_le_bytes());
    body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    // body[48..52] CreateContextsOffset=0
    // body[52..56] CreateContextsLength=0

    (body, name_utf16)
}

/// Build the fixed 56-byte CREATE Request body for opening a named pipe.
/// `name` is the bare leaf (`"srvsvc"`, `"samr"`, …) — no leading backslash.
/// Returns `(body, name_utf16)` so the caller can append the name buffer
/// after the body when assembling the full SMB2 packet.
fn build_pipe_create_body(name: &str) -> (Vec<u8>, Vec<u8>) {
    build_create_body(
        &CreateParams {
            desired_access: PIPE_DESIRED_ACCESS,
            share_access: 0x0000_0007, // R|W|D
            disposition: FILE_OPEN,
            // pipes must NOT set FILE_NON_DIRECTORY_FILE
            create_options: 0,
        },
        name,
    )
}

/// Build the fixed 56-byte IOCTL Request body for `FSCTL_PIPE_TRANSCEIVE`.
/// The caller appends the request payload (a DCE/RPC PDU) after this body.
fn build_pipe_transceive_body(file_id: &[u8; 16], request_len: u32) -> Vec<u8> {
    let mut body = vec![0u8; 56];
    body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
    // body[2..4]   Reserved=0
    body[4..8].copy_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes());
    body[8..24].copy_from_slice(file_id);

    let input_offset = (SMB2_HEADER_SIZE + 56) as u32;
    body[24..28].copy_from_slice(&input_offset.to_le_bytes()); // InputOffset
    body[28..32].copy_from_slice(&request_len.to_le_bytes()); // InputCount
    // body[32..36] MaxInputResponse=0  (no input echoed back)
    body[36..40].copy_from_slice(&input_offset.to_le_bytes()); // OutputOffset
    // body[40..44] OutputCount=0       (unused on request)
    body[44..48].copy_from_slice(&65_535u32.to_le_bytes()); // MaxOutputResponse
    body[48..52].copy_from_slice(&SMB2_0_IOCTL_IS_FSCTL.to_le_bytes());
    // body[52..56] Reserved2=0
    body
}

/// Build the fixed 48-byte WRITE Request body for a pipe or file handle. The
/// caller appends the payload bytes after this body.
///
/// Layout per MS-SMB2 §2.2.21:
///   - StructureSize = 49 (0x31), the "fixed body + 1" sentinel
///   - DataOffset    = SMB2_HEADER_SIZE + 48 — payload starts right after body
///   - Length        = `data_len`
///   - Offset        = `offset` (0 for pipes — they ignore the field)
///   - FileId        = 16 bytes
///   - Channel/RemainingBytes/WriteChannelInfo*/Flags = 0
fn build_write_body(file_id: &[u8; 16], offset: u64, data_len: u32) -> Vec<u8> {
    let mut body = vec![0u8; 48];
    body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
    let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
    body[2..4].copy_from_slice(&data_offset.to_le_bytes()); // DataOffset
    body[4..8].copy_from_slice(&data_len.to_le_bytes()); // Length
    body[8..16].copy_from_slice(&offset.to_le_bytes()); // Offset
    body[16..32].copy_from_slice(file_id);
    // body[32..36]  Channel = 0
    // body[36..40]  RemainingBytes = 0
    // body[40..42]  WriteChannelInfoOffset = 0
    // body[42..44]  WriteChannelInfoLength = 0
    // body[44..48]  Flags = 0
    body
}

/// Build the fixed 24-byte CLOSE Request body for a pipe handle.
fn build_pipe_close_body(file_id: &[u8; 16]) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    body[0..2].copy_from_slice(&24u16.to_le_bytes()); // StructureSize
    // body[2..4] Flags=0  (no SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB)
    // body[4..8] Reserved=0
    body[8..24].copy_from_slice(file_id);
    body
}

/// Extract the 16-byte FileId from an SMB2 CREATE Response (MS-SMB2 §2.2.14).
/// FileId sits at body offset 64 (8 bytes Persistent + 8 bytes Volatile).
fn parse_pipe_create_response(resp: &[u8]) -> Result<[u8; 16], String> {
    if resp.len() < SMB2_HEADER_SIZE + 88 {
        return Err(format!(
            "pipe_open response too short: {} < {}",
            resp.len(),
            SMB2_HEADER_SIZE + 88
        ));
    }
    let body_off = SMB2_HEADER_SIZE;
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&resp[body_off + 64..body_off + 80]);
    Ok(file_id)
}

/// Extract the OUTPUT buffer from an SMB2 IOCTL Response (MS-SMB2 §2.2.32).
/// `OutputOffset` is from the start of the SMB2 packet (header included).
/// Both offset and length are bounds-checked against the actual response.
fn parse_pipe_transceive_response(resp: &[u8]) -> Result<Vec<u8>, String> {
    // Fixed IOCTL Response body is 48 bytes (StructureSize=49 → 48 fixed).
    if resp.len() < SMB2_HEADER_SIZE + 48 {
        return Err(format!(
            "pipe_transceive response too short: {} < {}",
            resp.len(),
            SMB2_HEADER_SIZE + 48
        ));
    }
    let body_off = SMB2_HEADER_SIZE;
    let output_offset =
        u32::from_le_bytes(resp[body_off + 32..body_off + 36].try_into().unwrap()) as usize;
    let output_length =
        u32::from_le_bytes(resp[body_off + 36..body_off + 40].try_into().unwrap()) as usize;

    let end = output_offset
        .checked_add(output_length)
        .ok_or_else(|| "pipe_transceive output offset+length overflow".to_string())?;
    if end > resp.len() {
        return Err(format!(
            "pipe_transceive output out of bounds: {output_offset}+{output_length} > {}",
            resp.len()
        ));
    }
    Ok(resp[output_offset..end].to_vec())
}

// ───────────────────────── File-op helpers ─────────────────────────
//
// Same convention as the pipe helpers: pure functions, no `&self`, no IO —
// unit-testable without a TcpStream.

/// Map an SMB2 status from a CREATE response onto the caller-facing
/// `SmbReadError` classification.
fn map_create_status(status: u32) -> SmbReadError {
    match status {
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => SmbReadError::NotFound,
        STATUS_SHARING_VIOLATION => SmbReadError::SharingViolation,
        STATUS_OBJECT_NAME_COLLISION => SmbReadError::NameCollision,
        STATUS_ACCESS_DENIED => SmbReadError::AccessDenied,
        s => SmbReadError::Other(s, "create".into()),
    }
}

/// `FileInformationClass` for QUERY_DIRECTORY — `FILE_BOTH_DIRECTORY_INFORMATION`
/// (MS-FSCC §2.4.8). The classic choice: carries FileAttributes, EndOfFile
/// and the 8.3 short name (which we skip).
const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 0x03;

/// QUERY_DIRECTORY `Flags` bit: restart the enumeration from the beginning of
/// the directory (MS-SMB2 §2.2.33). Only the first request in a scan sets it.
const SMB2_RESTART_SCANS: u8 = 0x01;

/// Output buffer we ask for per QUERY_DIRECTORY round-trip. Mirrors
/// Impacket's `SMB_MAX_QUERY_DIRECTORY_SIZE` — large enough that a share
/// root fits in one response, small enough to stay under every server's
/// negotiated transact size.
const QUERY_DIR_MAX_BUFFER: u32 = 65_024;

/// Build the fixed 32-byte QUERY_DIRECTORY Request body (MS-SMB2 §2.2.33).
/// Returns `(body, pattern_utf16)` — the caller appends the pattern buffer.
fn build_query_directory_body(
    file_id: &[u8; 16],
    pattern: &str,
    restart_scan: bool,
) -> (Vec<u8>, Vec<u8>) {
    let pattern_utf16: Vec<u8> = pattern
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut body = vec![0u8; 32];
    body[0..2].copy_from_slice(&33u16.to_le_bytes()); // StructureSize
    body[2] = FILE_BOTH_DIRECTORY_INFORMATION; // FileInformationClass
    body[3] = if restart_scan { SMB2_RESTART_SCANS } else { 0 }; // Flags
    // body[4..8] FileIndex = 0 (resume via the FileId + no-restart convention)
    body[8..24].copy_from_slice(file_id);
    // Always point past the fixed body, even for an empty pattern (same
    // Windows NameOffset validation as CREATE — see build_create_body).
    let name_offset = (SMB2_HEADER_SIZE + 32) as u16;
    body[24..26].copy_from_slice(&name_offset.to_le_bytes()); // FileNameOffset
    body[26..28].copy_from_slice(&(pattern_utf16.len() as u16).to_le_bytes());
    body[28..32].copy_from_slice(&QUERY_DIR_MAX_BUFFER.to_le_bytes()); // OutputBufferLength
    (body, pattern_utf16)
}

/// Extract the OUTPUT buffer from an SMB2 QUERY_DIRECTORY Response
/// (MS-SMB2 §2.2.34). `OutputBufferOffset` is a u16 from the start of the
/// SMB2 header; `OutputBufferLength` a u32 right after it.
fn parse_query_directory_response(resp: &[u8]) -> Result<Vec<u8>, String> {
    if resp.len() < SMB2_HEADER_SIZE + 8 {
        return Err(format!(
            "query_dir response too short: {} < {}",
            resp.len(),
            SMB2_HEADER_SIZE + 8
        ));
    }
    let body_off = SMB2_HEADER_SIZE;
    let output_offset =
        u16::from_le_bytes(resp[body_off + 2..body_off + 4].try_into().unwrap()) as usize;
    let output_length =
        u32::from_le_bytes(resp[body_off + 4..body_off + 8].try_into().unwrap()) as usize;

    let end = output_offset
        .checked_add(output_length)
        .ok_or_else(|| "query_dir output offset+length overflow".to_string())?;
    if end > resp.len() {
        return Err(format!(
            "query_dir output out of bounds: {output_offset}+{output_length} > {}",
            resp.len()
        ));
    }
    Ok(resp[output_offset..end].to_vec())
}

/// Size of the fixed part of `FILE_BOTH_DIRECTORY_INFORMATION` — everything
/// before the variable-length `FileName` (MS-FSCC §2.4.8):
/// NextEntryOffset(4) + FileIndex(4) + 4×LARGE_INTEGER(32) + EndOfFile(8)
/// + AllocationSize(8) + FileAttributes(4) + FileNameLength(4) + EaSize(4)
/// + ShortNameLength(1) + Reserved(1) + ShortName(24) = 94.
const FILE_BOTH_FIXED_SIZE: usize = 94;

/// `FileAttributes` bit marking a directory entry.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// Parse a chain of `FILE_BOTH_DIRECTORY_INFORMATION` entries out of one
/// QUERY_DIRECTORY output buffer. Entries are linked by `NextEntryOffset`
/// (relative to the start of the entry); the last entry carries 0. `.` and
/// `..` entries are dropped.
fn parse_file_both_entries(buffer: &[u8]) -> Result<Vec<DirEntry>, String> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < buffer.len() {
        let remaining = &buffer[pos..];
        if remaining.len() < FILE_BOTH_FIXED_SIZE {
            return Err(format!(
                "query_dir entry truncated: {} bytes left at offset {pos}, need {FILE_BOTH_FIXED_SIZE}",
                remaining.len()
            ));
        }
        let next_offset = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
        let end_of_file = u64::from_le_bytes(remaining[40..48].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(remaining[56..60].try_into().unwrap());
        let name_len = u32::from_le_bytes(remaining[60..64].try_into().unwrap()) as usize;
        if remaining.len() < FILE_BOTH_FIXED_SIZE + name_len {
            return Err(format!(
                "query_dir name truncated at offset {pos}: {} < {}",
                remaining.len(),
                FILE_BOTH_FIXED_SIZE + name_len
            ));
        }
        let name_utf16: Vec<u16> = remaining[FILE_BOTH_FIXED_SIZE..FILE_BOTH_FIXED_SIZE + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&name_utf16);
        if name != "." && name != ".." {
            entries.push(DirEntry {
                name,
                is_dir: file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                size: end_of_file,
            });
        }
        if next_offset == 0 {
            break; // last entry of this batch
        }
        pos += next_offset;
    }
    Ok(entries)
}

/// `InfoType` for SET_INFO on a file handle (MS-SMB2 §2.2.39).
const SMB2_0_INFO_FILE: u8 = 0x01;
/// `FileInfoClass` arming the DELETE_ON_CLOSE disposition.
const FILE_DISPOSITION_INFORMATION: u8 = 13;

/// Build the fixed 32-byte SET_INFO Request body for
/// `FileDispositionInformation = TRUE` (MS-SMB2 §2.2.39 / MS-FSCC §2.4.11).
/// The caller appends the 1-byte BOOLEAN `TRUE` buffer after the body.
fn build_set_info_disposition_body(file_id: &[u8; 16]) -> Vec<u8> {
    let mut body = vec![0u8; 32];
    body[0..2].copy_from_slice(&33u16.to_le_bytes()); // StructureSize
    body[2] = SMB2_0_INFO_FILE; // InfoType
    body[3] = FILE_DISPOSITION_INFORMATION; // FileInfoClass
    body[4..8].copy_from_slice(&1u32.to_le_bytes()); // BufferLength (BOOLEAN = 1 byte)
    let buffer_offset = (SMB2_HEADER_SIZE + 32) as u16;
    body[8..10].copy_from_slice(&buffer_offset.to_le_bytes()); // BufferOffset
    // body[10..12] Reserved = 0
    // body[12..16] AdditionalInformation = 0
    body[16..32].copy_from_slice(file_id);
    body
}

#[cfg(test)]
mod pipe_tests {
    use super::*;

    #[test]
    fn pipe_create_body_lays_out_expected_bytes() {
        let (body, name) = build_pipe_create_body("srvsvc");

        assert_eq!(body.len(), 56, "fixed body must be exactly 56 bytes");
        // StructureSize = 57 (0x39 LE)
        assert_eq!(&body[0..2], &[0x39, 0x00]);
        // SecurityFlags=0, RequestedOplockLevel=0
        assert_eq!(&body[2..4], &[0x00, 0x00]);
        // ImpersonationLevel = 2 (Impersonation)
        assert_eq!(&body[4..8], &[0x02, 0x00, 0x00, 0x00]);
        // DesiredAccess = 0x0012019F
        assert_eq!(&body[24..28], &0x0012_019Fu32.to_le_bytes());
        // ShareAccess = 0x07 (R|W|D)
        assert_eq!(&body[32..36], &[0x07, 0x00, 0x00, 0x00]);
        // CreateDisposition = FILE_OPEN (1)
        assert_eq!(&body[36..40], &[0x01, 0x00, 0x00, 0x00]);
        // CreateOptions = 0 (no FILE_NON_DIRECTORY_FILE for pipes)
        assert_eq!(&body[40..44], &[0x00, 0x00, 0x00, 0x00]);
        // NameOffset = 64 + 56 = 120
        assert_eq!(&body[44..46], &120u16.to_le_bytes());
        // NameLength = 12 (UTF-16 of "srvsvc" = 6 cu × 2 bytes)
        assert_eq!(&body[46..48], &12u16.to_le_bytes());
        // Name bytes are UTF-16 LE "srvsvc", no leading backslash
        assert_eq!(name, b"s\0r\0v\0s\0v\0c\0");
    }

    #[test]
    fn pipe_create_body_handles_known_pipe_names() {
        for (name, want_len) in [
            ("samr", 8u16),
            ("svcctl", 12u16),
            ("wkssvc", 12u16),
            ("winreg", 12u16),
            ("lsarpc", 12u16),
            ("netlogon", 16u16),
        ] {
            let (body, name_buf) = build_pipe_create_body(name);
            let length_field = u16::from_le_bytes(body[46..48].try_into().unwrap());
            assert_eq!(length_field, want_len, "wrong NameLength for `{name}`");
            assert_eq!(name_buf.len(), want_len as usize);
        }
    }

    #[test]
    fn pipe_transceive_body_lays_out_expected_bytes() {
        let mut file_id = [0u8; 16];
        file_id[..8].fill(0x41); // Persistent = 0x41…41
        file_id[8..].fill(0x42); // Volatile   = 0x42…42

        let body = build_pipe_transceive_body(&file_id, 72);

        assert_eq!(body.len(), 56);
        // StructureSize = 57
        assert_eq!(&body[0..2], &[0x39, 0x00]);
        // Reserved = 0
        assert_eq!(&body[2..4], &[0x00, 0x00]);
        // CtlCode = FSCTL_PIPE_TRANSCEIVE (0x0011C017 LE)
        assert_eq!(&body[4..8], &[0x17, 0xC0, 0x11, 0x00]);
        // FileId (16 bytes — Persistent + Volatile)
        assert_eq!(&body[8..24], &file_id);
        // InputOffset = 120, InputCount = 72
        assert_eq!(&body[24..28], &120u32.to_le_bytes());
        assert_eq!(&body[28..32], &72u32.to_le_bytes());
        // MaxInputResponse = 0
        assert_eq!(&body[32..36], &[0x00, 0x00, 0x00, 0x00]);
        // OutputOffset = 120 (echoed; server replaces on response)
        assert_eq!(&body[36..40], &120u32.to_le_bytes());
        // MaxOutputResponse = 65535
        assert_eq!(&body[44..48], &65_535u32.to_le_bytes());
        // Flags = SMB2_0_IOCTL_IS_FSCTL (1)
        assert_eq!(&body[48..52], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pipe_write_body_lays_out_expected_bytes() {
        let mut file_id = [0u8; 16];
        for (i, b) in file_id.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8);
        }
        let body = build_write_body(&file_id, 0, 64);

        assert_eq!(body.len(), 48, "fixed WRITE body must be exactly 48 bytes");
        // StructureSize = 49 (0x31)
        assert_eq!(&body[0..2], &49u16.to_le_bytes());
        // DataOffset = SMB2_HEADER_SIZE(64) + 48 = 112 (0x70)
        assert_eq!(&body[2..4], &112u16.to_le_bytes());
        // Length = 64
        assert_eq!(&body[4..8], &64u32.to_le_bytes());
        // Offset = 0 (pipes ignore this)
        assert_eq!(&body[8..16], &[0u8; 8]);
        // FileId
        assert_eq!(&body[16..32], &file_id);
        // Channel / RemainingBytes / WriteChannelInfo* / Flags = 0
        assert_eq!(&body[32..48], &[0u8; 16]);
    }

    #[test]
    fn file_write_body_carries_the_file_offset() {
        let file_id = [0x33u8; 16];
        let offset: u64 = 0x0010_0000; // exactly one 60 KiB chunk in
        let body = build_write_body(&file_id, offset, 4096);
        assert_eq!(&body[4..8], &4096u32.to_le_bytes());
        assert_eq!(&body[8..16], &offset.to_le_bytes());
    }

    #[test]
    fn pipe_close_body_lays_out_expected_bytes() {
        let file_id = [0xAAu8; 16];
        let body = build_pipe_close_body(&file_id);

        assert_eq!(body.len(), 24);
        assert_eq!(&body[0..2], &24u16.to_le_bytes()); // StructureSize=24
        assert_eq!(&body[2..4], &[0x00, 0x00]); // Flags=0
        assert_eq!(&body[4..8], &[0x00, 0x00, 0x00, 0x00]); // Reserved=0
        assert_eq!(&body[8..24], &file_id);
    }

    #[test]
    fn parse_pipe_create_response_extracts_file_id() {
        // 64-byte SMB2 hdr + 89-byte CREATE Resp body, FileId at body+64.
        let mut resp = vec![0u8; SMB2_HEADER_SIZE + 89];
        resp[0..4].copy_from_slice(SMB2_MAGIC);
        for (i, b) in resp[SMB2_HEADER_SIZE + 64..SMB2_HEADER_SIZE + 80]
            .iter_mut()
            .enumerate()
        {
            *b = 0xC0u8.wrapping_add(i as u8);
        }
        let fid = parse_pipe_create_response(&resp).expect("parse should succeed");
        for (i, b) in fid.iter().enumerate() {
            assert_eq!(*b, 0xC0u8.wrapping_add(i as u8), "fid[{i}] mismatch");
        }
    }

    #[test]
    fn parse_pipe_create_response_rejects_truncation() {
        // Way shorter than SMB2_HEADER_SIZE + 88 = 152.
        let short = vec![0u8; 100];
        assert!(parse_pipe_create_response(&short).is_err());
    }

    #[test]
    fn parse_pipe_transceive_response_extracts_output_buffer() {
        let payload: &[u8] = b"\x05\x00\x0c\x03BIND_ACK_payload_marker";
        // Build a fake IOCTL Response: 64B hdr + 48B fixed body + payload.
        let total = SMB2_HEADER_SIZE + 48 + payload.len();
        let mut resp = vec![0u8; total];
        resp[0..4].copy_from_slice(SMB2_MAGIC);

        let body_off = SMB2_HEADER_SIZE;
        let output_offset = (SMB2_HEADER_SIZE + 48) as u32; // 112
        resp[body_off + 32..body_off + 36].copy_from_slice(&output_offset.to_le_bytes());
        resp[body_off + 36..body_off + 40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        resp[output_offset as usize..total].copy_from_slice(payload);

        let out = parse_pipe_transceive_response(&resp).expect("parse should succeed");
        assert_eq!(out.as_slice(), payload);
    }

    #[test]
    fn parse_pipe_transceive_response_rejects_oob_offset() {
        let mut resp = vec![0u8; SMB2_HEADER_SIZE + 48];
        resp[0..4].copy_from_slice(SMB2_MAGIC);
        let body_off = SMB2_HEADER_SIZE;
        // OutputOffset = 200 (well past end), OutputCount = 32.
        resp[body_off + 32..body_off + 36].copy_from_slice(&200u32.to_le_bytes());
        resp[body_off + 36..body_off + 40].copy_from_slice(&32u32.to_le_bytes());
        assert!(parse_pipe_transceive_response(&resp).is_err());
    }

    #[test]
    fn parse_pipe_transceive_response_handles_zero_length_output() {
        // Empty pipe response is legal — server sets OutputCount=0.
        let mut resp = vec![0u8; SMB2_HEADER_SIZE + 48];
        resp[0..4].copy_from_slice(SMB2_MAGIC);
        let body_off = SMB2_HEADER_SIZE;
        resp[body_off + 32..body_off + 36]
            .copy_from_slice(&((SMB2_HEADER_SIZE + 48) as u32).to_le_bytes());
        resp[body_off + 36..body_off + 40].copy_from_slice(&0u32.to_le_bytes());
        let out = parse_pipe_transceive_response(&resp).expect("parse should succeed");
        assert!(out.is_empty());
    }
}

#[cfg(test)]
mod file_ops_tests {
    use super::*;

    // ── build_create_body ──

    #[test]
    fn create_body_lays_out_params_in_the_right_fields() {
        let (body, name) = build_create_body(
            &CreateParams {
                desired_access: 0x0010_0102,
                share_access: 0x0000_0007,
                disposition: FILE_OVERWRITE_IF,
                create_options: FILE_NON_DIRECTORY_FILE,
            },
            "sub\\file.txt",
        );

        assert_eq!(body.len(), 56, "fixed body must be exactly 56 bytes");
        assert_eq!(&body[0..2], &57u16.to_le_bytes()); // StructureSize
        assert_eq!(&body[4..8], &2u32.to_le_bytes()); // ImpersonationLevel
        assert_eq!(&body[24..28], &0x0010_0102u32.to_le_bytes()); // DesiredAccess
        assert_eq!(&body[28..32], &[0u8; 4]); // FileAttributes = 0
        assert_eq!(&body[32..36], &0x0000_0007u32.to_le_bytes()); // ShareAccess
        assert_eq!(&body[36..40], &5u32.to_le_bytes()); // FILE_OVERWRITE_IF
        assert_eq!(&body[40..44], &0x40u32.to_le_bytes()); // FILE_NON_DIRECTORY_FILE
        assert_eq!(&body[44..46], &120u16.to_le_bytes()); // NameOffset = 64+56
        assert_eq!(&body[46..48], &24u16.to_le_bytes()); // "sub\file.txt" = 12 cu
        // UTF-16 LE of the path, backslashes included ("sub" + '\' + "file.txt")
        assert_eq!(name.len(), 24);
        assert_eq!(&name[6..8], b"\\\0");
        assert_eq!(&name[0..6], b"s\0u\0b\0");
    }

    #[test]
    fn create_body_empty_path_still_points_past_body() {
        let (body, name) = build_create_body(
            &CreateParams {
                desired_access: FILE_LIST_DIRECTORY_ACCESS,
                share_access: 0x07,
                disposition: FILE_OPEN,
                create_options: FILE_DIRECTORY_FILE,
            },
            "",
        );
        // NameOffset must still point past the fixed body (64+56): Windows
        // returns STATUS_INVALID_PARAMETER for NameOffset=0 even when the
        // name is empty (share root).
        assert_eq!(
            &body[44..46],
            &120u16.to_le_bytes(),
            "NameOffset must be 120"
        );
        assert_eq!(&body[46..48], &0u16.to_le_bytes(), "NameLength must be 0");
        assert!(name.is_empty());
    }

    #[test]
    fn pipe_create_body_delegation_keeps_pipe_semantics() {
        let (body, name) = build_pipe_create_body("srvsvc");
        // The pipe builder is now a thin delegation to build_create_body —
        // pin the pipe-specific fields so the refactor can't drift.
        assert_eq!(&body[24..28], &PIPE_DESIRED_ACCESS.to_le_bytes());
        assert_eq!(&body[36..40], &1u32.to_le_bytes()); // FILE_OPEN
        assert_eq!(&body[40..44], &[0u8; 4]); // CreateOptions = 0 (no NON_DIRECTORY)
        assert_eq!(name, b"s\0r\0v\0s\0v\0c\0");
    }

    // ── build_query_directory_body ──

    #[test]
    fn query_directory_body_lays_out_expected_bytes() {
        let file_id = [0x77u8; 16];
        let (body, pattern) = build_query_directory_body(&file_id, "*", true);

        assert_eq!(body.len(), 32, "fixed body must be exactly 32 bytes");
        assert_eq!(&body[0..2], &33u16.to_le_bytes()); // StructureSize
        assert_eq!(body[2], FILE_BOTH_DIRECTORY_INFORMATION);
        assert_eq!(
            body[3], SMB2_RESTART_SCANS,
            "first request must restart scan"
        );
        assert_eq!(&body[4..8], &[0u8; 4]); // FileIndex = 0
        assert_eq!(&body[8..24], &file_id);
        assert_eq!(&body[24..26], &96u16.to_le_bytes()); // FileNameOffset = 64+32
        assert_eq!(&body[26..28], &2u16.to_le_bytes()); // "*" = 1 code unit
        assert_eq!(&body[28..32], &QUERY_DIR_MAX_BUFFER.to_le_bytes());
        assert_eq!(pattern, b"*\0");
    }

    #[test]
    fn query_directory_body_continuation_clears_restart_flag() {
        let (body, _) = build_query_directory_body(&[0u8; 16], "*", false);
        assert_eq!(body[3], 0, "continuation must NOT restart the scan");
    }

    // ── parse_query_directory_response ──

    #[test]
    fn query_directory_response_extracts_output_buffer() {
        // 64-byte header + 8-byte fixed body, then a 4-byte output payload
        // at offset 72 (header + 8).
        let mut resp = vec![0u8; SMB2_HEADER_SIZE + 8 + 4];
        resp[0..4].copy_from_slice(SMB2_MAGIC);
        let body_off = SMB2_HEADER_SIZE;
        resp[body_off..body_off + 2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp[body_off + 2..body_off + 4].copy_from_slice(&72u16.to_le_bytes()); // OutputOffset
        resp[body_off + 4..body_off + 8].copy_from_slice(&4u32.to_le_bytes()); // OutputLength
        resp[72..76].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let out = parse_query_directory_response(&resp).expect("parse should succeed");
        assert_eq!(out, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn query_directory_response_rejects_short_and_out_of_bounds() {
        assert!(parse_query_directory_response(&[0u8; 16]).is_err());

        // Length pointing past the end of the packet.
        let mut resp = vec![0u8; SMB2_HEADER_SIZE + 8];
        resp[SMB2_HEADER_SIZE + 4..SMB2_HEADER_SIZE + 8].copy_from_slice(&100u32.to_le_bytes());
        assert!(parse_query_directory_response(&resp).is_err());
    }

    // ── parse_file_both_entries ──

    /// Build one FILE_BOTH_DIRECTORY_INFORMATION entry for tests.
    fn both_dir_entry(next_offset: u32, attrs: u32, size: u64, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut e = vec![0u8; FILE_BOTH_FIXED_SIZE];
        e[0..4].copy_from_slice(&next_offset.to_le_bytes());
        e[40..48].copy_from_slice(&size.to_le_bytes());
        e[56..60].copy_from_slice(&attrs.to_le_bytes());
        e[60..64].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        e.extend_from_slice(&name_utf16);
        e
    }

    #[test]
    fn file_both_entries_parses_a_chained_batch() {
        // NextEntryOffset is the distance from this entry's start to the
        // next one — with no inter-entry padding that's the entry's own
        // length (94-byte fixed part + UTF-16 name).
        let e2 = both_dir_entry(0, 0, 4242, "readme.txt");
        let e1 = both_dir_entry(106, FILE_ATTRIBUTE_DIRECTORY, 0, "folder");
        let mut buffer = both_dir_entry(96, FILE_ATTRIBUTE_DIRECTORY, 0, ".");
        buffer.extend_from_slice(&e1);
        buffer.extend_from_slice(&e2);

        let entries = parse_file_both_entries(&buffer).expect("parse should succeed");
        // "." is dropped; entries keep chain order.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "folder");
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].size, 0);
        assert_eq!(entries[1].name, "readme.txt");
        assert!(!entries[1].is_dir);
        assert_eq!(entries[1].size, 4242);
    }

    #[test]
    fn file_both_entries_drops_dot_dot() {
        let buffer = both_dir_entry(0, FILE_ATTRIBUTE_DIRECTORY, 0, "..");
        let entries = parse_file_both_entries(&buffer).expect("parse should succeed");
        assert!(entries.is_empty());
    }

    #[test]
    fn file_both_entries_rejects_truncation() {
        // Fixed part cut short.
        assert!(parse_file_both_entries(&[0u8; 10]).is_err());

        // Name length claims more bytes than the buffer carries.
        let mut e = vec![0u8; FILE_BOTH_FIXED_SIZE + 2];
        e[60..64].copy_from_slice(&64u32.to_le_bytes()); // name needs 64 bytes
        assert!(parse_file_both_entries(&e).is_err());
    }

    // ── build_set_info_disposition_body ──

    #[test]
    fn set_info_disposition_body_lays_out_expected_bytes() {
        let file_id = [0x55u8; 16];
        let body = build_set_info_disposition_body(&file_id);

        assert_eq!(body.len(), 32, "fixed body must be exactly 32 bytes");
        assert_eq!(&body[0..2], &33u16.to_le_bytes()); // StructureSize
        assert_eq!(body[2], SMB2_0_INFO_FILE); // InfoType = file
        assert_eq!(body[3], FILE_DISPOSITION_INFORMATION); // FileDispositionInformation
        assert_eq!(&body[4..8], &1u32.to_le_bytes()); // BufferLength = 1
        assert_eq!(&body[8..10], &96u16.to_le_bytes()); // BufferOffset = 64+32
        assert_eq!(&body[16..32], &file_id);
    }

    // ── create status mapping ──

    #[test]
    fn create_status_maps_to_caller_facing_variants() {
        assert!(matches!(
            map_create_status(STATUS_OBJECT_NAME_NOT_FOUND),
            SmbReadError::NotFound
        ));
        assert!(matches!(
            map_create_status(STATUS_OBJECT_PATH_NOT_FOUND),
            SmbReadError::NotFound
        ));
        assert!(matches!(
            map_create_status(STATUS_SHARING_VIOLATION),
            SmbReadError::SharingViolation
        ));
        assert!(matches!(
            map_create_status(STATUS_OBJECT_NAME_COLLISION),
            SmbReadError::NameCollision
        ));
        assert!(matches!(
            map_create_status(STATUS_ACCESS_DENIED),
            SmbReadError::AccessDenied
        ));
        assert!(matches!(
            map_create_status(0xC000_0001),
            SmbReadError::Other(0xC000_0001, _)
        ));
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;

    /// Build a synthetic 72-byte SMB2 request (64-byte header + 8-byte
    /// TREE_CONNECT-shaped body) with the exact field values used to pin
    /// the HMAC-SHA256 KAT below. Pre-sign Flags = 1, Signature = 0.
    fn kat_message() -> Vec<u8> {
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 8];
        msg[0..4].copy_from_slice(SMB2_MAGIC);
        msg[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        msg[6..8].copy_from_slice(&1u16.to_le_bytes()); // CreditCharge
        msg[12..14].copy_from_slice(&SMB2_TREE_CONNECT.to_le_bytes());
        msg[14..16].copy_from_slice(&31u16.to_le_bytes()); // CreditRequest
        msg[16..20].copy_from_slice(&1u32.to_le_bytes()); // Flags (pre-sign)
        msg[24..32].copy_from_slice(&3u64.to_le_bytes()); // MessageId
        msg[36..40].copy_from_slice(&0x8001u32.to_le_bytes()); // TreeId
        msg[40..48].copy_from_slice(&0x11223344u64.to_le_bytes()); // SessionId
        msg[64..72].copy_from_slice(&[9, 0, 0, 0, 0, 0, 0, 0]); // body
        msg
    }

    /// Known-answer test for the SMB 2.0.2/2.1 signing MAC, cross-checked
    /// against `python3 -c "import hmac,hashlib; hmac.new(key, msg,
    /// hashlib.sha256).digest()[:16]"` with the SIGNED flag set and the
    /// Signature field zeroed — the exact transformation Impacket's
    /// `smb3.py:signSMB` performs for pre-3.0 dialects.
    #[test]
    fn sign_message_kat() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut msg = kat_message();
        sign_smb2_message(&mut msg, &key).expect("signing should succeed");
        let expected = [
            0xe6, 0x78, 0xad, 0x82, 0xbf, 0x0b, 0x3a, 0x87, 0x73, 0x73, 0x1b, 0x91, 0x61, 0x89,
            0x6e, 0x01,
        ];
        assert_eq!(&msg[48..64], &expected, "signature mismatch");
    }

    #[test]
    fn sign_message_sets_flag_and_preserves_header() {
        let key = [0xABu8; 16];
        let original = kat_message();
        let mut msg = original.clone();
        sign_smb2_message(&mut msg, &key).expect("signing should succeed");

        // SIGNED flag flipped on.
        let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap());
        assert_eq!(flags, 1 | SMB2_FLAGS_SIGNED);
        // Signature non-zero and exactly 16 bytes.
        assert_ne!(&msg[48..64], &[0u8; 16]);
        // Everything else in the header — and the whole body — untouched.
        assert_eq!(&msg[0..16], &original[0..16]);
        assert_eq!(&msg[20..48], &original[20..48]);
        assert_eq!(&msg[64..], &original[64..]);
    }

    #[test]
    fn sign_message_rejects_short_input() {
        let key = [0u8; 16];
        let mut short = vec![0u8; 32];
        assert!(sign_smb2_message(&mut short, &key).is_err());
    }

    #[test]
    fn negotiate_signing_required_parses_security_mode() {
        // Minimal Negotiate response: 64-byte header + SecurityMode at
        // body offset 2 (StructureSize sits at 0..2).
        let make = |security_mode: u16| {
            let mut resp = vec![0u8; SMB2_HEADER_SIZE + 4];
            resp[0..4].copy_from_slice(SMB2_MAGIC);
            resp[SMB2_HEADER_SIZE..SMB2_HEADER_SIZE + 2].copy_from_slice(&65u16.to_le_bytes());
            resp[SMB2_HEADER_SIZE + 2..SMB2_HEADER_SIZE + 4]
                .copy_from_slice(&security_mode.to_le_bytes());
            resp
        };
        // 0x0002 = SIGNING_REQUIRED (domain controllers) → sign.
        assert!(negotiate_signing_required(&make(0x0002)).unwrap());
        // 0x0003 = required + enabled → sign.
        assert!(negotiate_signing_required(&make(0x0003)).unwrap());
        // 0x0001 = signing enabled but not required (Samba default) → don't.
        assert!(!negotiate_signing_required(&make(0x0001)).unwrap());
        // 0x0000 = neither → don't.
        assert!(!negotiate_signing_required(&make(0x0000)).unwrap());
        // Truncated response → error rather than a guess.
        assert!(negotiate_signing_required(&[0u8; 16]).is_err());
    }
}
