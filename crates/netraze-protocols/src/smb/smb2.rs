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

/// Error from a raw SMB2 file read.
#[derive(Debug, Clone)]
pub enum SmbReadError {
    NotFound,
    SharingViolation,
    Other(u32, String),
}

impl SmbReadError {
    pub fn as_str(&self) -> String {
        match self {
            SmbReadError::NotFound => "NOT_FOUND".into(),
            SmbReadError::SharingViolation => "SHARING_VIOLATION".into(),
            SmbReadError::Other(s, ctx) => format!("0x{s:08x} ({ctx})"),
        }
    }
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
        // Heuristic: IPv6 literals contain `:` too, but always come wrapped in
        // `[…]` when a port is attached. A bare `:` indicates "host already
        // has a port" — anything else gets the default 445 tacked on.
        let addr = if target.starts_with('[') || !target.contains(':') {
            format!("{target}:445")
        } else {
            target.to_owned()
        };
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

    /// SMB2 CREATE: open file for read, return (FileId, EndOfFile).
    fn create_open_read(
        &mut self,
        tree_id: u32,
        rel_path: &str,
    ) -> Result<([u8; 16], u64), SmbReadError> {
        let name_utf16: Vec<u8> = rel_path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let hdr = self.build_header(SMB2_CREATE, tree_id);

        // Body: StructureSize=57, then 55 more bytes + 1 byte variable
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        // body[2]: SecurityFlags=0
        // body[3]: RequestedOplockLevel=0
        body[4..8].copy_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel=Impersonation
        // body[8..16] SmbCreateFlags=0
        // body[16..24] Reserved=0
        // DesiredAccess: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        body[24..28].copy_from_slice(&0x0012_0089u32.to_le_bytes());
        // FileAttributes=0
        body[32..36].copy_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess RWD
        body[36..40].copy_from_slice(&1u32.to_le_bytes()); // CreateDisposition=FILE_OPEN
        body[40..44].copy_from_slice(&0x40u32.to_le_bytes()); // CreateOptions=FILE_NON_DIRECTORY_FILE

        let name_offset = if name_utf16.is_empty() {
            0u16
        } else {
            (SMB2_HEADER_SIZE + 56) as u16
        };
        body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        // CreateContextsOffset/Length = 0
        // body[48..52], body[52..56]

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        if name_utf16.is_empty() {
            packet.push(0); // 1-byte dummy buffer
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
            return Err(match status {
                STATUS_OBJECT_NAME_NOT_FOUND => SmbReadError::NotFound,
                STATUS_SHARING_VIOLATION => SmbReadError::SharingViolation,
                s => SmbReadError::Other(s, "create".into()),
            });
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
            return Err(format!("TreeConnect {share}: 0x{status:08x}"));
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
        let body = build_pipe_write_body(&handle.file_id, data.len() as u32);
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
    /// Sends a CREATE Request with `DesiredAccess = FILE_WRITE_DATA` for a
    /// non-existent probe filename (caller picks the random suffix). The
    /// server checks ACLs **before** checking that the file exists, so:
    ///
    /// - `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034) → write would be granted
    ///   if the file existed → `Ok(true)`. This is the canonical "writable"
    ///   signal; we never actually create or modify anything.
    /// - `STATUS_OBJECT_PATH_NOT_FOUND` (0xC000003A) → same idea, just a
    ///   different leaf-vs-parent code path inside the server.
    /// - `STATUS_ACCESS_DENIED` (0xC0000022) → server refused at the ACL
    ///   check → `Ok(false)`. Read-only.
    /// - `STATUS_SUCCESS` → file actually existed (collision on the random
    ///   probe name); we close the handle and report `Ok(true)`.
    /// - Any other status is propagated as `Err` so the caller can log /
    ///   classify it; the share-access detection layer maps Err→Read as a
    ///   safe default.
    ///
    /// Mirrors `check_share_access` in the Windows-native `shares.rs` but
    /// runs identically on every OS via raw SMB2.
    pub fn probe_write(&mut self, tree_id: u32, rel_path: &str) -> Result<bool, String> {
        let name_utf16: Vec<u8> = rel_path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let hdr = self.build_header(SMB2_CREATE, tree_id);

        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[4..8].copy_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel=Impersonation
        // DesiredAccess = FILE_WRITE_DATA (0x02). The whole point of the
        // probe is to ask the server "would you give me write?" — anything
        // beyond that bit risks tripping unrelated ACL checks.
        body[24..28].copy_from_slice(&0x0000_0002u32.to_le_bytes());
        body[32..36].copy_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess RWD
        body[36..40].copy_from_slice(&1u32.to_le_bytes()); // CreateDisposition=FILE_OPEN
        body[40..44].copy_from_slice(&0x40u32.to_le_bytes()); // CreateOptions=FILE_NON_DIRECTORY_FILE

        let name_offset = if name_utf16.is_empty() {
            0u16
        } else {
            (SMB2_HEADER_SIZE + 56) as u16
        };
        body[44..46].copy_from_slice(&name_offset.to_le_bytes());
        body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());

        let mut packet = Vec::new();
        packet.extend_from_slice(&hdr);
        packet.extend_from_slice(&body);
        if name_utf16.is_empty() {
            packet.push(0);
        } else {
            packet.extend_from_slice(&name_utf16);
        }

        self.send_packet(&packet)?;
        let resp = self.recv_packet()?;

        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
        match status {
            STATUS_SUCCESS => {
                // File actually existed — close the handle we just got.
                if resp.len() >= SMB2_HEADER_SIZE + 88 {
                    let body_off = SMB2_HEADER_SIZE;
                    let mut fid = [0u8; 16];
                    fid.copy_from_slice(&resp[body_off + 64..body_off + 80]);
                    let _ = self.close_file(tree_id, &fid);
                }
                Ok(true)
            }
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => Ok(true),
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

    fn send_packet(&mut self, data: &[u8]) -> Result<(), String> {
        let len = data.len() as u32;
        let nb = [0u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        self.stream
            .write_all(&nb)
            .and_then(|_| self.stream.write_all(data))
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

// ─────────────────────────── Pipe helpers ───────────────────────────
//
// Pure functions — no `&self`, no IO — so we can unit-test the wire layouts
// without a TcpStream. The `pipe_*` methods on `Smb2Session` are thin
// orchestration wrappers around these.

/// Build the fixed 56-byte CREATE Request body for opening a named pipe.
/// `name` is the bare leaf (`"srvsvc"`, `"samr"`, …) — no leading backslash.
/// Returns `(body, name_utf16)` so the caller can append the name buffer
/// after the body when assembling the full SMB2 packet.
fn build_pipe_create_body(name: &str) -> (Vec<u8>, Vec<u8>) {
    let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut body = vec![0u8; 56];
    body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
    // body[2]      SecurityFlags=0
    // body[3]      RequestedOplockLevel=0 (no oplock for pipes)
    body[4..8].copy_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel=Impersonation
    // body[8..16]  SmbCreateFlags=0
    // body[16..24] Reserved=0
    body[24..28].copy_from_slice(&PIPE_DESIRED_ACCESS.to_le_bytes());
    // body[28..32] FileAttributes=0
    body[32..36].copy_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess: R|W|D
    body[36..40].copy_from_slice(&1u32.to_le_bytes()); // CreateDisposition=FILE_OPEN
    // body[40..44] CreateOptions=0  — pipes must NOT set FILE_NON_DIRECTORY_FILE
    let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
    body[44..46].copy_from_slice(&name_offset.to_le_bytes());
    body[46..48].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    // body[48..52] CreateContextsOffset=0
    // body[52..56] CreateContextsLength=0

    (body, name_utf16)
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

/// Build the fixed 48-byte WRITE Request body for a pipe handle. The
/// caller appends the payload bytes after this body.
///
/// Layout per MS-SMB2 §2.2.21:
///   - StructureSize = 49 (0x31), the "fixed body + 1" sentinel
///   - DataOffset    = SMB2_HEADER_SIZE + 48 — payload starts right after body
///   - Length        = `data_len`
///   - Offset        = 0 (pipes ignore this field)
///   - FileId        = 16 bytes
///   - Channel/RemainingBytes/WriteChannelInfo*/Flags = 0
fn build_pipe_write_body(file_id: &[u8; 16], data_len: u32) -> Vec<u8> {
    let mut body = vec![0u8; 48];
    body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
    let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
    body[2..4].copy_from_slice(&data_offset.to_le_bytes()); // DataOffset
    body[4..8].copy_from_slice(&data_len.to_le_bytes()); // Length
    // body[8..16]   Offset = 0 (pipe)
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
        let body = build_pipe_write_body(&file_id, 64);

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
