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

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_MORE_PROCESSING: u32 = 0xC0000016;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC0000034;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC0000043;
pub const STATUS_END_OF_FILE: u32 = 0xC0000011;

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

/// A minimal raw SMB2 session for pass-the-hash authentication.
pub struct Smb2Session {
    stream: TcpStream,
    session_id: u64,
    message_id: u64,
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
        let auth_msg = ntlm::build_authenticate(&auth, username, domain, challenge.negotiate_flags);
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
