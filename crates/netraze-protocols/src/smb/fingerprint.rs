//! SMB host fingerprinting via raw SMB2 negotiate + NTLMSSP challenge.
//!
//! Extracts: hostname, domain, OS version/build, signing requirement, dialect.
//! Does NOT require authentication — only the first round of session setup.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::ntlm;

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const SMB2_HEADER_SIZE: usize = 64;

#[derive(Debug, Clone)]
pub struct SmbFingerprint {
    pub hostname: String,
    pub domain: String,
    pub dns_hostname: String,
    pub dns_domain: String,
    pub os_info: String,
    pub os_major: u8,
    pub os_minor: u8,
    pub os_build: u16,
    pub signing: bool,
    pub smbv1: bool,
    pub dialect: u16,
}

impl SmbFingerprint {
    /// Format like NXC: "Windows Server 2022 Build 20348 x64 (name:DC01) (domain:keystone.local) (signing:True) (SMBv1:False)"
    pub fn nxc_line(&self, ip: &str) -> String {
        let signing = if self.signing { "True" } else { "False" };
        let smbv1 = if self.smbv1 { "True" } else { "False" };
        format!(
            "SMB  {ip:<16} 445    {:<16} [*] {} (name:{}) (domain:{}) (signing:{signing}) (SMBv1:{smbv1})",
            self.hostname,
            self.os_info,
            self.hostname,
            if self.dns_domain.is_empty() {
                &self.domain
            } else {
                &self.dns_domain
            },
        )
    }
}

/// Perform SMB fingerprinting on a target (no authentication needed).
pub fn fingerprint(target: &str) -> Result<SmbFingerprint, String> {
    let addr = format!("{target}:445");
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolve failed: {e}"))?
        .next()
        .ok_or("No address resolved")?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))
        .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // ── Step 1: SMB2 Negotiate ──
    let neg_resp = smb2_negotiate(&mut stream)?;

    // ── Step 2: Session Setup Round 1 (NTLMSSP Negotiate only) ──
    let challenge = ntlmssp_round1(&mut stream, neg_resp.session_id)?;

    // ── Step 3: Extract info from AV_PAIRs ──
    let hostname = av_pair_string(&challenge.target_info, 0x0001); // MsvAvNbComputerName
    let domain = av_pair_string(&challenge.target_info, 0x0002); // MsvAvNbDomainName
    let dns_hostname = av_pair_string(&challenge.target_info, 0x0003); // MsvAvDnsComputerName
    let dns_domain = av_pair_string(&challenge.target_info, 0x0004); // MsvAvDnsDomainName

    // ── Step 4: OS version from NTLM Version field ──
    let (os_major, os_minor, os_build) = challenge.version.unwrap_or((0, 0, 0));
    let os_info = build_os_string(os_major, os_minor, os_build);

    // ── Step 5: SMBv1 check (separate connection) ──
    let smbv1 = check_smbv1(target);

    // Clean up — send a logoff to be polite (ignore errors)
    let _ = stream.shutdown(std::net::Shutdown::Both);

    Ok(SmbFingerprint {
        hostname,
        domain,
        dns_hostname,
        dns_domain,
        os_info,
        os_major,
        os_minor,
        os_build,
        signing: neg_resp.signing_required,
        smbv1,
        dialect: neg_resp.dialect,
    })
}

// ── Internal structures ──

struct NegotiateResult {
    dialect: u16,
    signing_required: bool,
    session_id: u64,
}

fn smb2_negotiate(stream: &mut TcpStream) -> Result<NegotiateResult, String> {
    let dialects: &[u16] = &[0x0202, 0x0210, 0x0300, 0x0302];
    let mut hdr = vec![0u8; SMB2_HEADER_SIZE];
    hdr[0..4].copy_from_slice(SMB2_MAGIC);
    hdr[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    hdr[6..8].copy_from_slice(&1u16.to_le_bytes()); // CreditCharge
    // Command = NEGOTIATE (0)
    hdr[14..16].copy_from_slice(&31u16.to_le_bytes()); // CreditRequest

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

    send_packet(stream, &packet)?;
    let resp = recv_packet(stream)?;

    let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
    if status != 0 {
        return Err(format!("Negotiate failed: 0x{status:08x}"));
    }
    if resp.len() < SMB2_HEADER_SIZE + 65 {
        return Err("Negotiate response too short".into());
    }

    let resp_body = &resp[SMB2_HEADER_SIZE..];
    let security_mode = u16::from_le_bytes(resp_body[2..4].try_into().unwrap());
    let dialect = u16::from_le_bytes(resp_body[4..6].try_into().unwrap());
    let session_id = u64::from_le_bytes(resp[40..48].try_into().unwrap());

    Ok(NegotiateResult {
        dialect,
        signing_required: (security_mode & 0x02) != 0,
        session_id,
    })
}

fn ntlmssp_round1(
    stream: &mut TcpStream,
    _negotiate_session_id: u64,
) -> Result<ntlm::ChallengeMessage, String> {
    let negotiate_msg = ntlm::build_negotiate();
    let spnego = ntlm::wrap_spnego_init(&negotiate_msg);

    // Build Session Setup request
    let mut hdr = vec![0u8; SMB2_HEADER_SIZE];
    hdr[0..4].copy_from_slice(SMB2_MAGIC);
    hdr[4..6].copy_from_slice(&64u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&1u16.to_le_bytes());
    hdr[12..14].copy_from_slice(&1u16.to_le_bytes()); // Command = SESSION_SETUP
    hdr[14..16].copy_from_slice(&31u16.to_le_bytes());
    hdr[24..32].copy_from_slice(&1u64.to_le_bytes()); // MessageId = 1

    let sec_offset = (SMB2_HEADER_SIZE + 24) as u16;
    let mut body = vec![0u8; 24];
    body[0..2].copy_from_slice(&25u16.to_le_bytes()); // StructureSize
    body[3] = 1; // SecurityMode: signing enabled
    body[12..14].copy_from_slice(&sec_offset.to_le_bytes());
    body[14..16].copy_from_slice(&(spnego.len() as u16).to_le_bytes());

    let mut packet = Vec::new();
    packet.extend_from_slice(&hdr);
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&spnego);

    send_packet(stream, &packet)?;
    let resp = recv_packet(stream)?;

    let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
    // STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) is expected
    if status != 0xC0000016 {
        return Err(format!(
            "Session Setup round 1 unexpected status: 0x{status:08x}"
        ));
    }

    // Extract NTLMSSP challenge from SPNEGO
    let resp_body = &resp[SMB2_HEADER_SIZE..];
    let sec_off = u16::from_le_bytes(resp_body[4..6].try_into().unwrap()) as usize;
    let sec_len = u16::from_le_bytes(resp_body[6..8].try_into().unwrap()) as usize;

    if sec_off + sec_len > resp.len() {
        return Err("Security buffer out of bounds".into());
    }
    let spnego_data = &resp[sec_off..sec_off + sec_len];

    let challenge_data =
        ntlm::extract_ntlmssp(spnego_data).ok_or("No NTLMSSP in server challenge response")?;
    ntlm::parse_challenge(challenge_data)
}

/// Extract a UTF-16LE AV_PAIR as a String.
fn av_pair_string(target_info: &[u8], av_id: u16) -> String {
    ntlm::extract_av_pair(target_info, av_id)
        .map(|bytes| {
            let utf16: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&utf16)
        })
        .unwrap_or_default()
}

/// Build a human-readable OS string from NTLM version fields.
fn build_os_string(major: u8, minor: u8, build: u16) -> String {
    let name = match (major, minor, build) {
        (10, 0, b) if b >= 20348 => "Windows Server 2022",
        (10, 0, b) if b >= 17763 => "Windows Server 2019",
        (10, 0, b) if b >= 14393 => "Windows Server 2016",
        (10, 0, _) => "Windows 10/11",
        (6, 3, _) => "Windows Server 2012 R2",
        (6, 2, _) => "Windows Server 2012",
        (6, 1, _) => "Windows Server 2008 R2",
        (6, 0, _) => "Windows Server 2008",
        (5, 2, _) => "Windows Server 2003",
        (5, 1, _) => "Windows XP",
        _ if major == 0 && build == 0 => return "Unknown".to_string(),
        _ => "Windows",
    };
    if build > 0 {
        format!("{name} Build {build}")
    } else {
        name.to_string()
    }
}

/// Quick SMBv1 check: send an SMB1 Negotiate with "NT LM 0.12" dialect.
fn check_smbv1(target: &str) -> bool {
    let addr = format!("{target}:445");
    let sock_addr = match addr.to_socket_addrs() {
        Ok(mut a) => match a.next() {
            Some(s) => s,
            None => return false,
        },
        Err(_) => return false,
    };

    let mut stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(3))).ok();

    // SMB1 Negotiate Protocol Request
    // Header: 32 bytes, then dialect string
    let dialect = b"\x02NT LM 0.12\x00"; // dialect format: 0x02 + name + null

    let mut smb1_hdr = vec![0u8; 32];
    smb1_hdr[0..4].copy_from_slice(b"\xffSMB"); // SMB1 magic
    smb1_hdr[4] = 0x72; // COM_NEGOTIATE
    // Flags
    smb1_hdr[13] = 0x18; // Flags2 low byte (Unicode, NT Status)
    smb1_hdr[14] = 0xc8; // Flags2 high byte (Extended Security)

    // Parameter words: 0 words for negotiate
    let word_count: u8 = 0;
    let byte_count = dialect.len() as u16;

    let mut payload = Vec::new();
    payload.extend_from_slice(&smb1_hdr);
    payload.push(word_count);
    payload.extend_from_slice(&byte_count.to_le_bytes());
    payload.extend_from_slice(dialect);

    if send_packet(&mut stream, &payload).is_err() {
        return false;
    }

    match recv_packet(&mut stream) {
        Ok(resp) => {
            // Check if response is SMB1 (magic = \xffSMB) and not an error
            resp.len() >= 4 && &resp[0..4] == b"\xffSMB"
        }
        Err(_) => false,
    }
}

fn send_packet(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    let nb = [0u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    stream
        .write_all(&nb)
        .and_then(|_| stream.write_all(data))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("Send failed: {e}"))
}

fn recv_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut nb = [0u8; 4];
    stream
        .read_exact(&mut nb)
        .map_err(|e| format!("Recv header failed: {e}"))?;
    let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | (nb[3] as usize);
    if len > 1024 * 1024 {
        return Err("Response too large".into());
    }
    let mut data = vec![0u8; len];
    stream
        .read_exact(&mut data)
        .map_err(|e| format!("Recv data failed: {e}"))?;
    Ok(data)
}
