# Roadmap

This file documents two parallel tracks:

1. **Structural roadmap** — workspace shape, deep protocol modules, plugin API,
   storage, exports. The "what does the project look like" axis.
2. **Cross-platform portage plan** — moving the SMB post-exploitation
   modules off Windows-native APIs (SCM / WNet / NetAPI / Registry) onto
   the pure-Rust SMB2 + DCE/RPC stack so Linux becomes a full
   first-class attacker OS. The "what runs where" axis. **This track is
   complete.**

Code comments in `crates/netraze-protocols/src/smb/` reference the
portage plan as "Phase 1–7"; this file is the authoritative source for
what those phases mean.

---

# Structural roadmap

## Phase 1 — Core types and skeleton (done)

- Stabilise `netraze-core` contracts (`ProtocolMetadata`,
  `ModuleMetadata`, `ScanRequest`, `Capability`, error types).
- Formalise config, targets, output, runtime.
- Keep the CLI thin and testable.

## Phase 2 — Deep protocol modules and real storage

- Keep wire implementations under focused modules in `netraze-protocols`:
  - `netraze_protocols::smb`
  - `netraze_protocols::ldap`
  - `netraze_protocols::winrm`
  - `netraze_protocols::ssh`
- Wire a real SQLite backend into `netraze-storage`.

## Phase 3 — Plugin API, exports, module parity

- Stable plugin API for external modules.
- JSON / CSV export, richer observability.
- Port the highest-leverage NetExec modules per category.

## Phase 4 — Integration and operator-facing surface

- Per-protocol integration test suites.
- Network fixtures and regression harnesses.
- TUI or machine-friendly API.

## Evolution rules

- Shared logic ratchets up to `netraze-core` or a transversal crate.
- Protocol-specific dependencies stay isolated inside `netraze-protocols`.
- Campaign / workflow features stay above the core, never inside it.

---

# Cross-platform portage plan (complete)

## Why this plan existed

NetRaze inherited two implementation strategies for SMB post-exploitation
features that needed to converge:

| Strategy | What it was | Portability |
|---|---|---|
| Windows-native | Calls `windows` crate against local Win32 APIs (SCM, WNet, NetAPI, Registry) — ergonomic, fast to implement, but only runs from a Windows attacker. | Windows attacker only |
| Pure-Rust SMB2 + DCE/RPC | Talks SMB2 / NTLMSSP / DCE-RPC over a raw TCP socket — slower to implement (requires reimplementing each MS-SRVS / SAMR / SVCCTL / WKSSVC interface) but works from any OS. | Any attacker OS |

The portage plan was the migration path from the first strategy to the
second. It is finished: the Windows-native files and the `smb/stubs/`
`NOT_PORTED` stubs are deleted, the `windows` crate is no longer a
dependency of `netraze-protocols`, and a single pure-Rust implementation
serves every attacker OS.

## Phase 1 — Pure-Rust SMB2 wire foundation (done)

- SMB2 Negotiate + NTLMSSP NTLMv2 + TreeConnect implemented in
  `smb/smb2.rs` and `smb/ntlm.rs`.
- Validated end-to-end against a pinned Samba container (see
  `tests/samba/`).

## Phase 2 — DCE/RPC primitives (done)

- NDR20 reader/writer with deferred-pointer walker.
- MS-RPCE PDU framing.
- NTLMSSP auth verifier with seal/unseal.
- MS-SRVS `NetrShareEnum` validated byte-for-byte against
  Impacket-generated fixtures.

## Phase 3 — `FSCTL_PIPE_TRANSCEIVE` (done)

- SMB2 IOCTL in `smb/smb2.rs`; `FSCTL_PIPE_TRANSCEIVE` carries DCE/RPC
  PDUs over SMB named pipes (`\PIPE\srvsvc`, `\PIPE\samr`,
  `\PIPE\svcctl`, `\PIPE\winreg`) via `rpc::SmbPipeTransport`.
- Verified end-to-end with a real `NetrShareEnum` against the Samba
  container through this transport.

## Phase 4 — Port the read-only enumeration modules (done)

- `info` — `SRVSVC.NetrServerGetInfo`.
- `shares` — `SRVSVC.NetrShareEnum` + per-share access classification
  and ADMIN$ detection.
- `users` — `SAMR.SamrConnect2` → domain enum → `SamrEnumerateUsersInDomain`.

## Phase 5 — Port the write-side modules (exec, file transfer) (done)

- `exec` — smbexec via `SVCCTL.RCreateServiceW` + `RStartServiceW` over
  a remote pipe, with service cleanup.
- `browser` — SMB2 tree connect on the actual share + `CREATE` / `READ` /
  `WRITE` / `QUERY_DIRECTORY` / create/delete directory.

## Phase 6 — Port secret-dumping (dump) (done)

- SAM / LSA secrets via `WINREG.OpenLocalMachine` over RPC + the
  pure-Rust hive parser in `smb/hive.rs` and `smb/sam.rs`; the SCMR
  interface auto-starts RemoteRegistry when needed.
- DPAPI / DCSync / NTDS extraction — still future work (drsuapi), see
  `protocol-stack-plan.md`.

## Phase 7 — Retire the Windows-native code path (done)

Every module passes the Samba integration suite on the pure-Rust path;
the `#[cfg(windows)]` arms, the native files, and the stubs are deleted.
Linux is strictly equivalent to Windows as an attacker OS.

## Post-portage follow-ups (done)

- **Anonymous + guest access** — credential-shape dispatch (empty
  username → null session, username without secret → guest) across
  `connect_session` / `SmbClient::connect`, strict downgrade rejection
  preserved for secret-carrying credentials, guest/null sessions riding
  unauthenticated DCE binds (Impacket parity), desktop UI support
  (anonymous login entry, GUEST-badged secret-less credentials, CSV
  import). Covered by the `anonymous_samba` suite.
- **SMB signing** (HMAC-SHA256, dialects 2.0.2/2.1) — applied when the
  server's Negotiate SecurityMode demands it; validated against live
  signing-required hosts.
- **Release workflow** — tag-driven Linux + Windows desktop binaries
  (`.github/workflows/release.yml`).

## Validation gate per phase

Every phase ported a module by:

1. Generating Impacket byte fixtures for the target RPC interface
   (pattern: `crates/netraze-dcerpc/tests/gen_*.py`).
2. Adding round-trip encoder/decoder tests pinned to those fixtures.
3. Adding a Samba integration test that exercises the new module
   end-to-end against the test container.
4. Cross-checking the resulting behaviour against Impacket against the
   same harness before landing it.
