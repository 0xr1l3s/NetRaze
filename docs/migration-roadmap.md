# Roadmap

This file documents two parallel tracks:

1. **Structural roadmap** — workspace shape, crate splits, plugin API,
   storage, exports. The "what does the project look like" axis.
2. **Cross-platform portage plan** — moving the SMB post-exploitation
   modules off Windows-native APIs (SCM / WNet / NetAPI / Registry) onto
   the pure-Rust SMB2 + DCE/RPC stack so Linux becomes a full
   first-class attacker OS. The "what runs where" axis.

The two tracks progress independently. Code comments in
`crates/netraze-protocols/src/smb/` reference the portage plan as
"Phase 1–6"; this file is the authoritative source for what those phases
mean.

---

# Structural roadmap

## Phase 1 — Core types and skeleton (done)

- Stabilise `netraze-core` contracts (`ProtocolMetadata`,
  `ModuleMetadata`, `ScanRequest`, `Capability`, error types).
- Formalise config, targets, output, runtime.
- Keep the CLI thin and testable.

## Phase 2 — Per-protocol crates and real storage

- Split `netraze-protocols` into per-protocol crates:
  - `netraze-protocol-smb`
  - `netraze-protocol-ldap`
  - `netraze-protocol-winrm`
  - `netraze-protocol-ssh`
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
- Protocol-specific dependencies stay isolated inside the protocol crate.
- Campaign / workflow features stay above the core, never inside it.

---

# Cross-platform portage plan

## Why this plan exists

NetRaze inherits two implementation strategies for SMB post-exploitation
features that need to converge:

| Strategy | What it is | Where it lives | Portability |
|---|---|---|---|
| Windows-native | Calls `windows` crate against local Win32 APIs (SCM, WNet, NetAPI, Registry) — ergonomic, fast to implement, but only runs from a Windows attacker. | `crates/netraze-protocols/src/smb/{connection,browser,shares,info,users,dump,enum_av,exec}.rs` | Windows attacker only |
| Pure-Rust SMB2 + DCE/RPC | Talks SMB2 / NTLMSSP / DCE-RPC over a raw TCP socket — slower to implement (requires reimplementing each MS-SRVS / SAMR / SVCCTL / WKSSVC interface) but works from any OS. | `crates/netraze-protocols/src/smb/{smb2,ntlm,crypto,sam,hive,fingerprint}.rs` and `crates/netraze-dcerpc/` | Any attacker OS |

The portage plan is the migration path from the first strategy to the
second. Until it completes, the Linux build provides API-compatible
stubs that return a `NOT_PORTED` error so the rest of the workspace
compiles and the Windows path stays usable.

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

## Phase 3 — `FSCTL_PIPE_TRANSCEIVE` (next, blocking)

- Add SMB2 IOCTL to `smb/smb2.rs`.
- Implement `FSCTL_PIPE_TRANSCEIVE` so DCE/RPC PDUs can ride over an
  SMB named pipe (`\PIPE\srvsvc`, `\PIPE\samr`, `\PIPE\svcctl`,
  `\PIPE\wkssvc`).
- Smoke test: drive a real `NetrShareEnum` against the Samba container
  end-to-end through this transport.

This phase is the single biggest unlock: it makes every subsequent
module portable for free.

## Phase 4 — Port the read-only enumeration modules

Replace the Windows-native impl in each of these with a pure-Rust call
through the new pipe transport:

- `info` — `WKSSVC.NetrWkstaGetInfo` (replace `NetWkstaGetInfo` Win32).
- `shares` — `SRVSVC.NetrShareEnum` (replace `WNetEnumResource` Win32);
  encoder/decoder already exist in `netraze-dcerpc`.
- `users` — `SAMR.SamrEnumerateUsersInDomain` (replace local SAMR
  ergonomics).

These are read-only and the lowest-risk to port first.

## Phase 5 — Port the write-side modules (exec, file transfer)

- `exec` — port smbexec from local SCM to `SVCCTL.RCreateServiceW` +
  `SVCCTL.RStartServiceW` over a remote pipe. Add atexec
  (`ATSVC.NetrJobAdd`) and wmiexec (`IWbemServices.ExecMethod` over
  DCOM) as alternative execution methods.
- `browser` — port file transfer from `WNetAddConnection2` to SMB2 tree
  connect on the actual share + `CREATE` / `READ` / `WRITE` /
  `IOCTL_PIPE_TRANSCEIVE` against the file pipe.

Higher risk because writes can damage the target or leave artifacts.
Each port needs a Samba-based integration test.

## Phase 6 — Port secret-dumping (dump)

- SAM / LSA secrets — port from `RemoteRegistry` + Win32 hive APIs to
  `WINREG.OpenLocalMachine` over RPC + the existing pure-Rust hive
  parser in `smb/hive.rs` and `smb/sam.rs`.
- DPAPI / DCSync / NTDS extraction — Phase 6+, larger scope.

## Phase 7 — Retire the Windows-native code path

Once every module has a pure-Rust implementation that passes the
Samba integration suite, delete the `#[cfg(windows)]` arms in
`smb/mod.rs` and the corresponding native files. The stubs become the
single implementation. Linux is then strictly equivalent to Windows as
an attacker OS.

## Validation gate per phase

Every phase ports a module by:

1. Generating Impacket byte fixtures for the target RPC interface
   (pattern: `crates/netraze-dcerpc/tests/gen_*.py`).
2. Adding round-trip encoder/decoder tests pinned to those fixtures.
3. Adding a Samba integration test that exercises the new module
   end-to-end against the test container.
4. Removing the `NOT_PORTED` stub for that module on `not(windows)` and
   wiring the pure-Rust impl on every target.
5. Confirming the existing Windows-native impl still passes its tests
   (parallel implementations during migration), then deleting it once
   the pure-Rust path is proven.
