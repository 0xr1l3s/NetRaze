# NetRaze

[![Release](https://github.com/Ah4ds/NetRaze/actions/workflows/release.yml/badge.svg)](https://github.com/Ah4ds/NetRaze/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](#license)
[![Rust Edition](https://img.shields.io/badge/rust-2024%20edition%20%28MSRV%201.85%29-orange)](rust-toolchain.toml)
[![Status](https://img.shields.io/badge/status-alpha%20%E2%80%94%20SMB%20%2B%20LDAP-yellow)](#current-status)

**NetRaze** is an offensive network-execution toolkit, rewritten from scratch
in pure Rust. It is the spiritual successor to the NetExec / CrackMapExec
lineage — same workflow (enumerate, authenticate, execute, post-exploit),
but with a memory-safe backend, native binaries, and a built-in
desktop workflow graph.

This repository is the **active port**. The mature Python reference
([NetExec](https://github.com/Pennyw0rth/NetExec)) lives alongside it in the
sibling directory and remains the tool you should use for real engagements
while the Rust port catches up.

---

## Table of contents

- [Why NetRaze](#why-netraze)
- [Current status](#current-status)
- [What's inside](#whats-inside)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Desktop GUI](#desktop-gui)
- [Architecture](#architecture)
- [Development](#development)
- [Validation methodology](#validation-methodology)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Related projects](#related-projects)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Legal disclaimer](#legal-disclaimer)

---

## Why NetRaze

NetExec and Impacket are the de-facto standard for Windows network
post-exploitation, and they are excellent. The Python stack has two
long-term pain points that get worse as the tool grows:

1. **Cold-start latency.** A Python import chain of ~200 modules means every
   `nxc` invocation pays 400–800 ms before the first packet goes out.
   Disruptive during iteration on large target sets.
2. **Packaging and deployment.** Operator laptops, red-team C2 relays, and
   CI runners all want a self-contained application binary. A Python
   tree with native extensions (Impacket, pycryptodome, LDAP3) is hostile
   to that.

NetRaze keeps the NetExec model — protocol handlers, post-auth modules,
workspace-per-engagement — and rebases it on:

- **Pure Rust wire code.** No FFI bindings to Impacket or Samba. The
  DCE/RPC NDR walker, NTLMSSP, and SMB2 framing are re-implemented and
  validated byte-for-byte against Impacket-generated fixtures.
- **Single-binary applications.** `cargo build --release` produces one
  executable per binary crate; static linking is not the default build mode.
- **Async I/O from the ground up.** `tokio` across the board, not retrofitted
  onto a synchronous Python core.
- **Desktop workflow graph.** An `egui`/`egui-snarl` canvas for composing
  offensive workflows visually, complementing the headless CLI.

## Current status

NetRaze is **alpha**. The SMB/DCE-RPC post-exploitation stack is fully
ported to pure Rust and behaves identically from Linux and Windows
attackers — the cross-platform portage (Phases 1–7 of the portage plan)
is complete, and the `windows` crate is no longer a dependency of any
protocol crate.

### SMB capability matrix

Every capability below is **pure Rust** — SMB2/DCE-RPC over raw TCP —
and works from any attacker OS.

| Capability | Implementation |
|---|---|
| SMB2 Negotiate + NTLMv2 Session Setup + Tree Connect | `smb2`, `ntlm` |
| Anonymous (null session) access | `connect_anonymous` — empty AUTHENTICATE, IS_NULL accepted |
| Guest access (username, no secret) | `connect_guest` — rides the server's map-to-guest policy |
| Pass-the-hash authentication | NTLMv2 with a supplied NT hash |
| SMB signing (HMAC-SHA256, dialects 2.0.2/2.1) | applied in `smb2::send_packet` when the server demands it |
| Host fingerprinting | `fingerprint` |
| Share enumeration (SRVSVC `NetrShareEnum`) | `shares_rpc` |
| User enumeration (SAMR) | `users_rpc` |
| Server info (SRVSVC `NetrServerGetInfo`) | `info_rpc` |
| SAM / LSA secret dump (WINREG + hive parse) | `dump_rpc`, `sam`, `hive` |
| AV product enumeration (SCMR + IPC$ pipe listing) | `enum_av` |
| Remote command execution (smbexec via SVCCTL) | `exec_rpc` |
| Browser / file transfer on shares (SMB2 file ops) | `browser_rpc` |
| DCE/RPC over named pipes (`FSCTL_PIPE_TRANSCEIVE`) | `rpc::SmbPipeTransport` |

Anonymous and guest access is expressed by **credential shape**: an
empty username means a null session, a username without a secret means
guest. Secret-carrying credentials stay strict — a wrong password is
rejected even when the server would downgrade the session to guest.
Guest and null sessions ride an unauthenticated DCE bind over the SMB
session (exactly how Impacket drives them), so share and user
enumeration work in both modes.

### Other protocols

| Protocol | State |
|---|---|
| LDAP | Port 389; NTLMv2 SASL/SPNEGO sign-and-seal (password or NT hash), anonymous bind, RootDSE, paged read-only AD inventory (users, groups, computers, OUs, topology, privileged principals, SPNs, and reported security policy), plus BloodHound Community Edition schema-v6 JSON/ZIP export. |
| WinRM, MSSQL, SSH, RDP, FTP, NFS, VNC, WMI | Scaffold only — factory registered, no wire code yet |

### DCE/RPC stack (`netraze-dcerpc`)

- NDR20 reader/writer with BFS deferred-pointer walker (conformant arrays,
  unique/ref pointers, unions with pointer arms)
- MS-RPCE PDU framing (Bind, BindAck, Auth3, Request, Response, Fault)
- NTLMSSP auth verifier including seal/unseal (RC4 + HMAC-MD5 v2)
- Interfaces: SRVSVC, SAMR, WINREG, SCMR — each validated against
  Impacket-generated byte fixtures

### What's next

- Kerberos / AES-based authentication (only NTLMv2 today).
- SMB3 encryption (AES-CCM/GCM) — most targets still accept unencrypted
  SMB2.
- LDAP follow-ups — ACL/security-descriptor collection and active checks for
  settings currently shown as `Not tested` in the desktop Security tab.
- Relay attacks, coercion (PetitPotam, PrinterBug), ADCS abuse, DCSync
  (see `docs/protocol-stack-plan.md`).

## What's inside

This is a Cargo workspace of 14 crates. The hard rule: **`netraze-core`
depends on nothing applicative; `netraze-cli` contains no protocol
logic**. Everything else flows from those two constraints.

| Crate | Purpose |
|---|---|
| `netraze-core` | Domain contracts: `ProtocolMetadata`, `ModuleMetadata`, `ScanRequest`, `Capability`, error types. |
| `netraze-app` | Composition root. `NetRazeApp::bootstrap()` wires registries and services. |
| `netraze-cli` | Thin CLI binary (`clap`). Maps arguments to use-cases. |
| `netraze-desktop` | `egui`/`eframe` GUI with `egui-snarl` workflow graph and `egui_graphs` network view. |
| `netraze-protocols` | Wire-level protocol handlers, including the implemented SMB and LDAP modules. |
| `netraze-dcerpc` | MS-RPCE stack: NDR, PDU, NTLMSSP auth; SRVSVC, SAMR, WINREG, SCMR interfaces. |
| `netraze-modules` | Post-exploitation modules organised by category (`active_directory`, `credentials`, `reconnaissance`). |
| `netraze-auth` | Credential types and authentication methods. |
| `netraze-targets` | Target parsing and normalisation. |
| `netraze-config` | `AppConfig`, `WorkspaceConfig`, `RuntimeConfig`. |
| `netraze-storage` | `WorkspaceStore` trait with an in-memory implementation (SQLite backend planned). |
| `netraze-output` | Console reporting, output events. |
| `netraze-runtime` | Concurrency, timeouts, async orchestration. |
| `xtask` | Build automation stub. |

See [`docs/architecture.md`](docs/architecture.md) for the full dependency
graph and [`docs/migration-roadmap.md`](docs/migration-roadmap.md) for
phased delivery.

## Installation

Prebuilt desktop binaries for Linux and Windows are attached to every
release (built by the tag-driven
[`release`](https://github.com/Ah4ds/NetRaze/actions/workflows/release.yml)
workflow):

```shell
curl -LO https://github.com/Ah4ds/NetRaze/releases/latest/download/netraze-desktop-linux-x86_64.tar.gz
```

Or build from source:

```shell
git clone https://github.com/Ah4ds/NetRaze.git
cd NetRaze
cargo build --release
```

The CLI lands at `target/release/netraze-cli` and the desktop at
`target/release/netraze-desktop` (Windows: `.exe`).

### Linux prerequisites

The desktop GUI links against X11/Wayland/GTK headers. On Debian/Ubuntu:

```shell
sudo apt install -y \
  libx11-dev libxkbcommon-dev libxkbcommon-x11-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libwayland-dev libgtk-3-dev build-essential pkg-config
```

The CLI-only build needs none of these.

### Windows prerequisites

Rust toolchain 1.85+ via `rustup`, and the MSVC build tools. No other
system dependencies.

## Quick start

### List available protocols and modules

```shell
cargo run -p netraze-cli -- protocols
cargo run -p netraze-cli -- modules
```

### Plan a scan

```shell
cargo run -p netraze-cli -- plan smb 10.10.10.0/24 --module shares
```

General scan execution is wired through the GUI for now; `plan` only validates
targets, resolves the protocol handler, and computes concurrency. BloodHound CE
export is also available as a focused headless command. Keep the secret outside
the command line by naming the environment variable that contains it:

```shell
export NETRAZE_LDAP_PASSWORD='replace-with-an-authorized-test-password'
cargo run -p netraze-cli -- bloodhound-ce \
  --endpoint dc.example.test:389 \
  --domain EXAMPLE \
  --username alice \
  --password-env NETRAZE_LDAP_PASSWORD \
  --output ./bloodhound-ce
unset NETRAZE_LDAP_PASSWORD
```

For pass-the-hash authentication, put the 32-character NT hash in an
environment variable and replace `--password-env` with `--nt-hash-env`.
The exporter writes loose BloodHound CE schema-v6 JSON files and a ZIP archive.

## Desktop GUI

The GUI (`netraze-desktop`) is a node-graph workspace where each host,
share listing, user listing, and post-exploitation action is a node
connected by data-flow edges. This is the primary interface for
interactive workflows today.

```shell
cargo run -p netraze-desktop
```

Anonymous and guest access are first-class in the GUI: hosts can be
listed and browsed with no login at all (null session), credentials can
be saved without a secret for guest access (badged `GUEST`), and a
`👤 (anonymous)` entry is always available in the per-host login menu.
Secret-less credentials can also be imported in bulk through the
Credential Manager's CSV import.

For SMB or LDAP scans, enter a target and select the protocol in
Configuration. The Username, Password, and NTLM Hash fields apply to both;
`DOMAIN\username` selects a domain, and an NT hash takes priority over a
password. A nonempty Kerberos Ticket field is rejected because ticket
authentication is not implemented. If the credential fields are blank,
each target reuses its current **Login As** account or scans anonymously
when it has none. Entered credentials override that choice and are added
to Credential Manager when the scan starts. A missing saved secret is an
error for that target, not a silent anonymous retry. LDAP anonymous bind
has no SASL sign-and-seal; named LDAP credentials use NTLMv2 sign-and-seal.
`Guest` with an empty password is an explicit NTLM attempt that the server
may reject.

LDAP discovery creates an **AD Directory** workflow node with Overview,
Users, Groups, Computers, OUs, Topology, Privileged, Services, and Security
tabs. The Security tab separates reported policy values from checks marked
`Not tested`; referrals and partial-section errors are surfaced rather
than followed automatically. Select an AD Directory node and use
**Export BloodHound CE…** to choose an output folder. The export reuses that
host's current **Login As** credential, reports progress in the bottom dock,
and writes loose schema-v6 JSON plus a ZIP archive. The bottom
Network/Credentials/Progress dock can be closed with `×` and reopened from the
status bar without clearing its contents.

The current BloodHound collector covers the schema and default domain naming
contexts over NetRaze's LDAP/NTLM transport. It does not yet collect AD CS,
interactive sessions, local groups, SYSVOL data, or Kerberos-only relationships;
LDAPS and referral chasing also remain out of scope. LDAP referrals are returned
to the caller and never followed with credentials.

**Workspace files contain Credential Manager secrets** (passwords and NT
hashes) in their saved JSON. Treat them as sensitive files and do not
commit or share them. Session-only credential copies are not serialized.

Backend is `wgpu` by default, which works natively on Linux (Vulkan),
Windows (DX12), macOS (Metal), and in WSL (via Lavapipe software
fallback).

## Architecture

Layered, with one-way dependencies:

```
               netraze-cli      netraze-desktop
                     \             /
                      netraze-app
                           |
   ┌──────────────┬────────┼─────────┬──────────────┐
   |              |        |         |              |
netraze-      netraze-  netraze-   netraze-     netraze-
protocols     modules   dcerpc     auth         targets
   \              \        /         /             /
    \──────────── netraze-core ──────────────────/
                           |
         (transversal: config, output, runtime, storage)
```

Rules enforced in code review:

- `netraze-core` has no applicative dependencies.
- Protocol and module crates never depend on the CLI.
- `netraze-app` is the only crate allowed to know almost everything.
- Shared logic ratchets *up* into `netraze-core` or a transversal crate —
  never stays buried in a protocol crate.

Full write-up in [`docs/architecture.md`](docs/architecture.md).

## Development

### Daily commands

```shell
cargo check --workspace --all-targets # type-check
cargo clippy -p netraze-dcerpc -- -D warnings   # strict gate for new code
cargo test --workspace --no-fail-fast # excludes ignored live suites
cargo fmt --all --check               # check formatting
```

### Per-crate testing

```shell
cargo test -p netraze-dcerpc         # NDR / PDU / NTLMSSP / interface suites
cargo test -p netraze-protocols      # SMB, LDAP, NTLM, and dispatcher tests
```

### CI / release

GitHub Actions ships a single workflow, [`release.yml`](.github/workflows/release.yml):
pushing a `v*` tag builds `netraze-desktop` on native Linux and Windows
runners and attaches the binaries to a GitHub Release. Run the fmt /
clippy / test gates locally before pushing — the strict clippy gate
(`-D warnings`) applies to `netraze-dcerpc`, the newest pure-Rust stack.

## Validation methodology

A wire-level toolkit is only as trustworthy as its test harness. Unit
tests, pinned byte fixtures, and isolated live harnesses cover the
implemented SMB/DCE-RPC and LDAP paths:

1. **Known-answer vectors for crypto.** NTLMv2 response, NTOWFv2,
   SIGN/SEAL key derivation, and RC4 keystream are validated against
   MS-NLMP test vectors. Any drift is caught before a single packet is
   built.
2. **Impacket-pinned byte fixtures for NDR.** Python scripts in
   `crates/netraze-dcerpc/tests/` use the Impacket library to generate
   exact bytes for `NetrShareEnum` requests and responses; the LDAP
   fixture script covers BER bind/search messages, controls, and entries.
   Bytes are pinned in Rust tests, so normal test runs need no Python.
3. **Live Samba SMB integration harness.** `tests/samba/` ships a
   `docker-compose.yml` + `smb.conf` that pin a Samba server with a
   known share inventory. Ignored integration suites in
   `crates/netraze-protocols/tests/` drive the full stack against the
   real daemon — session setup (including anonymous and guest), share
   and user enumeration, file ops, smbexec wire behavior, and AV probes —
   proving the wire is not just internally consistent but actually
   interoperable. SMB wire changes are cross-checked against Impacket
   against the same harness before they land.
4. **Samba AD LDAP harness.** `tests/samba-ad/` runs a separate, digest-pinned
   domain controller bound to loopback. Its ignored suite verifies NTLM
   password/hash bind, protected RootDSE search, paging, and complete
   read-only inventory. It also checks anonymous RootDSE access, rejection
   of wrong-password and Guest NTLM binds, protected searches with escaped
   filters and returned referrals, and a complete BloodHound CE schema-v6
   JSON/ZIP export.

See the [SMB harness guide](tests/samba/README.md) and
[LDAP harness guide](tests/samba-ad/README.md) for local commands.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 0 | Workspace hygiene, wgpu backend, CI matrix | Done |
| Phase 1 | DCE/RPC primitives, NTLMSSP, SMB2 auth, SRVSVC, Samba harness | Done |
| Phase 2 | SMB2 IOCTL / FSCTL_PIPE_TRANSCEIVE, SMB signing, SAM RemoteOperations, SQLite workspace, CLI execution path | Mostly done — pipe transport, signing and SAM remote ops landed; SQLite workspace and the CLI execution path remain |
| Phase 3 | Deep per-protocol modules inside `netraze-protocols`, stable plugin API, JSON/CSV export, priority module parity with NetExec | Planned |
| Phase 4 | Integration test corpus, network fixtures, TUI or machine-friendly API, Kerberos | Planned |

Full write-up in [`docs/migration-roadmap.md`](docs/migration-roadmap.md).

## Contributing

This is an early-stage port. The highest-leverage contributions right now:

- **LDAP follow-ups** (`netraze-protocols::ldap`) — security-descriptor
  collection and explicitly tested policy probes; the read-only inventory
  already covers users, groups, computers, SPNs, and directory structure.
- **Kerberos** (`netraze-protocols::kerberos`) — AS/TGS exchange, RC4/AES key
  handling; the next big authentication milestone after NTLMv2.
- **Deep per-protocol modules** inside `netraze-protocols` as coverage grows.
- **Impacket-pinned fixtures** for each new DCE/RPC interface added
  (see `crates/netraze-dcerpc/tests/gen_*.py` for the pattern).

Before opening a PR, please ensure:

- `cargo fmt --all --check` passes.
- `cargo clippy -p netraze-dcerpc -- -D warnings` passes.
- `cargo test --workspace --no-fail-fast` passes on your OS. If you touched
  SMB2/DCE-RPC, run the SMB Samba suite; if you touched LDAP or its NTLM
  SASL path, run the separate Samba AD suite as well.

## Related projects

- **[NetExec](https://github.com/Pennyw0rth/NetExec)** — the mature Python
  tool this port descends from. Use it today for real engagements.
- **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)** — the
  original project by @byt3bl33d3r (2015), which NetExec forked from in
  2023.
- **[Impacket](https://github.com/fortra/impacket)** — the reference
  Python library for MS-RPCE, DCE/RPC interfaces (SRVSVC, SAMR, LSAD,
  WKSSVC, RPRN, …), NTLMv2, and Kerberos. NetRaze validates its wire
  output against Impacket-generated byte fixtures.
- **[RustHound-CE](https://github.com/g0h4n/RustHound-CE)** — the MIT-licensed
  BloodHound Community Edition object/relationship parser used by the LDAP
  export adapter. NetRaze retains responsibility for transport, authentication,
  paging, controls, and referral policy.

## Acknowledgments

Technical inspiration and protocol know-how come from the years of work
put into **CrackMapExec** by @byt3bl33d3r and subsequent maintainers, and
into **NetExec** by @NeffIsBack, @Marshall-Hallenbeck, @zblurx, @mpgn,
and the wider contributor community. The MS-RPCE / MS-NLMP / MS-SMB2
specs from Microsoft, plus Impacket's reference implementation, have
been essential ground truth throughout the port.

## License

Licensed under the BSD 2-Clause License. See the `license` field in
[`Cargo.toml`](Cargo.toml).

## Legal disclaimer

NetRaze is intended **exclusively** for authorised security assessments
— your own infrastructure, engagements covered by a signed statement of
work, or purpose-built lab environments. Running it against systems you
do not own or do not have explicit written permission to test is
illegal in virtually every jurisdiction and will not be supported by
the maintainers. You are solely responsible for how you use this
software.
