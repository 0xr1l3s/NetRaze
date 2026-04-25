# NetRaze

[![CI](https://img.shields.io/badge/CI-Linux%20%2B%20Windows-brightgreen)](.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](#license)
[![Rust Edition](https://img.shields.io/badge/rust-2024%20edition%20%28MSRV%201.85%29-orange)](rust-toolchain.toml)
[![Status](https://img.shields.io/badge/status-alpha%20%E2%80%94%20port%20in%20progress-yellow)](#current-status)

**NetRaze** is an offensive network-execution toolkit, rewritten from scratch
in pure Rust. It is the spiritual successor to the NetExec / CrackMapExec
lineage — same workflow (enumerate, authenticate, execute, post-exploit),
but with a memory-safe backend, a single static binary, and a built-in
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
   CI runners all want a single static artifact. A Python tree with native
   extensions (Impacket, pycryptodome, LDAP3) is hostile to that.

NetRaze keeps the NetExec model — protocol handlers, post-auth modules,
workspace-per-engagement — and rebases it on:

- **Pure Rust wire code.** No FFI bindings to Impacket or Samba. The
  DCE/RPC NDR walker, NTLMSSP, and SMB2 framing are re-implemented and
  validated byte-for-byte against Impacket-generated fixtures.
- **Single-binary distribution.** `cargo build --release` produces one
  executable per binary crate.
- **Async I/O from the ground up.** `tokio` across the board, not retrofitted
  onto a synchronous Python core.
- **Desktop workflow graph.** An `egui`/`egui-snarl` canvas for composing
  offensive workflows visually, complementing the headless CLI.

## Current status

NetRaze is **alpha**. The core engineering foundations are solid, but the
protocol coverage is narrow — and capability by capability, the
**attacker-side OS matters**: a lot of the post-exploitation modules are
still Windows-only native-API implementations today, with Linux stubs
that return `NOT_PORTED` until the pure-Rust replacement lands.

### SMB capability matrix

Rows are capabilities; columns are the attacker OS you're running NetRaze
from. "Windows-native" means the code uses the `windows` crate (SCM,
WNet, NetAPI, Registry) — very much functional, just not portable yet.
"Pure-Rust" means it talks SMB2/DCE-RPC directly over TCP and works from
any OS.

| Capability | Windows attacker | Linux attacker | Implementation |
|---|---|---|---|
| SMB2 Negotiate + NTLMv2 Session Setup + Tree Connect | Works | Works | Pure-Rust (`smb2`, `ntlm`) |
| Host fingerprinting | Works | Stub | Windows-native |
| Share enumeration | Works | Stub | Windows-native (WNet / NetAPI) |
| User enumeration | Works | Stub | Windows-native (SAMR via local APIs) |
| SAM / LSA secret dump | Works | Stub | Windows-native (RemoteRegistry + hive parse) |
| AV product enumeration | Works | Stub | Windows-native (WMI local) |
| Remote command execution (smbexec via SCM) | Works | Stub | Windows-native (Service Control Manager) |
| Pass-the-hash authentication | Works | Works | Pure-Rust NTLMv2 |
| Browser / file transfer on shares | Works | Stub | Windows-native (WNet) |

Pure-Rust cross-platform modules today: `smb2`, `ntlm`, `crypto`, `sam`
(hive parsing), `hive`, `fingerprint`. The rest is Windows-native with
Linux stubs — tracked as Phase 2 of the portage plan, which is the next
major effort.

### Other protocols

| Protocol | State |
|---|---|
| LDAP, WinRM, MSSQL, SSH, RDP, FTP, NFS, VNC, WMI | Scaffold only — factory registered, no wire code yet |

### DCE/RPC stack (`netraze-dcerpc`)

- NDR20 reader/writer with BFS deferred-pointer walker (conformant arrays,
  unique/ref pointers, unions with pointer arms)
- MS-RPCE PDU framing (Bind, Request, Response, Fault)
- NTLMSSP auth verifier including seal/unseal (RC4 + HMAC-MD5 v2)
- MS-SRVS interface: `NetrShareEnum` request/response validated against
  Impacket-generated byte fixtures

### Missing pieces blocking the pure-Rust port

- **`FSCTL_PIPE_TRANSCEIVE`** over SMB2 — this is the single biggest
  blocker. Once implemented, the 8 Windows-native SMB modules can be
  rewritten on top of the pure-Rust SMB2 session + the existing DCE/RPC
  interfaces (SRVSVC for shares, SAMR for users, WKSSVC for info,
  SVCCTL for exec, …), making Linux a full first-class attacker OS.
- SMB signing and encryption negotiation against the target.
- Kerberos / AES-based authentication (only NTLMv2 today).
- Relay attacks, coercion, ADCS abuse (planned as modules once the
  DCE/RPC-over-pipe path is unblocked).

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
| `netraze-protocols` | Wire-level protocol handlers (SMB is the only one significantly implemented). |
| `netraze-dcerpc` | MS-RPCE stack: NDR, PDU, NTLMSSP auth, MS-SRVS interface. |
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

No published crates yet. Build from source:

```shell
git clone https://github.com/0xr1l3s/NetRaze.git
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

The CLI today stops at **planning** (validating targets, resolving the
protocol handler, computing concurrency). Execution is wired through the
GUI for now; the headless execution path is part of the next milestone.

## Desktop GUI

The GUI (`netraze-desktop`) is a node-graph workspace where each host,
share listing, user listing, and post-exploitation action is a node
connected by data-flow edges. This is the primary interface for
interactive workflows today.

```shell
cargo run -p netraze-desktop
```

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
cargo check --workspace              # type-check
cargo clippy -p netraze-dcerpc -- -D warnings   # strict gate for new code
cargo test --workspace               # run all unit + integration tests
cargo fmt --all                      # format
```

### Per-crate testing

```shell
cargo test -p netraze-dcerpc         # NDR / PDU / NTLMSSP / SRVSVC suites
cargo test -p netraze-protocols      # SMB crypto, NTLM vectors
```

### CI gate

`.github/workflows/ci.yml` enforces, on every push and PR:

1. `cargo fmt --all --check` (Linux).
2. Strict clippy on `netraze-dcerpc` (the new pure-Rust stack has zero
   warning tolerance); advisory clippy on the rest of the workspace.
3. `cargo check --workspace --all-targets` on both **Ubuntu** and
   **Windows**.
4. Full `cargo test --workspace` on both OS.
5. An opt-in `samba-integration` job that spins up the pinned Samba
   container (see below) and runs the live SMB2 smoke tests. Triggered
   by `workflow_dispatch` or pushes to `main`.

## Validation methodology

A wire-level offensive toolkit is only as trustworthy as its test harness.
Three independent layers protect the SMB/DCE-RPC stack:

1. **Known-answer vectors for crypto.** NTLMv2 response, NTOWFv2,
   SIGN/SEAL key derivation, and RC4 keystream are validated against
   MS-NLMP test vectors. Any drift is caught before a single packet is
   built.
2. **Impacket-pinned byte fixtures for NDR.** Python scripts in
   `crates/netraze-dcerpc/tests/` use the Impacket library to generate
   exact bytes for `NetrShareEnum` requests and responses, which are
   then baked into Rust tests. Any divergence in our encoder/decoder is
   a test failure with a clear byte-level diff.
3. **Live Samba integration harness.** `tests/samba/` ships a
   `docker-compose.yml` + `smb.conf` that pin a Samba server with a
   known share inventory. Rust integration tests in
   `crates/netraze-protocols/tests/samba_integration.rs` drive SMB2
   Negotiate + NTLMv2 Session Setup + Tree Connect against the real
   daemon, proving the wire is not just internally consistent but
   actually interoperable.

See [`tests/samba/README.md`](tests/samba/README.md) for how to run the
integration suite locally.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 0 | Workspace hygiene, wgpu backend, CI matrix | Done |
| Phase 1 | DCE/RPC primitives, NTLMSSP, SMB2 auth, SRVSVC, Samba harness | Done |
| Phase 2 | SMB2 IOCTL / FSCTL_PIPE_TRANSCEIVE, SMB signing, SAM RemoteOperations, SQLite workspace, CLI execution path | In progress |
| Phase 3 | Split `netraze-protocols` per protocol, stable plugin API, JSON/CSV export, priority module parity with NetExec | Planned |
| Phase 4 | Integration test corpus, network fixtures, TUI or machine-friendly API, Kerberos | Planned |

Full write-up in [`docs/migration-roadmap.md`](docs/migration-roadmap.md).

## Contributing

This is an early-stage port. The highest-leverage contributions right now:

- **SMB2 IOCTL support**, unlocking the full DCE/RPC-over-named-pipe
  path and most of the interesting post-exploitation surface.
- **SMB signing**, required to talk to hardened targets.
- **Per-protocol crates** as NetRaze grows beyond SMB.
- **Impacket-pinned fixtures** for each new DCE/RPC interface added
  (see `crates/netraze-dcerpc/tests/gen_*.py` for the pattern).

Before opening a PR, please ensure:

- `cargo fmt --all --check` passes.
- `cargo clippy -p netraze-dcerpc -- -D warnings` passes.
- `cargo test --workspace` passes on your OS. If you touched SMB2 or
  NTLMSSP code, run the Samba integration suite too.

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
