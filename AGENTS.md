# NetRaze — Agent Guide

> This file is written for AI coding agents. It assumes you know Rust and Cargo but nothing about this specific project.

---

## Project Overview

**NetRaze** is an offensive network-execution toolkit written in pure Rust. It is the spiritual successor to the Python tools NetExec / CrackMapExec — same workflow (enumerate, authenticate, execute, post-exploit), but rebuilt for:

- **Single static binaries** — no Python runtime or native extension hell.
- **Async I/O from the ground up** — `tokio` across the entire stack.
- **Memory-safe wire protocols** — SMB2, NTLMSSP, and DCE/RPC are re-implemented in Rust and validated byte-for-byte against Impacket-generated fixtures. No FFI to Impacket or Samba libraries.
- **Cross-platform attacker OS** — Linux and Windows are equally capable attacker platforms. The cross-platform portage is complete: every SMB capability is pure Rust, and the `windows` crate is no longer a dependency of any protocol crate.

**Status:** Alpha. SMB2 + NTLMv2 (including anonymous null sessions and guest access) are the most mature protocols; the SMB post-exploitation surface (share/user enumeration, file browser, smbexec, SAM/LSA dump, AV enum) is fully ported and covered by the Samba integration harness. The next protocol frontiers are LDAP and Kerberos (see `docs/protocol-stack-plan.md`).

**License:** BSD-2-Clause.

---

## Technology Stack

- **Language:** Rust, edition 2024, MSRV 1.85.
- **Toolchain:** Stable Rust with `clippy` and `rustfmt` components (see `rust-toolchain.toml`).
- **Async runtime:** `tokio` (`rt-multi-thread`, `macros`, `signal`, `sync`, `time`).
- **CLI framework:** `clap` with derive macros.
- **Desktop GUI:** `egui` + `eframe` with the `wgpu` backend (not the default `glow` / OpenGL). `wgpu` is configured with `dx12`, `vulkan`, `metal`, `gles`, and `wgsl` features for cross-platform and headless/WSL compatibility.
- **Serialization:** `serde` + `serde_json`.
- **Diagnostics:** `tracing` + `tracing-subscriber`.
- **Crypto:** `aes`, `cbc`, `cipher`, `des`, `hmac`, `md-5`, `md4`, `rand`.
- **Graph / workflow UI:** `egui-snarl` (node graph), `egui_graphs`, `petgraph`.

---

## Workspace Structure

This is a Cargo workspace with 14 members (13 application crates + `xtask`).

### Crate Map

| Crate | Purpose | Key Notes |
|---|---|---|
| `netraze-core` | Domain contracts, shared types, traits, error types. | **Zero applicative dependencies.** Defines `ProtocolFactory`, `ModuleFactory`, `ScanRequest`, `Capability`, `NetRazeError`. |
| `netraze-app` | Composition root / service wiring. | The only crate allowed to know almost everything. Bootstraps registries, storage, output, config, and runtime. |
| `netraze-cli` | Thin CLI binary (`clap`). | **Must contain zero protocol logic.** Entry point for headless use. |
| `netraze-desktop` | `egui`/`eframe` GUI with node-graph workflow canvas. | Binary crate. Uses `wgpu` backend and `egui-snarl` for visual workflows. |
| `netraze-protocols` | Wire-level protocol handlers. | SMB is the only significantly implemented protocol (`smb2`, `ntlm`, `browser`, `shares`, `users`, `dump`, `exec`, `enum_av`, … all pure Rust). Others (LDAP, SSH, WinRM, RDP, FTP, MSSQL, NFS, VNC, WMI) are scaffold-only. |
| `netraze-dcerpc` | Pure-Rust DCE/RPC v5 stack. | NDR20, PDU framing, NTLMSSP auth verifier, interfaces: SRVSVC, SAMR, WINREG, SCMR. No `cfg(windows)` allowed inside this crate. |
| `netraze-modules` | Post-exploitation module registry. | Categories: `active_directory`, `credentials`, `reconnaissance`. |
| `netraze-auth` | Credential types and authentication methods. | `CredentialSet`, `SecretMaterial`, `AuthMethod`. |
| `netraze-targets` | Target parsing and normalization. | Detects hostnames, IPs, CIDRs, file lists, Nmap XML, Nessus files. |
| `netraze-config` | App / workspace / runtime configuration. | `AppConfig`, `WorkspaceConfig`, `RuntimeConfig`, `LoggingConfig`. |
| `netraze-storage` | Workspace persistence trait. | Async trait `WorkspaceStore`. In-memory impl today; SQLite backend planned. |
| `netraze-output` | Console reporting and output events. | `OutputEvent`, `Reporter` trait, `ConsoleReporter` bridges to `tracing`. |
| `netraze-runtime` | Concurrency, timeouts, async orchestration. | `RuntimeProfile` with bounded thread limits. |
| `xtask` | Build automation stub. | Currently a placeholder. Cargo alias `cargo xtask` maps to `cargo run -p xtask --`. |

### Dependency Rules (enforced in code review)

- `netraze-core` depends on **no** applicative crate.
- `netraze-cli` contains **no** protocol logic.
- `netraze-protocols` and `netraze-modules` depend only on `netraze-core` (and transversals), never on the CLI.
- `netraze-app` is the **only** crate allowed to know almost everything.
- Shared logic ratchets *up* into `netraze-core` or a transversal crate — never stays buried in a protocol crate.

### Dependency Graph (simplified)

```
netraze-cli        netraze-desktop
      │                  │
      └────┬─────────────┘
           │
      netraze-app
           │
    ┌──────┼──────┬────────┬────────┬─────────┬──────────┐
    │      │      │        │        │         │          │
netraze-  netraze-  netraze-  netraze-  netraze-  netraze-  netraze-  netraze-
protocols modules   dcerpc    auth      targets   config    output    runtime
   │                                              │
   │                                         netraze-storage
   │
   └────── netraze-core ────────────────────────────────────────
```

---

## Build and Test Commands

### Daily Development

```bash
# Type-check the entire workspace
cargo check --workspace --all-targets

# Run all unit + integration tests (excludes #[ignore] tests)
cargo test --workspace --no-fail-fast

# Format everything
cargo fmt --all

# Strict lint gate for the new pure-Rust DCE/RPC stack
cargo clippy -p netraze-dcerpc --all-targets -- -D warnings

# Advisory lint on the full workspace (legacy crates have pre-existing warnings)
cargo clippy --workspace --all-targets
```

### Release Builds

```bash
cargo build --release
# CLI binary:  target/release/netraze-cli
# GUI binary:  target/release/netraze-desktop
```

### Per-Crate Testing

```bash
# NDR / PDU / NTLMSSP / interface unit tests
cargo test -p netraze-dcerpc

# SMB crypto, NTLM known-answer vectors, anonymous AUTHENTICATE shape
cargo test -p netraze-protocols
```

### Linux GUI Prerequisites

The desktop GUI links against X11 / Wayland / GTK headers. On Debian/Ubuntu:

```bash
sudo apt install -y \
  libx11-dev libxkbcommon-dev libxkbcommon-x11-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libwayland-dev libgtk-3-dev build-essential pkg-config
```

The CLI-only build needs none of these.

---

## Testing Strategy

NetRaze uses **three independent validation layers** for the SMB/DCE-RPC stack:

### 1. Known-Answer Crypto Vectors

NTLMv2 response computation, NTOWFv2, SIGN/SEAL key derivation, and RC4 keystream are validated against MS-NLMP test vectors. These are fast unit tests that run on every `cargo test`.

### 2. Impacket-Pinned Byte Fixtures

Python scripts in `crates/netraze-dcerpc/tests/` (e.g., `gen_srvs_fixture.py`) use the Impacket library to generate exact byte arrays for DCE/RPC requests and responses. The generated bytes are baked into Rust test modules as `const &[u8]` literals. CI does **not** need Python/Impacket — the fixtures are pinned. Any divergence in NetRaze's encoder/decoder is a test failure with a clear byte-level diff.

### 3. Live Samba Integration Harness

Directory: `tests/samba/`

- `docker-compose.yml` spins `servercontainers/samba:smbd-only-latest` on `127.0.0.1:1445` (high port to avoid colliding with the host OS SMB client).
- `smb.conf` defines a pinned share inventory with user `alice` / `wonderland` in workgroup `NETRAZE`. Wrong passwords map onto the guest account (`map to guest = Bad Password`), which is what exercises the guest paths. Share names and comments are **load-bearing** — Rust tests assert on them exactly.
- Integration tests live in `crates/netraze-protocols/tests/` (nine suites, 29 tests: `samba_integration`, `rpc_channel_samba`, `shares_rpc_samba`, `info_rpc_samba`, `users_rpc_samba`, `browser_ops_samba`, `exec_samba`, `enum_av_samba`, `anonymous_samba`) and are `#[ignore]` by default.

Run locally:

```bash
# Start the container
docker compose -f tests/samba/docker-compose.yml up -d --wait

# Run every ignored suite (single-threaded to avoid Samba passdb-lock races)
cargo test -p netraze-protocols -- --ignored --test-threads=1

# Tear down
docker compose -f tests/samba/docker-compose.yml down -v
```

Environment variable `NETRAZE_SAMBA_ADDR` defaults to `127.0.0.1:1445` and can be overridden to point at a custom endpoint.

**Impacket cross-check is a standing rule:** when SMB wire behaviour changes, verify the new behaviour against Impacket running against the same harness before committing, and pin the result in a test. Several suites carry comments noting "identical to Impacket" for exactly this reason.

---

## CI/CD

GitHub Actions ships a single workflow: [`.github/workflows/release.yml`](.github/workflows/release.yml).

- **Trigger:** pushing a `v*` tag (`git tag v0.1.1 && git push origin v0.1.1`).
- **Build:** `cargo build --release -p netraze-desktop` on native Ubuntu and Windows runners, packaged as `netraze-desktop-{linux,windows}-x86_64` archives.
- **Release:** binaries are attached to a GitHub Release with auto-generated notes.

The fmt / clippy / test gates are not enforced by CI today — run them locally before pushing (see Quick Reference). The strict clippy gate (`-D warnings`) applies to `netraze-dcerpc`.

---

## Code Style Guidelines

### Tooling

- `rustfmt` for formatting. Run `cargo fmt --all` before committing.
- `clippy` with workspace-level lints:
  - `clippy::pedantic` enabled at `warn` level.
  - `module_name_repetitions`, `missing_errors_doc`, `missing_panics_doc` explicitly allowed.

### Documentation Style

- **Module-level docs (`//!`) are extensive** and explain the wire-protocol context. Expect to see references like `MS-SRVS §3.1.4`, `MS-RPCE §2.2.2.13`, `MS-SMB2 §2.2.13`.
- **Comments explain *why*, not just *what*.** They often reference the original spec subtlety or bug that motivated a layout decision (e.g., "the union's tag=1 arm is a *pointer*, not an inline container — missing that pointer level was the original decoder bug").
- **English** is the language of all code comments, documentation, and commit messages. The only French document is `docs/architecture.md` (the target architecture description).

### Naming and Structure

- Follow standard Rust naming (`PascalCase` for types/traits, `snake_case` for functions/variables/modules, `SCREAMING_SNAKE_CASE` for constants).
- **Credential shape carries auth intent** in `SmbCredential`: empty username → anonymous null session; username with no hash and no password → guest; anything else → strict password/pass-the-hash (a wrong password is *rejected*, never silently downgraded to guest). Guest and null sessions bind DCE/RPC unauthenticated over the SMB session (Impacket parity) — see `smb/rpc.rs::bind_interface_over_smb`.
- Sanity caps on untrusted input allocations (e.g., `MAX_SHARES_PER_RESPONSE = 65_536`, `64 KiB` wstring cap) to prevent malicious server inputs from forcing huge allocations.

---

## Security Considerations

1. **This is offensive security software.** It is intended exclusively for authorized security assessments — your own infrastructure, engagements covered by a signed statement of work, or purpose-built lab environments. Running it against systems you do not own or do not have explicit written permission to test is illegal.

2. **Test credentials are published openly.** The Samba integration harness uses `alice` / `wonderland` in workgroup `NETRAZE`. These are test-only and must never be reused in any real environment.

3. **No `unsafe` Rust policy:** There is no project-wide ban on `unsafe`, but the wire-protocol crates (`netraze-dcerpc`, `netraze-protocols::smb2`) are written entirely in safe Rust. Any introduction of `unsafe` should be justified and documented.

4. **Strict auth semantics:** a credential carrying a secret must never accept a server-downgraded GUEST/NULL session — the error ("downgraded to GUEST") is the security property, pinned by tests in `anonymous_samba`.

---

## Cross-Platform Portage Plan (Complete)

NetRaze inherited two implementation strategies for SMB post-exploitation.
The migration from Windows-native APIs to the pure-Rust SMB2 + DCE/RPC
stack is **finished** — every phase below is done, the Windows-native
files and `smb/stubs/` are deleted, and the `windows` crate is no longer
a dependency of `netraze-protocols`:

| Strategy | Where it lives | Portability |
|---|---|---|
| **Pure-Rust SMB2 + DCE/RPC** (the only strategy left) | `crates/netraze-protocols/src/smb/*.rs` and `netraze-dcerpc/` | Any attacker OS |

- **Phase 1** (Done) — Pure-Rust SMB2 wire foundation: Negotiate, NTLMv2, TreeConnect.
- **Phase 2** (Done) — DCE/RPC primitives: NDR20, PDU framing, NTLMSSP auth verifier, MS-SRVS `NetrShareEnum`.
- **Phase 3** (Done) — `FSCTL_PIPE_TRANSCEIVE` over SMB2 (`rpc::SmbPipeTransport`).
- **Phase 4** (Done) — Read-only modules: `info`, `shares`, `users`.
- **Phase 5** (Done) — Write-side modules: `exec` (smbexec via SVCCTL), `browser` (file ops over SMB2).
- **Phase 6** (Done) — Secret dumping: `dump` (SAM/LSA via WINREG + hive parser).
- **Phase 7** (Done) — Windows-native code path retired; single pure-Rust implementation everywhere.
- **Follow-up** (Done) — Anonymous null-session and guest access across the stack (credential-shape dispatch, unauthenticated DCE binds for guest/null sessions), plus the tag-driven release workflow.

**What this means for agents:**
- If you modify `netraze-dcerpc` or `netraze-protocols::smb`, run the full Samba integration suite (`cargo test -p netraze-protocols -- --ignored --test-threads=1`) and cross-check behaviour changes against Impacket.
- If you add a new DCE/RPC interface, follow the fixture pattern: write a `gen_*.py` script that uses Impacket to generate bytes, paste the bytes into a Rust test, and add a round-trip test.
- Never re-introduce `#[cfg(windows)]` protocol paths in `netraze-protocols` or any `cfg`-gating in `netraze-dcerpc` — those crates are 100% cross-platform by policy.

---

## Key Files for Orientation

| File | Why it matters |
|---|---|
| `Cargo.toml` | Workspace members, shared dependencies, lints. |
| `rust-toolchain.toml` | Pins stable Rust + clippy + rustfmt. |
| `docs/architecture.md` | Target architecture (in French). Dependency rules and evolution plan. |
| `docs/migration-roadmap.md` | Detailed structural roadmap + the (now complete) cross-platform portage plan. |
| `docs/protocol-stack-plan.md` | Operational inventory of every protocol interface NetRaze needs — the "what do we attack next" table. |
| `tests/samba/README.md` | Operator guide for the live integration harness (suite list, known Samba limits). |
| `crates/netraze-dcerpc/tests/gen_srvs_fixture.py` | Pattern for Impacket-pinned byte fixtures. |
| `crates/netraze-protocols/tests/` | The nine live Samba integration suites (`#[ignore]` by default). |
| `.github/workflows/release.yml` | Tag-driven Linux + Windows desktop release builds. |

---

## Quick Reference

```bash
# Build everything
cargo build --release

# Run the CLI
cargo run -p netraze-cli -- protocols
cargo run -p netraze-cli -- modules
cargo run -p netraze-cli -- plan smb 10.10.10.0/24 --module shares

# Run the GUI
cargo run -p netraze-desktop

# Full test suite (fast)
cargo test --workspace --no-fail-fast

# Lint gates (required before pushing)
cargo fmt --all --check
cargo clippy -p netraze-dcerpc --all-targets -- -D warnings

# Samba integration (requires Docker)
docker compose -f tests/samba/docker-compose.yml up -d --wait
cargo test -p netraze-protocols -- --ignored --test-threads=1
docker compose -f tests/samba/docker-compose.yml down -v

# Release (tag-driven — builds Linux + Windows binaries on GitHub Actions)
git tag v0.1.2 && git push origin v0.1.2
```
