# NetRaze — Agent Guide

> This file is written for AI coding agents. It assumes you know Rust and Cargo but nothing about this specific project.

---

## Project Overview

**NetRaze** is an offensive network-execution toolkit written in pure Rust. It is the spiritual successor to the Python tools NetExec / CrackMapExec — same workflow (enumerate, authenticate, execute, post-exploit), but rebuilt for:

- **Single static binaries** — no Python runtime or native extension hell.
- **Async I/O from the ground up** — `tokio` across the entire stack.
- **Memory-safe wire protocols** — SMB2, NTLMSSP, and DCE/RPC are re-implemented in Rust and validated byte-for-byte against Impacket-generated fixtures. No FFI to Impacket or Samba libraries.
- **Cross-platform attacker OS** — the long-term goal is that Linux and Windows are equally capable attacker platforms. Today, some post-exploitation modules are still Windows-native only.

**Status:** Alpha. SMB2 + NTLMv2 are the most mature protocols. The project is currently blocked on `FSCTL_PIPE_TRANSCEIVE` over SMB2 (Phase 3 of the cross-platform portage), which will unlock rewriting all Windows-native post-exploitation modules as pure-Rust code.

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
| `netraze-protocols` | Wire-level protocol handlers. | SMB is the only significantly implemented protocol. Others (LDAP, SSH, WinRM, RDP, FTP, MSSQL, NFS, VNC, WMI) are scaffold-only. |
| `netraze-dcerpc` | Pure-Rust DCE/RPC v5 stack. | NDR20, PDU framing, NTLMSSP auth verifier, MS-SRVS interface. No `cfg(windows)` allowed inside this crate. |
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
# NDR / PDU / NTLMSSP / SRVSVC unit tests
cargo test -p netraze-dcerpc

# SMB crypto, NTLM known-answer vectors
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
- `smb.conf` defines a pinned share inventory with user `alice` / `wonderland` in workgroup `NETRAZE`. Share names and comments are **load-bearing** — Rust tests assert on them exactly.
- Integration tests are in `crates/netraze-protocols/tests/samba_integration.rs` and are `#[ignore]` by default.

Run locally:

```bash
# Start the container
docker compose -f tests/samba/docker-compose.yml up -d --wait

# Run the ignored smoke tests (single-threaded to avoid Samba passdb-lock races)
cargo test -p netraze-protocols --test samba_integration -- --ignored --test-threads=1

# Tear down
docker compose -f tests/samba/docker-compose.yml down -v
```

Environment variable `NETRAZE_SAMBA_ADDR` defaults to `127.0.0.1:1445` and can be overridden to point at a custom endpoint.

---

## CI/CD

File: `.github/workflows/ci.yml`

Three jobs, triggered on `push`/`pull_request` to `main`/`master`, plus manual `workflow_dispatch`:

### Job 1: `fmt-and-clippy` (Ubuntu, fast gate)

1. `cargo fmt --all --check`
2. **Strict** clippy on `netraze-dcerpc`: `cargo clippy -p netraze-dcerpc --all-targets -- -D warnings` (zero tolerance — this is brand new code).
3. **Advisory** clippy on full workspace: `cargo clippy --workspace --all-targets` (pre-existing warnings in legacy crates are allowed).

### Job 2: `test` (Matrix: Ubuntu + Windows)

- Depends on `fmt-and-clippy`.
- `cargo check --workspace --all-targets`
- `cargo test --workspace --no-fail-fast`
- `fail-fast: false` on the matrix.

### Job 3: `samba-integration` (Ubuntu, opt-in)

- **Conditional**: only runs on `workflow_dispatch` or pushes to `main`/`master` (not PRs by default).
- Depends on `fmt-and-clippy`.
- Spins up `tests/samba/docker-compose.yml`.
- Runs: `cargo test -p netraze-protocols --test samba_integration -- --ignored --test-threads=1`
- Dumps Samba container logs on failure.
- Always tears down the container (`down -v`).

**Note:** `RUSTFLAGS=-D warnings` is **not** set globally because legacy crates carry pre-existing warnings.

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
- Platform-gated code uses `#[cfg(windows)]` / `#[cfg(not(windows))]`. On non-Windows, stub files in `smb/stubs/` return `NOT_PORTED` until the pure-Rust implementation replaces them.
- Sanity caps on untrusted input allocations (e.g., `MAX_SHARES_PER_RESPONSE = 65_536`, `64 KiB` wstring cap) to prevent malicious server inputs from forcing huge allocations.

---

## Security Considerations

1. **This is offensive security software.** It is intended exclusively for authorized security assessments — your own infrastructure, engagements covered by a signed statement of work, or purpose-built lab environments. Running it against systems you do not own or do not have explicit written permission to test is illegal.

2. **Test credentials are published openly.** The Samba integration harness uses `alice` / `wonderland` in workgroup `NETRAZE`. These are test-only and must never be reused in any real environment.

3. **No `unsafe` Rust policy:** There is no project-wide ban on `unsafe`, but the wire-protocol crates (`netraze-dcerpc`, `netraze-protocols::smb2`) are written entirely in safe Rust. Any introduction of `unsafe` should be justified and documented.

4. **Stub modules on Linux:** Non-Windows builds compile stub implementations that return `NOT_PORTED` errors. This prevents accidental execution of Windows-native code paths on the wrong platform, but also means an operator on Linux will see "not ported" for many capabilities until the pure-Rust stack catches up.

---

## Cross-Platform Portage Plan (Current Engineering Focus)

NetRaze inherited two implementation strategies for SMB post-exploitation:

| Strategy | Where it lives | Portability |
|---|---|---|
| **Windows-native** | `crates/netraze-protocols/src/smb/{connection,browser,shares,info,users,dump,enum_av,exec}.rs` | Windows attacker only. Uses `windows` crate (SCM, WNet, NetAPI, Registry). |
| **Pure-Rust SMB2 + DCE/RPC** | `crates/netraze-protocols/src/smb/{smb2,ntlm,crypto,sam,hive,fingerprint}.rs` and `crates/netraze-dcerpc/` | Any attacker OS. Talks raw TCP. |

The project is migrating from the first to the second. Phases:

- **Phase 1** (Done) — Pure-Rust SMB2 wire foundation: Negotiate, NTLMv2, TreeConnect.
- **Phase 2** (Done) — DCE/RPC primitives: NDR20, PDU framing, NTLMSSP auth verifier, MS-SRVS `NetrShareEnum`.
- **Phase 3** (In Progress, **blocking**) — `FSCTL_PIPE_TRANSCEIVE` over SMB2. This unlocks DCE/RPC-over-named-pipe, which in turn unlocks porting every enumeration and execution module to pure Rust.
- **Phase 4** (Planned) — Port read-only modules: `info`, `shares`, `users`.
- **Phase 5** (Planned) — Port write-side modules: `exec`, `browser`.
- **Phase 6** (Planned) — Port secret-dumping: `dump` (SAM/LSA).
- **Phase 7** (Planned) — Retire Windows-native code path entirely.

**What this means for agents:**
- If you modify `netraze-dcerpc` or `netraze-protocols::smb2`, run the Samba integration suite.
- If you add a new DCE/RPC interface, follow the fixture pattern: write a `gen_*.py` script that uses Impacket to generate bytes, paste the bytes into a Rust test, and add a round-trip test.
- Do not add new Windows-native code in `netraze-dcerpc` — that crate must remain 100% cross-platform.

---

## Key Files for Orientation

| File | Why it matters |
|---|---|
| `Cargo.toml` | Workspace members, shared dependencies, lints. |
| `rust-toolchain.toml` | Pins stable Rust + clippy + rustfmt. |
| `docs/architecture.md` | Target architecture (in French). Dependency rules and evolution plan. |
| `docs/migration-roadmap.md` | Detailed structural roadmap + cross-platform portage plan (Phases 1–7). |
| `tests/samba/README.md` | Operator guide for the live integration harness. |
| `crates/netraze-dcerpc/tests/gen_srvs_fixture.py` | Pattern for Impacket-pinned byte fixtures. |
| `crates/netraze-protocols/tests/samba_integration.rs` | Live SMB2/NTLM smoke tests against the Samba container. |
| `.github/workflows/ci.yml` | CI gates and their rationale. |

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

# Strict lint (required before PR)
cargo fmt --all --check
cargo clippy -p netraze-dcerpc --all-targets -- -D warnings

# Samba integration (requires Docker)
docker compose -f tests/samba/docker-compose.yml up -d --wait
cargo test -p netraze-protocols --test samba_integration -- --ignored --test-threads=1
docker compose -f tests/samba/docker-compose.yml down -v
```
