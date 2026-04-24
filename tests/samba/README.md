# Samba integration test harness

This directory holds the pinned Samba server used to exercise NetRaze's
SMB2 / NTLMSSP / DCE-RPC stack against a real SMB implementation.

Unit tests run in milliseconds but can't catch bugs that only surface on
the wire — NDR alignment drift, an NTLMv2 key-schedule off-by-one, an SMB2
header field written with the wrong size. This harness gives the Rust code
a deterministic peer to talk to, so those failures reproduce locally and
in CI.

---

## What runs here

| File | Role |
|---|---|
| `docker-compose.yml` | Spins up `servercontainers/samba:smbd-only-latest` on `127.0.0.1:1445` (port 445 is usually taken by the OS SMB client). |
| `smb.conf` | Pinned share inventory. Share names and `comment =` values are load-bearing — Rust tests assert on them. |

The container provisions a single user, `alice` / `wonderland`, in the
`NETRAZE` workgroup. These credentials are test-only and published here
openly — **do not reuse them anywhere real**.

### Share inventory (matches assertions in the Rust tests)

| Share | Type | Auth | Comment |
|---|---|---|---|
| `private` | Disk | `alice` only | `Alice's private share` |
| `public`  | Disk | guest-ok, read-only | `Public read-only` |
| `ADMIN$`  | Disk | `alice` admin, not browseable | `Remote Admin` |

---

## Running locally

### Start the container

```shell
docker compose -f tests/samba/docker-compose.yml up -d --wait
```

`--wait` blocks until the healthcheck (`smbcontrol smbd ping`) passes, so
the tests don't race the daemon's startup.

### Run the Rust integration tests

The smoke tests are in `crates/netraze-protocols/tests/samba_integration.rs`
and are `#[ignore]` by default — you need to pass `--ignored` to run them:

```shell
cargo test -p netraze-protocols --test samba_integration -- --ignored --test-threads=1
```

`--test-threads=1` is belt-and-braces: Samba handles concurrent sessions
fine, but parallel session setup against the same account occasionally
races on the passdb lock in Samba 4.x.

### What the smoke tests cover

- SMB2 Negotiate handshake (dialect, capabilities, security mode)
- NTLMSSP Negotiate → Challenge → Authenticate dance
- NTLMv2 response computed from `NT-hash("wonderland")`
- Tree Connect to `\\server\IPC$` (the named-pipe entrypoint)
- Negative path: a wrong password must be rejected

Not covered yet:
- `FSCTL_PIPE_TRANSCEIVE` / DCE-RPC over named pipe — blocked on SMB2
  IOCTL support in `smb2.rs`. Once that lands, a follow-up suite in
  `crates/netraze-dcerpc/tests/` will drive the full SRVSVC stack
  end-to-end against the same container.
- SMB signing / encryption — we do the NTLM dance but don't yet negotiate
  signing against Samba.

### Tear down

```shell
docker compose -f tests/samba/docker-compose.yml down -v
```

`-v` wipes the `samba-passdb` volume. Skip it if you want to keep the
account database across restarts; include it if you've edited
`smb.conf`'s user configuration and want a clean provisioning on next
`up`.

---

## Pointing at a non-default endpoint

The tests read `NETRAZE_SAMBA_ADDR` from the environment (default
`127.0.0.1:1445`). Override it when:

- You've remapped the host port in `docker-compose.yml`.
- You're running Samba as a CI service container on a different host.
- You're pointing at a dev box's native Samba install.

```shell
NETRAZE_SAMBA_ADDR=10.0.0.50:445 \
  cargo test -p netraze-protocols --test samba_integration -- --ignored
```

---

## CI

The `samba-integration` job in `.github/workflows/ci.yml` runs this
harness automatically on Linux runners, but **only** for:

- Pushes to `main` / `master`
- Manual `workflow_dispatch` triggers

Pull requests don't trigger it by default — the Impacket-pinned byte
fixtures in `netraze-dcerpc` already catch most regressions, and
docker-in-Actions adds ~1 minute of cold-start per run. Trigger it
manually from the Actions tab when a PR touches SMB2, NTLM, or DCE-RPC
code paths.

---

## Troubleshooting

### `NT_STATUS_LOGON_FAILURE` against a freshly started container

Usually means a stale passdb volume from a prior run whose `smb.conf`
didn't successfully provision `alice`. Nuke the volume and restart:

```shell
docker compose -f tests/samba/docker-compose.yml down -v
docker compose -f tests/samba/docker-compose.yml up -d --wait
docker exec netraze-samba pdbedit -L   # should show `alice:1000:`
```

### `testparm` warns about an invalid parameter

Samba's accepted values for `ntlm auth` are `yes`, `no`, `ntlmv2-only`,
`mschapv2-and-ntlmv2-only`, `disabled`. Older docs sometimes mention
`mandatory` — that's not valid and will silently fall back to the
default (which allows LM/NTLMv1).

### The container is healthy but `cargo test` can't connect

Check the port mapping is actually `127.0.0.1:1445:445` (not `0.0.0.0:…`
or the wrong host port):

```shell
docker port netraze-samba
```

If it says something like `445/tcp -> 127.0.0.1:1445`, you're good.

### Regenerating the `NT-hash("wonderland")` reference

The `nt_hash_of_wonderland_is_md4_of_utf16le` test has a precomputed NT
hash baked in. Python 3.11's stdlib `hashlib` dropped MD4 because OpenSSL
did — regenerate via pycryptodome or `openssl dgst -md4`:

```shell
docker run --rm python:3.11-alpine sh -c \
  "pip install pycryptodome -q && python -c '\
    from Crypto.Hash import MD4; \
    h = MD4.new(); h.update(\"wonderland\".encode(\"utf-16le\")); \
    print(h.hexdigest())'"
# → 3e057cd123205aa168af5f121716b335
```
