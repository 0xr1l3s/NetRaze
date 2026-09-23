# Samba AD LDAP/NTLM integration harness

This directory contains a disposable Samba Active Directory Domain Controller
used only for NetRaze's local LDAP/NTLM integration tests. It is separate from
`tests/samba/`, which remains the standalone SMB/SAMR fixture for guest and
anonymous-session behavior.

Unit tests validate BER, NTLM, and paging in isolation; this harness checks
those operations against a real directory server. The Samba project's AD DC
image is pinned by digest, provisions `NETRAZE.TEST` from `domain.json`, and
publishes LDAP and SMB only on the loopback interface.

---

## What runs here

| File | Role |
|---|---|
| `docker-compose.yml` | Starts the digest-pinned `quay.io/samba.org/samba-ad-server` on loopback ports 1389 (LDAP) and 2445 (SMB). The healthcheck waits for a directory query to succeed. |
| `domain.json` | Password-free template that provisions the fixed test realm, users, groups, and domain controller. |
| `inject-secrets.py` | Injects required environment-provided passwords into a mode-0600 runtime configuration inside the container, then replaces itself with Samba. |
| `crates/netraze-protocols/tests/ldap_samba_ad.rs` | Seven ignored, fixed-endpoint integration tests for binds, searches, paging, referrals, inventory, and BloodHound CE export. |

The container runs privileged because Samba AD provisioning needs filesystem
extended attributes. Do not run it on an untrusted Docker host.

## Test directory

| Setting | Value |
|---|---|
| LDAP endpoint | `127.0.0.1:1389` |
| SMB endpoint | `127.0.0.1:2445` |
| Realm | `NETRAZE.TEST` |
| NetBIOS domain | `NETRAZE` |
| Administrator password | Runtime-only `NETRAZE_SAMBA_AD_ADMIN_PASSWORD` |
| LDAP test account | `alice` / runtime-only `NETRAZE_SAMBA_AD_PASSWORD` |
| Additional users | `bob`, `carol` (same runtime-only test password) |
| Provisioned groups | `interns`, `operators` |
| Domain controller | `dc1` (`DC1$` in computer enumeration) |

Generate fresh passwords for each run and never reuse them outside this
disposable harness. Neither password has a repository default.

---

## Running locally

### Start the domain controller

```shell
export NETRAZE_SAMBA_AD_ADMIN_PASSWORD="Aa1!$(openssl rand -hex 20)"
export NETRAZE_SAMBA_AD_PASSWORD="Aa1!$(openssl rand -hex 20)"
docker compose -f tests/samba-ad/docker-compose.yml up -d --wait
```

`--wait` blocks until the container's LDAP healthcheck passes. The first
provisioning run can take longer than subsequent starts. Run Cargo in the same
shell so the test client receives the provisioned account password.

### Run the LDAP/NTLM integration tests

```shell
cargo test -p netraze-protocols --test ldap_samba_ad -- --ignored --test-threads=1
```

The suite is ignored by ordinary `cargo test`. Keep `--test-threads=1` so
the shared directory fixture is exercised sequentially during local runs.

### Test cases

| Test | Covers |
|---|---|
| `password_bind_discovers_root_dse_and_enumerates_users` | GSS-SPNEGO/NTLMv2 password bind, protected RootDSE, `defaultNamingContext`, and LDAP-source user records. |
| `nt_hash_bind_enumerates_multiple_pages_in_stable_order` | Pass-the-hash bind, page size two, all provisioned users, and deterministic case-insensitive order. |
| `full_inventory_covers_directory_structure_and_security_sections` | Paged read-only inventory of users, groups, computers, OUs/containers, topology, privileged principals, SPNs, and reported domain/LDAP policy; no partial-section error. |
| `bloodhound_ce_export_writes_schema_v6_json_and_zip` | NetRaze LDAP collection through the RustHound-CE parser, schema-v6 metadata and object counts in every loose JSON file, plus a non-empty CE ZIP archive. Output is written to a unique temporary directory and removed by the test. |
| `anonymous_bind_can_read_root_dse_without_ntlm_credentials` | Empty-name/empty-password anonymous bind, unprotected RootDSE read, and Unbind. |
| `wrong_password_and_guest_do_not_authorize_ldap_searches` | Wrong-password and empty-password `Guest` NTLM attempts are rejected and do not authorize a subsequent search. |
| `protected_search_supports_compound_escaped_filter_and_base_scope` | Signed/sealed compound search with a hex-escaped assertion, base-object lookup, and returned referrals. |

The tests issue no LDAP write operations. Authentication may still update
server-managed logon metadata.

### Tear down

```shell
docker compose -f tests/samba-ad/docker-compose.yml down -v
unset NETRAZE_SAMBA_AD_ADMIN_PASSWORD NETRAZE_SAMBA_AD_PASSWORD
```

`-v` removes the disposable `samba-ad-state` volume and its provisioned
accounts. Only tear down a harness you started for this run; omit `-v` if
you intentionally want to retain its state.

---

## Known Samba AD behavior and limits

- Anonymous bind can read RootDSE. This does **not** prove that anonymous
  users can enumerate the domain naming context; that policy is not asserted.
- The provisioned `Guest` account has no usable empty-password NTLM LDAP
  login. A `Guest` failure is not an anonymous bind fallback.
- A domain subtree search returns referrals for other naming contexts,
  including `CN=Configuration,DC=netraze,DC=test`. NetRaze reports them
  alongside entries and does not automatically follow them with credentials.
- The named-account tests perform searches after NTLM bind, requiring the
  LDAP SASL sign-and-seal layer. The anonymous RootDSE test uses plain BER.

Not covered here: LDAPS, StartTLS, Kerberos, channel binding, cross-domain
referral chasing, LDAP writes, or active probes of server signing and
channel-binding enforcement. The Security tab reports those untested
checks as `Not tested`; this suite only validates values the directory
returns and the protection negotiated for its own NTLM session. SMB/SAMR
guest and null-session behavior belongs to the separate
[standalone Samba harness](../samba/README.md).

---

## Fixed endpoint and CI

The tests intentionally use a fixed loopback endpoint and provide no
environment-variable override. They cannot be redirected to a real AD server.
If port 1389 or 2445 is occupied, stop the conflicting local service before
running the suite; changing only the Compose port mapping will not change the
Rust test endpoint.

The ignored suite is not run by the tag-driven GitHub Actions release
workflow. For fast checks without Docker, run:

```shell
cargo test -p netraze-protocols --lib
cargo test -p netraze-protocols --test ldap_samba_ad
```

The second command compiles the live suite but leaves its seven tests ignored.

---

## Reset and troubleshooting

Provisioning state is stored in the `samba-ad-state` Docker volume. If you
change `domain.json` and want a fresh directory, remove the disposable volume
and reprovision:

```shell
docker compose -f tests/samba-ad/docker-compose.yml down -v
export NETRAZE_SAMBA_AD_ADMIN_PASSWORD="Aa1!$(openssl rand -hex 20)"
export NETRAZE_SAMBA_AD_PASSWORD="Aa1!$(openssl rand -hex 20)"
docker compose -f tests/samba-ad/docker-compose.yml up -d --wait
```

If startup does not become healthy, inspect the provisioning log:

```shell
docker compose -f tests/samba-ad/docker-compose.yml logs samba-ad
```

If the container is healthy but Rust cannot connect, confirm the loopback
port bindings:

```shell
docker port netraze-samba-ad
```

The expected mappings are `389/tcp -> 127.0.0.1:1389` and
`445/tcp -> 127.0.0.1:2445`. A stale volume after fixture changes or a
port collision are the first things to check; do not redirect the tests to
an unrelated directory server.
