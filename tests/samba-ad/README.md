# Samba AD LDAP/NTLM integration harness

This directory contains a disposable Samba Active Directory Domain Controller
used only for NetRaze's local LDAP/NTLM integration tests. It is separate from
`tests/samba/`, which remains the standalone SMB/SAMR fixture for guest and
anonymous-session behavior.

The harness uses the Samba project's AD DC container image. The image is pinned
by digest, provisions `NETRAZE.TEST` from `domain.json`, and publishes services
only on the loopback interface.

## Test directory

| Setting | Value |
|---|---|
| LDAP endpoint | `127.0.0.1:1389` |
| SMB endpoint | `127.0.0.1:2445` |
| Realm | `NETRAZE.TEST` |
| NetBIOS domain | `NETRAZE` |
| Administrator password | `NetRaze-Admin-42!` |
| LDAP test account | `alice` / `Wonderland-42!` |
| Additional users | `bob`, `carol` |

Every credential above is public test data. Never reuse it outside this
disposable harness.

## Run the LDAP/NTLM tests

```shell
docker compose -f tests/samba-ad/docker-compose.yml up -d --wait
cargo test -p netraze-protocols --test ldap_samba_ad -- --ignored --test-threads=1
docker compose -f tests/samba-ad/docker-compose.yml down -v
```

The ignored Rust suite validates:

- GSS-SPNEGO/NTLMv2 password authentication over LDAP port 389.
- NT-hash authentication without passing the plaintext password to the bind.
- NTLM sign-and-seal by performing RootDSE and search operations after bind.
- RootDSE `defaultNamingContext` discovery.
- Paged AD user enumeration with a page size of two.
- Deterministic case-insensitive result ordering and LDAP source metadata.
- Full read-only inventory coverage for users, groups, computers, OUs and
  containers, domain topology, privileged principals, SPNs, and domain/LDAP
  security policy.

Anonymous LDAP bind and empty-password Guest NTLM have loopback/unit tests,
but this ignored live suite currently exercises authenticated `alice` only.
It does not assert server-side anonymous directory access or Guest policy.

The tests intentionally use a fixed loopback endpoint and provide no
environment-variable override. They cannot be redirected to a real AD server.

## Reset and troubleshooting

Provisioning state is stored in the `samba-ad-state` Docker volume. Remove it
after changing `domain.json`:

```shell
docker compose -f tests/samba-ad/docker-compose.yml down -v
docker compose -f tests/samba-ad/docker-compose.yml up -d --wait
```

If startup does not become healthy, inspect the provisioning log:

```shell
docker compose -f tests/samba-ad/docker-compose.yml logs samba-ad
```

The official image currently requires a privileged container because Samba AD
uses filesystem extended attributes while provisioning its directory state.
