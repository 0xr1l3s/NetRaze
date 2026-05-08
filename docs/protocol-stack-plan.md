# NetRaze — Protocol stack plan

**Vivant.** Mise à jour à chaque PR qui touche une interface protocol ou
qui ajoute une opération wire-level.

---

## Pourquoi ce document existe

NetRaze remplace progressivement les API Windows-natives par une stack
réseau pure-Rust qui tourne sur tout OS attaquant. Le "comment" est
documenté dans `migration-roadmap.md` (phases A→D pour SMB).

Ce document-ci est **différent** : c'est l'inventaire opérationnel de
**chaque interface protocol** dont NetRaze a besoin pour couvrir un
pentest AD moderne, et **où on en est sur chacune**. C'est le tableau
qu'on regarde quand on se demande "qu'est-ce qu'on attaque ensuite ?"
et "est-ce que tel module post-exploit est utilisable aujourd'hui ?"

**Stratégie générale** : pas de port en bloc d'Impacket — les ~150k LOC
Python évoluent et 60-70% ne servent jamais en pentest. À la place, on
porte **à la demande**, par crate Rust dédié, avec Impacket comme
**oracle byte-pour-byte** (cf. les `gen_*_fixture.py` de
`crates/netraze-dcerpc/tests/`).

---

## Légende des statuts

| Marqueur | Sens |
|---|---|
| ✅ | Implémenté + testé unit + validé live (Samba ou Win VM) |
| 🟡 | Implémenté + tests unit, **pas encore validé live** |
| 🔵 | En cours d'implémentation |
| 🔜 | Planifié, prochaine vague |
| ⚪ | Identifié mais hors scope v1 |
| ❌ | Décidé hors scope (avec justification) |

---

## Couches transverses

| Couche | Crate | Statut | Notes |
|---|---|---|---|
| TCP transport (timeout, IPv4/IPv6) | `std::net` | ✅ | Pas besoin de wrapper — `std::net::TcpStream` suffit |
| TLS (rustls) | `rustls` | ⚪ | Requis pour LDAPS, RPC over HTTPS, WinRM. Out v1 |
| ASN.1 / DER / BER | TBD | 🔜 | Choix : crate maison `netraze-asn1` partagé entre LDAP + Kerberos vs `rasn`/`asn1` externe. Décision à prendre au démarrage de `netraze-ldap` |
| NTLMSSP (NEGOTIATE/CHALLENGE/AUTHENTICATE + seal/sign) | `netraze-dcerpc::auth` | ✅ | Réutilisable cross-protocol (SMB, RPC, LDAP, MSSQL). Vendoring depuis `protocols::smb::ntlm` à factoriser dans un `netraze-ntlm` dédié quand on aura un 3e consommateur |
| SPNEGO wrapping | `protocols::smb::ntlm::wrap_spnego_*` | 🟡 | Marche pour SMB. Vérifier compat LDAP SASL/GSS-SPNEGO quand on attaquera `netraze-ldap` |
| Kerberos AS-REQ/REP, TGS-REQ/REP | `netraze-kerberos` (à créer) | 🔜 | Requis pour AS-REProast, Kerberoast, S4U |

---

## SMB / DCE-RPC stack

### `netraze-protocols::smb` (transport SMB2 + ntlm)

| Op | Statut | Test |
|---|---|---|
| SMB2 Negotiate (dialects 2.02, 2.10) | ✅ | unit |
| Session Setup NTLMSSP NTLMv2 | ✅ | live Samba |
| **GUEST/NULL session downgrade detection** | ✅ | post-fix de `0xC0000022` mystérieux |
| Tree Connect / Tree Disconnect | ✅ | live |
| Diagnostic actionnable sur tree_connect failures | ✅ | unit |
| Pipe Open/Transceive/Write/Close | ✅ | live |
| File CREATE / READ (read_full_file) | ✅ | live (utilisé par dump_rpc) |
| File WRITE | 🔜 | Phase D — bloque exec_rpc |
| File DELETE (DELETE_ON_CLOSE) | 🔜 | Phase D — cleanup côté exec |
| Query Directory (FileBothDirectoryInformation) | 🔜 | Phase D — bloque browser_rpc |
| Create Directory (FILE_DIRECTORY_FILE) | 🔜 | Phase D |
| **SMB signing (HMAC-SHA256)** | ⚪ | Bloque les targets avec "require signing" — à activer quand on en croisera |
| SMB3 encryption (AES-CCM/GCM) | ⚪ | Out v1 — la plupart des cibles acceptent SMB2 unencrypted |
| Kerberos session setup (AP-REQ in SPNEGO) | 🔜 | Couplé avec `netraze-kerberos` |

### `netraze-dcerpc` (DCE/RPC v5 + NDR + auth + interfaces)

| Couche | Statut |
|---|---|
| `pdu` Bind/BindAck/Auth3/Request/Response/Fault | ✅ |
| `ndr` (writer/reader, deferred queue, RPC_SID, RPC_UNICODE_STRING, context_handle) | ✅ |
| `auth` NTLMSSP PKT_PRIVACY (seal/sign) | ✅ |
| `channel::RpcChannel` (bind, bind_authenticated, multi-frag) | ✅ |

### Interfaces RPC (`netraze-dcerpc::interfaces`)

| Interface | UUID | Pipe | Opnums implémentés | Statut | Module consumer |
|---|---|---|---|---|---|
| **srvsvc** | `4b324fc8-…` | srvsvc | `NetrShareEnum` (15), `NetrServerGetInfo` (21) | ✅ | `smb::shares`, `smb::info` |
| **samr** | `12345778-…` | samr | Connect2 (62), CloseHandle (1), EnumDomains (6), LookupDomain (5), OpenDomain (7), EnumUsers (13), OpenUser (34), QueryInfoUser (36) | ✅ | `smb::users` |
| **winreg** | `338cd001-…` | winreg | OpenLocalMachine (2), CloseKey (5), OpenKey (15), QueryInfoKey (16), SaveKey (20) | ✅ | `smb::dump` |
| **scmr** | `367abb81-…` | svcctl | OpenSCManagerW (15), OpenServiceW (16), CloseServiceHandle (0), QueryServiceStatus (6), StartServiceW (19), ChangeServiceConfigW (11) | ✅ | `smb::dump` (auto-start RemoteRegistry) |
| **scmr** suite | — | — | CreateServiceW (12), DeleteService (2), ControlService (1) | 🔜 | Bloque `exec_rpc` (smbexec) |
| **lsarpc** | `12345778-…` | lsarpc | OpenPolicy2, LookupSids, LookupNames, QueryInformationPolicy | 🔜 | Account/SID resolution, helps secret naming dans LSA dump |
| **drsuapi** | `e3514235-…` | lsass (RPC over named pipe) | DRSBind, DRSCrackNames, DRSGetNCChanges | 🔜 | **DCSync** — jackpot du pentest AD |
| **wkssvc** | `6bffd098-…` | wkssvc | NetrWkstaGetInfo, NetrWkstaUserEnum | ⚪ | Alternative à srvsvc pour info — pas urgent |
| **atsvc** | `1ff70682-…` | atsvc | NetrJobAdd, NetrJobEnum, NetrJobDel | ⚪ | Alternative à smbexec via task scheduler — utile si SCMR est bloqué EDR |
| **rprn** (printer bug → coerced auth) | `12345678-…` | spoolss | RpcRemoteFindFirstPrinterChangeNotificationEx | ⚪ | PrinterBug exploit — useful for relay attacks |
| **efsrpc** (PetitPotam) | `c681d488-…` | efsrpc, lsarpc | EfsRpcOpenFileRaw | ⚪ | PetitPotam coerced auth — critical for ADCS attacks |

---

## LDAP stack

### `netraze-ldap` (à créer)

C'est la priorité #1 immédiate — débloquer `enum_users` AD stable et
préparer le terrain pour Kerberoasting.

| Module | Statut | Notes |
|---|---|---|
| `ber` (BER/DER encoder/decoder) | 🔜 | Décision : crate maison ou `rasn`. Si `rasn`, accepter +1 dep workspace |
| `message` (LDAPMessage envelope) | 🔜 | RFC 4511 §4.1.1 |
| `bind::simple` (cleartext credentials) | 🔜 | Quick win, mais peu utilisé en prod |
| `bind::sasl_gss_spnego` (NTLMSSP wrapped) | 🔜 | **C'est le bind qui fait marcher** GetADUsers.py-equivalent. Réutilise `dcerpc::auth::NtlmBinder` |
| `search::request` + `search::result_entry` | 🔜 | RFC 4511 §4.5 |
| `controls::paged_results` (1.2.840.113556.1.4.319) | 🔜 | Obligatoire — sans ça, search retourne max 1000 entrées |
| `controls::sd_flags` (security descriptor) | ⚪ | Pour ACL enum (BloodHound-equivalent) |
| `client::LdapClient` (TCP + bind + search loop) | 🔜 | Async, tokio |

### Modules NetRaze qui consommeront `netraze-ldap`

| Use case | Statut | Notes |
|---|---|---|
| `enum_users_ldap` (≈ `GetADUsers.py`) | 🔜 | Filtre `(&(sAMAccountType=805306368))`, attrs `sAMAccountName, userAccountControl, lastLogon, memberOf, adminCount` |
| `enum_computers_ldap` (≈ `GetMachineAccounts.py`) | 🔜 | Filtre `(&(sAMAccountType=805306369))` |
| `enum_groups_ldap` | 🔜 | Filtre `(objectClass=group)` |
| `find_kerberoastable` | 🔜 | Filtre `(&(samAccountType=805306368)(servicePrincipalName=*))` — feeds `netraze-kerberos::kerberoast` |
| `find_asreproastable` | 🔜 | Filtre `(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` — feeds `netraze-kerberos::asreproast` |
| `find_unconstrained_delegation` | 🔜 | UAC bit `TRUSTED_FOR_DELEGATION` |
| RootDSE fetch (defaultNamingContext) | 🔜 | Préliminaire à toute search |

### Smart `enum_users` orchestration

```
enum_users(target, cred):
  if tcp_open(target, 389) and target_looks_like_dc(target):
    try LDAP path → return on success
    log warn "LDAP failed, falling back to SAMR"
  fallback to SAMR path
```

---

## Kerberos stack

### `netraze-kerberos` (à créer après LDAP)

| Op | Statut | Use case |
|---|---|---|
| ASN.1 Kerberos types (PA-DATA, KrbPrincipalName, …) | 🔜 | Base |
| AS-REQ / AS-REP | 🔜 | TGT acquisition + AS-REProast |
| TGS-REQ / TGS-REP | 🔜 | Service ticket + Kerberoast |
| Pre-auth disabled detection | 🔜 | AS-REProast filter |
| Encrypt/decrypt RC4-HMAC, AES128/256-CTS-HMAC-SHA1-96 | 🔜 | Hash extraction des roastables |
| Krb5 ASCII format (hashcat -m 18200, 13100) | 🔜 | Output |
| Pass-the-ticket (kirbi/ccache) | ⚪ | Out v1 |
| S4U2Self / S4U2Proxy | ⚪ | Constrained delegation abuse — phase 2 |
| Diamond/Sapphire ticket | ⚪ | Phase 3 |

---

## DCOM / WMI stack

| Crate | Statut | Use case |
|---|---|---|
| `netraze-dcom` (à créer) | ⚪ | wmiexec, dcomexec — alternative à smbexec quand SCM est watched |
| `netraze-wmi` (consumer de dcom) | ⚪ | Win32_Process.Create pour exec, Win32_Service.Start pour mvt latéral |

**Hors scope v1** mais essentiel à terme. Estimation ~3 semaines de port (DCOM est lourd : OXID resolver, IRemUnknown, IDispatch).

---

## MSSQL / RDP / SSH

| Protocole | Statut | Stratégie |
|---|---|---|
| MSSQL (TDS) | ⚪ | Utiliser la crate `tiberius` (pure-Rust, async). Pas de port from-scratch |
| RDP | ⚪ | `rdp-rs` ou port maison de `pyrdp`. Lourd. Phase 3 |
| SSH | ⚪ | `russh` ou `thrussh`. Standard, pas de réinvention |
| FTP | ⚪ | `suppaftp`. Standard |

---

## Modules NetRaze post-exploit (consumers)

Inventaire des modules attaquant (modules NetExec ↔ équivalent NetRaze).
Statut **module-level** — peut composer plusieurs interfaces RPC.

### Reconnaissance

| Module NetExec | Crate consumer | Statut | Bloqué par |
|---|---|---|---|
| `enum_av` | `protocols::smb::enum_av` | ❌ Windows-only v1 | DCOM/WMI ou SCMR enum services + IPC$ pipe listing |
| `enum_dns` | — | 🔜 | netraze-ldap (DNS records dans `MicrosoftDNS` partition) |
| `enum_ca` | — | ⚪ | netraze-ldap + netraze-dcerpc::interfaces::icpr (cert enrollment) |
| `gpp_password` | `modules::reconnaissance::gpp_password` | ✅ (factory only — logic à porter) | smb file ops + Crypto AES (déjà là) |
| `enum_logged_in` | — | 🔜 | wkssvc.NetrWkstaUserEnum |
| `enum_shares_v_admin` | — | ✅ | déjà fait via shares_rpc |
| `enum_users_loggedon` | — | 🔜 | samr.SamrEnumerateUsersInDomain |

### Active Directory

| Module | Statut | Bloqué par |
|---|---|---|
| `add_computer` | ✅ factory | netraze-ldap (LDAP add operation) |
| `adcs` (cert template enum) | ✅ factory | netraze-ldap (CN=Configuration partition) |
| `coerce_plus` (PetitPotam, PrinterBug, ShadowCoerce) | ✅ factory | dcerpc.efsrpc + dcerpc.rprn |
| `dcsync` | 🔜 | dcerpc.drsuapi |
| `kerberoast` | 🔜 | netraze-ldap + netraze-kerberos |
| `asreproast` | 🔜 | netraze-ldap + netraze-kerberos |

### Credentials

| Module | Statut | Bloqué par |
|---|---|---|
| SAM dump | ✅ | dump_rpc done |
| LSA dump | 🟡 | lsa.rs done, besoin validation Win VM |
| NTDS.dit dump (DCSync) | 🔜 | dcerpc.drsuapi |
| DPAPI extraction | ⚪ | Phase 2 |
| AWS credentials harvest | ✅ factory | smb file_browser + parsing |

### Exec / lateral movement

| Module | Statut | Bloqué par |
|---|---|---|
| smbexec (SCMR) | 🔜 | Phase D — SMB2 file ops + scmr CreateServiceW |
| atexec | ⚪ | dcerpc.atsvc |
| wmiexec | ⚪ | netraze-dcom + netraze-wmi |
| psexec | ⚪ | smbexec variant — fait en même temps |

---

## Roadmap d'attaque (ordre opérationnel)

L'ordre **chronologique** dans lequel je recommande d'avancer.
Chaque ligne débloque les suivantes.

| # | Chantier | Coût | Débloque |
|---|---|---|---|
| 1 | **Phase D.1** — SMB2 file ops (write, delete, query_directory, create_directory) | 4j | smbexec, browser, NTDS dump path |
| 2 | **Phase D.3** — `exec_rpc` via SCMR (CreateServiceW + StartServiceW + cleanup) | 4j | Lateral movement complet |
| 3 | **Phase D.4** — `browser_rpc` (pure SMB2) + audit call sites desktop | 3j | Desktop file browser cross-platform |
| 4 | **Crate `netraze-ldap`** — BER + LDAPMessage + bind SASL/NTLMSSP + search + paged_results | 5j | enum_users AD stable, enum_computers, enum_groups, find_kerberoastable |
| 5 | **Crate `netraze-kerberos`** — ASN.1 Kerberos + AS-REQ/REP + TGS-REQ/REP + RC4/AES decrypt | 8j | AS-REProast + Kerberoast |
| 6 | `dcerpc.lsarpc` — OpenPolicy2 + LookupSids/Names | 3j | Account naming dans LSA dump |
| 7 | `dcerpc.drsuapi` — DRSBind + DRSGetNCChanges | 10j | **DCSync** = NTDS.dit complet sans toucher disque |
| 8 | SMB signing HMAC-SHA256 | 4j | Targets avec "require signing" |
| 9 | `netraze-dcom` + `netraze-wmi` | 15j | wmiexec, dcomexec |
| 10 | Coerced auth modules (PetitPotam/PrinterBug) | 5j | Relay attacks → ADCS abuse |

**Total ~60j (≈3 mois plein temps)** pour un NetRaze qui couvre les use
cases pentest AD modernes essentiels. Comparé au "porter tout Impacket"
qui prendrait ≥2 ans pour 80% de code mort.

---

## Comment ce document évolue

À **chaque PR** qui touche une interface ou ajoute une op :

1. Marquer la ligne du tableau correspondant : ⚪→🔵→🟡→✅
2. Ajouter une ligne dans la roadmap d'attaque si on a découvert un blocage non listé
3. Si une décision d'architecture est prise (ex: choix `rasn` vs ber maison), la documenter dans la section concernée
4. Si on retire un module du scope v1, le marquer ❌ avec la justification

L'objectif : à n'importe quel instant, ouvrir ce fichier doit donner une
réponse claire à "où on en est" et "qu'est-ce qu'on attaque ensuite".
