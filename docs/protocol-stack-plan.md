# NetRaze — Protocol stack plan

**Vivant.** Mise à jour à chaque PR qui touche une interface protocol ou
qui ajoute une opération wire-level.

---

## Pourquoi ce document existe

NetRaze a remplacé les API Windows-natives par une stack réseau pure-Rust
qui tourne sur tout OS attaquant — le portage est **terminé** (phases
1–7 de `migration-roadmap.md`, plus l'accès anonymous/guest). Le "comment"
est documenté dans `migration-roadmap.md`.

Ce document-ci est **différent** : c'est l'inventaire opérationnel de
**chaque interface protocol** dont NetRaze a besoin pour couvrir un
pentest AD moderne, et **où on en est sur chacune**. C'est le tableau
qu'on regarde quand on se demande "qu'est-ce qu'on attaque ensuite ?"
et "est-ce que tel module post-exploit est utilisable aujourd'hui ?"

**Stratégie générale** : pas de port en bloc d'Impacket — les ~150k LOC
Python évoluent et 60-70% ne servent jamais en pentest. À la place, on
porte **à la demande**, par module Rust ciblé, avec Impacket comme
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
| TCP transport (timeout, IPv4/IPv6) | `std::net` + `tokio::net` | ✅ | SMB utilise son transport existant ; LDAP est async avec délais et plafond de PDU |
| TLS (rustls) | `rustls` | ⚪ | Requis pour LDAPS, RPC over HTTPS, WinRM. Out v1 |
| ASN.1 / DER / BER | `rasn` + `rasn-ldap` dans `netraze-protocols::ldap` | ✅ | Modèle RFC 4511 maintenu par `rasn-ldap`; façade interne étroite |
| NTLMSSP (NEGOTIATE/CHALLENGE/AUTHENTICATE + seal/sign) | `netraze-protocols::ntlm` | ✅ | Implémentation LDAP SASL partagée dans le crate protocoles; SMB et DCE/RPC restent inchangés jusqu'à migration validée |
| SPNEGO wrapping | `netraze-protocols::ntlm::spnego` | ✅ | Parsing borné et `mechListMIC` validés pour LDAP SASL/GSS-SPNEGO |
| Kerberos AS-REQ/REP, TGS-REQ/REP | `netraze-protocols::kerberos` (à créer) | 🔜 | Requis pour AS-REProast, Kerberoast, S4U |

---

## SMB / DCE-RPC stack

### `netraze-protocols::smb` (transport SMB2 + ntlm)

| Op | Statut | Test |
|---|---|---|
| SMB2 Negotiate (dialects 2.02, 2.10) | ✅ | unit |
| Session Setup NTLMSSP NTLMv2 | ✅ | live Samba |
| **GUEST/NULL session downgrade detection** | ✅ | post-fix de `0xC0000022` mystérieux |
| **Anonymous (null session) + guest login** | ✅ | `connect_anonymous` (AUTHENTICATE vide, IS_NULL accepté) + `connect_guest` (user sans secret, IS_GUEST accepté) ; dispatch par forme du credential dans `connect_session` / `SmbClient::connect` ; live Samba (anonymous_samba) + parité Impacket |
| **Bind DCE non authentifié pour guest/null** | ✅ | `bind_interface_over_smb` route les credentials guest/null vers `RpcChannel::bind` (niveau auth NONE, comme Impacket) — l'AUTH3 NTLMSSP dans le pipe avec un user inexistant est fauté `0x5` par Samba à l'appel. Enum shares + users guest vérifiée, parité Impacket byte-pour-byte |
| Tree Connect / Tree Disconnect | ✅ | live |
| Diagnostic actionnable sur tree_connect failures | ✅ | unit |
| Pipe Open/Transceive/Write/Close | ✅ | live |
| File CREATE / READ (read_full_file) | ✅ | live Samba (utilisé par dump_rpc) |
| File WRITE | ✅ | Phase D — write_full_file (60 KiB chunks) ; round-trip live Samba via browser upload |
| File DELETE (DELETE_ON_CLOSE) | ✅ | Phase D — delete_on_close ; live Samba (browser + cleanup exec) |
| Query Directory (FileBothDirectoryInformation) | ✅ | Phase D — boucle QUERY_DIRECTORY + resume cookie ; live Samba (browser, pipe listing enum_av) |
| Create Directory (FILE_DIRECTORY_FILE) | ✅ | Phase D — live Samba (browser) |
| **SMB signing (HMAC-SHA256)** | ✅ | Dialectes 2.0.2/2.1 — HMAC-SHA256(ExportedSessionKey) sur le message entier ; appliqué dans `send_packet` quand le Negotiate serveur exige la signature (DC). Vérifié live contre un DC |
| SMB3 encryption (AES-CCM/GCM) | ⚪ | Out v1 — la plupart des cibles acceptent SMB2 unencrypted |
| Kerberos session setup (AP-REQ in SPNEGO) | 🔜 | Couplé avec `netraze-protocols::kerberos` |

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
| **scmr** | `367abb81-…` | svcctl | OpenSCManagerW (15), OpenServiceW (16), CloseServiceHandle (0), QueryServiceStatus (6), StartServiceW (19), ChangeServiceConfigW (11) | ✅ | `smb::dump` (auto-start RemoteRegistry), `smb::enum_av` (probes service) |
| **scmr** suite | — | — | CreateServiceW (12), DeleteService (2), ControlService (1) | ✅ | `smb::exec` (smbexec complet — create/start/stop/delete) |
| **lsarpc** | `12345778-…` | lsarpc | OpenPolicy2, LookupSids, LookupNames, QueryInformationPolicy | 🔜 | Account/SID resolution, helps secret naming dans LSA dump |
| **drsuapi** | `e3514235-…` | lsass (RPC over named pipe) | DRSBind, DRSCrackNames, DRSGetNCChanges | 🔜 | **DCSync** — jackpot du pentest AD |
| **wkssvc** | `6bffd098-…` | wkssvc | NetrWkstaGetInfo, NetrWkstaUserEnum | ⚪ | Alternative à srvsvc pour info — pas urgent |
| **atsvc** | `1ff70682-…` | atsvc | NetrJobAdd, NetrJobEnum, NetrJobDel | ⚪ | Alternative à smbexec via task scheduler — utile si SCMR est bloqué EDR |
| **rprn** (printer bug → coerced auth) | `12345678-…` | spoolss | RpcRemoteFindFirstPrinterChangeNotificationEx | ⚪ | PrinterBug exploit — useful for relay attacks |
| **efsrpc** (PetitPotam) | `c681d488-…` | efsrpc, lsarpc | EfsRpcOpenFileRaw | ⚪ | PetitPotam coerced auth — critical for ADCS attacks |

---

## LDAP stack

### `netraze-protocols::ldap`

Le socle LDAP est livré dans `netraze-protocols` : port 389, BER borné,
bind NTLMv2 SASL/SPNEGO avec signature et chiffrement, RootDSE, recherche
paginée et inventaire AD en lecture seule. Le harness Samba AD séparé
(`tests/samba-ad/`) valide le chemin authentifié ; le bind anonyme est
couvert par un serveur factice en boucle locale.

| Module | Statut | Notes |
|---|---|---|
| `message` (BER via `rasn-ldap`) | ✅ | RFC 4511 §4.1.1, fixtures Impacket |
| Bind simple avec mot de passe en clair | ❌ | Non exposé ; seul le bind anonyme (nom et mot de passe vides) utilise cette forme sur le port 389 |
| Bind anonyme | 🟡 | BER non protégé après bind ; testé en boucle locale, sans assertion live contre Samba AD |
| `bind::sasl_gss_spnego` (NTLMSSP wrapped) | ✅ | NTLMv2 mot de passe/hash, MIC, sign-and-seal |
| `search::request` + `search::result_entry` | ✅ | RFC 4511 §4.5, framing borné |
| `controls::paged_results` (1.2.840.113556.1.4.319) | ✅ | Cookies itérés avec détection des répétitions |
| `controls::sd_flags` (security descriptor) | ⚪ | Pour ACL enum (BloodHound-equivalent) |
| `client::LdapClient` (TCP + bind + search loop) | ✅ | Async, tokio, délais de 5 s/20 s, plafond 16 Mio, IDs de message corrélés ; referrals retournés sans suivi automatique |
| `inventory` (RootDSE + sections AD) | ✅ | Utilisateurs, groupes, ordinateurs, OU/conteneurs, topologie, privilèges, SPN et politiques rapportées ; erreurs partielles exposées |

### Collecteurs LDAP et usages suivants

| Use case | Statut | Notes |
|---|---|---|
| `enum_users_ldap` (≈ `GetADUsers.py`) | ✅ | Filtre `(sAMAccountType=805306368)`, attrs `sAMAccountName, userAccountControl, adminCount` |
| Inventaire des ordinateurs | ✅ | Objets ordinateur, OS, SPN et indicateurs de délégation |
| Inventaire des groupes | ✅ | Groupes, membres et groupes parents ; analyse des appartenances privilégiées |
| OU, topologie et politique | ✅ | Conteneurs, domaines, trusts, sites, sous-réseaux, GPO et attributs de politique en lecture seule |
| Comptes de service et SPN | ✅ | Découverte LDAP des principaux et SPN ; pas d'extraction de tickets Kerberos |
| `find_kerberoastable` / extraction TGS | 🔜 | La découverte SPN est faite ; l'obtention et le traitement des tickets attendent `netraze-protocols::kerberos` |
| `find_asreproastable` | 🔜 | Filtre `(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` — alimente `netraze-protocols::kerberos::asreproast` |
| Indicateurs de délégation | ✅ | Bits UAC exposés dans l'inventaire utilisateur/ordinateur ; pas encore de module d'exploitation dédié |
| RootDSE fetch (defaultNamingContext) | ✅ | Préliminaire à toute search |

### Smart `enum_users` orchestration (livrée)

```
enum_users(target, cred):
  if cred contient un mot de passe ou hash NT:
    try LDAP path → return on success, même avec zéro résultat
    log warn "LDAP failed, falling back to SAMR"
  fallback to SAMR path pour guest/anonyme ou échec LDAP
```

---

## Kerberos stack

### `netraze-protocols::kerberos` (à créer après LDAP)

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

| Module | Statut | Use case |
|---|---|---|
| `netraze-protocols::dcom` (à créer) | ⚪ | wmiexec, dcomexec — alternative à smbexec quand SCM est watched |
| `netraze-protocols::wmi` (consumer de dcom) | ⚪ | Win32_Process.Create pour exec, Win32_Service.Start pour mvt latéral |

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
| `enum_av` | `protocols::smb::enum_av` | 🟡 portable (SCMR probes + IPC$ pipe listing) | validation live contre cible Windows en attente |
| `enum_dns` | — | 🔜 | `netraze-protocols::ldap` (DNS records dans `MicrosoftDNS` partition) |
| `enum_ca` | — | ⚪ | `netraze-protocols::ldap` + `netraze-dcerpc::interfaces::icpr` (cert enrollment) |
| `gpp_password` | `modules::reconnaissance::gpp_password` | ✅ (factory only — logic à porter) | smb file ops + Crypto AES (déjà là) |
| `enum_logged_in` | — | 🔜 | wkssvc.NetrWkstaUserEnum |
| `enum_shares_v_admin` | — | ✅ | déjà fait via shares_rpc |
| `enum_users_loggedon` | — | 🔜 | samr.SamrEnumerateUsersInDomain |

### Active Directory

| Module | Statut | Bloqué par |
|---|---|---|
| `add_computer` | ✅ factory | `netraze-protocols::ldap` (LDAP add operation) |
| `adcs` (cert template enum) | ✅ factory | `netraze-protocols::ldap` (CN=Configuration partition) |
| `coerce_plus` (PetitPotam, PrinterBug, ShadowCoerce) | ✅ factory | dcerpc.efsrpc + dcerpc.rprn |
| `dcsync` | 🔜 | dcerpc.drsuapi |
| `kerberoast` | 🔜 | `netraze-protocols::{ldap, kerberos}` |
| `asreproast` | 🔜 | `netraze-protocols::{ldap, kerberos}` |

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
| smbexec (SCMR) | 🟡 | portable via `smb::exec` (exec_rpc) — wire-smoke Samba OK, validation live cible Windows (admin) en attente |
| atexec | ⚪ | dcerpc.atsvc |
| wmiexec | ⚪ | `netraze-protocols::{dcom, wmi}` |
| psexec | ⚪ | smbexec variant — fait en même temps |

---

## Roadmap d'attaque (ordre opérationnel)

L'ordre **chronologique** dans lequel je recommande d'avancer.
Les chantiers 1–4 et 8 (SMB2 file ops, `exec_rpc`, `browser_rpc`, LDAP,
SMB signing) sont **faits** ; le chantier LDAP est validé contre le
harness Samba AD local. Reste, chaque ligne débloquant les suivantes :

| # | Chantier | Coût | Débloque |
|---|---|---|---|
| ~~1~~ | ~~**Phase D.1** — SMB2 file ops~~ | ✅ fait | write/delete/query_directory/create_directory — live Samba (browser_ops) |
| ~~2~~ | ~~**Phase D.3** — `exec_rpc` via SCMR~~ | ✅ fait | smbexec complet (create/start/stop/delete) — wire-smoke Samba OK |
| ~~3~~ | ~~**Phase D.4** — `browser_rpc`~~ | ✅ fait | browser cross-platform + suites browser_ops |
| ~~4~~ | ~~**Module `netraze-protocols::ldap`** — BER, bind SASL/NTLMSSP, recherche paginée et inventaire AD~~ | ✅ fait | Utilisateurs, groupes, ordinateurs, OU, topologie, privilèges, SPN et politiques rapportées |
| 5 | **Module `netraze-protocols::kerberos`** — ASN.1 Kerberos + AS-REQ/REP + TGS-REQ/REP + RC4/AES decrypt | 8j | AS-REProast + Kerberoast |
| 6 | `dcerpc.lsarpc` — OpenPolicy2 + LookupSids/Names | 3j | Account naming dans LSA dump |
| 7 | `dcerpc.drsuapi` — DRSBind + DRSGetNCChanges | 10j | **DCSync** = NTDS.dit complet sans toucher disque |
| ~~8~~ | ~~SMB signing HMAC-SHA256~~ | ✅ fait | dialectes 2.0.2/2.1 — vérifié live contre un DC "require signing" |
| 9 | `netraze-protocols::{dcom, wmi}` | 15j | wmiexec, dcomexec |
| 10 | Coerced auth modules (PetitPotam/PrinterBug) | 5j | Relay attacks → ADCS abuse |

Les estimations précédentes ne sont plus fiables depuis la livraison du
socle LDAP ; les tâches restantes seront chiffrées séparément.

---

## Comment ce document évolue

À **chaque PR** qui touche une interface ou ajoute une op :

1. Marquer la ligne du tableau correspondant : ⚪→🔵→🟡→✅
2. Ajouter une ligne dans la roadmap d'attaque si on a découvert un blocage non listé
3. Si une décision d'architecture est prise (ex: choix `rasn` vs ber maison), la documenter dans la section concernée
4. Si on retire un module du scope v1, le marquer ❌ avec la justification

L'objectif : à n'importe quel instant, ouvrir ce fichier doit donner une
réponse claire à "où on en est" et "qu'est-ce qu'on attaque ensuite".
