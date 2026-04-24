# Roadmap de portage

## Phase 1

- Stabiliser les types du coeur (`netraze-core`).
- Formaliser la config, les cibles, l'output et le runtime.
- Garder la CLI mince et testable.

## Phase 2

- Extraire les protocoles critiques en crates dediees:
  - `netraze-protocol-smb`
  - `netraze-protocol-ldap`
  - `netraze-protocol-winrm`
  - `netraze-protocol-ssh`
- Brancher un storage SQLite reel dans `netraze-storage`.

## Phase 3

- Introduire une API de plugins stabilisee.
- Ajouter export JSON/CSV et observabilite plus riche.
- Porter les modules les plus rentables par categorie.

## Phase 4

- Ajouter tests d'integration par protocole.
- Ajouter fixtures reseau et harness de regression.
- Evaluer un TUI ou une API machine-friendly.

## Regles d'evolution

- Toute logique partagee monte vers `netraze-core` ou une crate transverse.
- Toute dependance protocolaire reste isolee dans la couche protocole.
- Toute fonctionnalite orientee campagne ou workflow reste au-dessus du coeur.
