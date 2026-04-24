# Architecture cible

## Couches

1. `netraze-cli`
Responsable de l'interface utilisateur, des sous-commandes et du mapping des flags vers des use-cases applicatifs.

2. `netraze-app`
Conteneur de composition. Construit l'application, branche les registres, injecte storage, output, config et runtime.

3. `netraze-core`
Contrats du domaine. Tout crate dépendant du coeur parle les mêmes types et les mêmes traits.

4. Crates transversales
- `netraze-auth`: identité, secrets, méthodes d'authentification.
- `netraze-targets`: parsing et normalisation des cibles.
- `netraze-config`: configuration CLI, fichiers, profils.
- `netraze-storage`: workspaces, credentials, historiques, artefacts.
- `netraze-output`: logs, rendu console, exports structurés.
- `netraze-runtime`: concurrence, timeouts, annulation, orchestration async.

5. Crates métier extensibles
- `netraze-protocols`: handlers par protocole.
- `netraze-modules`: modules transverses déclenchés après login ou dans des workflows dédiés.

## Evolution prévue

- Split futur de `netraze-protocols` en crates dédiées par protocole (`netraze-protocol-smb`, `netraze-protocol-ldap`, etc.).
- Introduction d'une API de plugins stable pour modules externes.
- Support éventuel d'agents distants et de files de jobs.
- Ajout d'une API machine-friendly ou d'un TUI sans casser le coeur.

## Règles de dépendance

- `netraze-core` ne dépend d'aucun crate applicatif.
- `netraze-cli` ne contient pas de logique protocolaire.
- `netraze-protocols` et `netraze-modules` dépendent du coeur, jamais de la CLI.
- `netraze-app` est le seul crate autorisé à connaître presque tout le monde.
