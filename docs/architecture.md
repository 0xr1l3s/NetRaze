# Architecture cible

## Couches

1. `getexec-cli`
Responsable de l'interface utilisateur, des sous-commandes et du mapping des flags vers des use-cases applicatifs.

2. `getexec-app`
Conteneur de composition. Construit l'application, branche les registres, injecte storage, output, config et runtime.

3. `getexec-core`
Contrats du domaine. Tout crate dépendant du coeur parle les mêmes types et les mêmes traits.

4. Crates transversales
- `getexec-auth`: identité, secrets, méthodes d'authentification.
- `getexec-targets`: parsing et normalisation des cibles.
- `getexec-config`: configuration CLI, fichiers, profils.
- `getexec-storage`: workspaces, credentials, historiques, artefacts.
- `getexec-output`: logs, rendu console, exports structurés.
- `getexec-runtime`: concurrence, timeouts, annulation, orchestration async.

5. Crates métier extensibles
- `getexec-protocols`: handlers par protocole.
- `getexec-modules`: modules transverses déclenchés après login ou dans des workflows dédiés.

## Evolution prévue

- Split futur de `getexec-protocols` en crates dédiées par protocole (`getexec-protocol-smb`, `getexec-protocol-ldap`, etc.).
- Introduction d'une API de plugins stable pour modules externes.
- Support éventuel d'agents distants et de files de jobs.
- Ajout d'une API machine-friendly ou d'un TUI sans casser le coeur.

## Règles de dépendance

- `getexec-core` ne dépend d'aucun crate applicatif.
- `getexec-cli` ne contient pas de logique protocolaire.
- `getexec-protocols` et `getexec-modules` dépendent du coeur, jamais de la CLI.
- `getexec-app` est le seul crate autorisé à connaître presque tout le monde.
