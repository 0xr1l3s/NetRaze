# getexec-rs

Workspace Rust pour un portage progressif et industrialisable de Getexec.

## Principes d'architecture

- `getexec-core` expose le langage commun du domaine: targets, auth, protocoles, modules, résultats.
- `getexec-app` orchestre le bootstrap, l'injection des services et les registres.
- `getexec-cli` reste mince: parsing des arguments, sélection des workflows, rendu utilisateur.
- `getexec-protocols` regroupe les implémentations natives par protocole, avec un registre extensible.
- `getexec-modules` sépare les modules métier des protocoles et prépare un futur système de plugins.
- `getexec-storage`, `getexec-config`, `getexec-output`, `getexec-runtime`, `getexec-targets`, `getexec-auth` isolent les préoccupations transversales.
- `xtask` porte l'automatisation de build, génération et qualité.

## Objectif

Cette structure est pensée pour supporter:

- un portage incrémental protocole par protocole;
- une croissance vers plusieurs binaires et services internes;
- l'ajout futur de plugins, exports, workflows distribués et intégrations CI.

## Démarrage

```powershell
cargo run -p getexec-cli -- --help
cargo run -p getexec-desktop
cargo check
```

## GUI Desktop

La GUI native cross-platform est dans [crates/getexec-desktop](crates/getexec-desktop) et utilise:

- `egui` + `eframe` pour l'application desktop
- `egui-snarl` pour le canvas node graph de workflow offensif
- `egui_graphs` pour la vue réseau interactive
- `tokio` + channels pour les tâches asynchrones et les logs temps réel
