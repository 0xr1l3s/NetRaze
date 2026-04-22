use anyhow::Context;
use std::fs;
use std::path::Path;

use crate::state::WorkspaceSave;

pub fn save_workspace(path: &Path, save: &WorkspaceSave) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(save)
        .context("Echec de serialisation du workspace")?;
    fs::write(path, json).with_context(|| format!("Echec d'ecriture de {}", path.display()))?;
    Ok(())
}

pub fn load_workspace(path: &Path) -> anyhow::Result<WorkspaceSave> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Echec de lecture de {}", path.display()))?;
    let save = serde_json::from_str::<WorkspaceSave>(&content)
        .context("Echec de deserialisation du workspace")?;
    Ok(save)
}
