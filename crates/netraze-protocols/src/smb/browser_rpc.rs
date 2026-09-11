//! Cross-platform share file browser — SMB2 file operations on a share,
//! no Windows APIs.
//!
//! Phase D of the cross-platform portage plan. Replaces the Windows-only
//! `FindFirstFileW` / `CopyFileW` / `CreateDirectoryW` / `DeleteFileW` /
//! `RemoveDirectoryW` implementation (and its `stubs/browser.rs`
//! `NOT_PORTED` stub) with a single backend that runs identically on every
//! host.
//!
//! The public surface keeps the Windows version's names
//! ([`RemoteEntry`], [`format_size`], the six operations) but every remote
//! operation is now `async` and takes explicit `(target, cred, share,
//! rel_path)` components instead of a pre-composed UNC string — the desktop
//! already holds these four values, and UNC parsing is fragile (IPv6
//! brackets, `$`-suffixed share names, `:port` suffixes).
//!
//! Every operation opens a fresh SMB2 session and tears it down at the end
//! (the `shares_rpc` orchestrator pattern): the browser is user-paced, so
//! per-action session setup cost is irrelevant and no state lingers.

use rand::RngCore;

use super::connection::SmbCredential;
use super::rpc::{connect_session, host_only};
use super::smb2::Smb2Session;

/// A single entry in a remote directory listing.
#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Open a session to `target` and hand it to `f` as a plain closure — the
/// `spawn_blocking` boilerplate every operation below repeats.
///
/// `f` receives the `host_only` form of `target` (port-stripped) because
/// every SMB2 file primitive builds `\\host\share` UNC paths internally,
/// and UNC rejects ports.
async fn with_session<T, F>(target: &str, cred: &SmbCredential, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Smb2Session, &str) -> Result<T, String> + Send + 'static,
{
    let target_owned = target.to_owned();
    let cred_for_session = cred.clone();
    tokio::task::spawn_blocking(move || -> Result<T, String> {
        let mut session = connect_session(&target_owned, &cred_for_session)?;
        let host = host_only(&target_owned);
        let out = f(&mut session, &host)?;
        session.logoff();
        Ok(out)
    })
    .await
    .map_err(|e| format!("spawn_blocking(browser op): {e}"))?
}

/// List files and directories at `rel_path` inside `share`.
///
/// Entries are sorted directories-first, then case-insensitively by name —
/// byte-for-byte the ordering the Windows `FindFirstFileW` implementation
/// produced, so the desktop tree renders identically.
pub async fn list_directory(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
) -> Result<Vec<RemoteEntry>, String> {
    let share = share.to_owned();
    let rel_path = rel_path.to_owned();
    let mut entries: Vec<RemoteEntry> = with_session(target, cred, move |session, host| {
        session
            .query_directory(host, &share, &rel_path, "*")
            .map_err(|e| e.as_str().to_owned())
    })
    .await?
    .into_iter()
    .map(|e| RemoteEntry {
        name: e.name,
        is_dir: e.is_dir,
        size: e.size,
    })
    .collect();

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// Download a remote file to a local path.
pub async fn download_file(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
    local_path: &str,
) -> Result<(), String> {
    let share = share.to_owned();
    let rel_path = rel_path.to_owned();
    let local_path = local_path.to_owned();
    let data = with_session(target, cred, move |session, host| {
        session
            .read_full_file(host, &share, &rel_path)
            .map_err(|e| e.as_str().to_owned())
    })
    .await?;

    std::fs::write(&local_path, &data).map_err(|e| format!("write {local_path}: {e}"))
}

/// Upload a local file to `rel_path` inside `share`.
pub async fn upload_file(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
    local_path: &str,
) -> Result<(), String> {
    let data =
        std::fs::read(local_path).map_err(|e| format!("read {local_path}: {e}"))?;
    let share = share.to_owned();
    let rel_path = rel_path.to_owned();
    with_session(target, cred, move |session, host| {
        session.write_full_file(host, &share, &rel_path, &data)
    })
    .await
}

/// Create a directory at `rel_path` inside `share`.
pub async fn create_directory(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
) -> Result<(), String> {
    let share = share.to_owned();
    let rel_path = rel_path.to_owned();
    with_session(target, cred, move |session, host| {
        session
            .create_directory(host, &share, &rel_path)
            .map_err(|e| e.as_str().to_owned())
    })
    .await
}

/// Delete a remote file via the DELETE_ON_CLOSE disposition.
pub async fn delete_remote_file(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
) -> Result<(), String> {
    delete_via_disposition(target, cred, share, rel_path).await
}

/// Delete a remote directory (must be empty — a non-empty directory
/// surfaces `DIRECTORY_NOT_EMPTY`, same contract as `RemoveDirectoryW`).
pub async fn delete_remote_directory(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
) -> Result<(), String> {
    delete_via_disposition(target, cred, share, rel_path).await
}

/// Shared body of the two delete operations — SMB2's DELETE_ON_CLOSE
/// disposition applies to files and directories alike; the split above only
/// exists so callers can express intent (and get operation-accurate errors).
async fn delete_via_disposition(
    target: &str,
    cred: &SmbCredential,
    share: &str,
    rel_path: &str,
) -> Result<(), String> {
    let share = share.to_owned();
    let rel_path = rel_path.to_owned();
    with_session(target, cred, move |session, host| {
        session
            .delete_on_close(host, &share, &rel_path)
            .map_err(|e| e.as_str().to_owned())
    })
    .await
}

/// Format a file size for display.
pub fn format_size(size: u64) -> String {
    const K: u64 = 1024;
    if size < K {
        format!("{size} B")
    } else if size < K * K {
        format!("{:.1} KB", size as f64 / K as f64)
    } else if size < K * K * K {
        format!("{:.1} MB", size as f64 / (K * K) as f64)
    } else {
        format!("{:.2} GB", size as f64 / (K * K * K) as f64)
    }
}

/// Random suffix for test artifacts (and any caller that wants a collision
/// -proof name). 64 bits of entropy.
fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{:016x}", u64::from_le_bytes(bytes))
}

/// Exposed for integration tests: a unique `__netraze_test_<hex>__` leaf
/// name so parallel runs can't collide on the writable test share.
#[doc(hidden)]
pub fn __test_leaf(prefix: &str) -> String {
    format!("__netraze_test_{prefix}_{}__", random_suffix())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_matches_windows_impl() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn test_leaf_names_are_unique_and_private() {
        let a = __test_leaf("dir");
        let b = __test_leaf("dir");
        assert_ne!(a, b);
        assert!(a.starts_with("__netraze_test_dir_"));
        assert!(a.ends_with("__"));
    }
}
