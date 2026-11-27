//! Agent Guard's own directory: `~/.agent-guard` (or `$AGENT_GUARD_HOME`), mode 0700.
//! Everything in it is the user's; the hook denies the agent any write to it.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;

/// The directory, without creating it.
pub fn dir() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os("AGENT_GUARD_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".agent-guard"))
}

/// The directory, created with mode 0700 if missing (and tightened if it is looser). An error if
/// the user cannot read and write it, so the guard fails loudly instead of running without state.
pub fn ensure() -> io::Result<PathBuf> {
    let d = dir()?;
    private_dir(&d)?;
    usable(&d)?;
    Ok(d)
}

/// An error unless the owner may list, enter and write `d`.
fn usable(d: &Path) -> io::Result<()> {
    let mode = fs::metadata(d)?.permissions().mode();
    if mode & 0o700 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not usable (mode {:o}); run chmod 700 on it",
                d.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

/// Creates `d` (and missing parents) and makes sure only the user can open it.
pub fn private_dir(d: &Path) -> io::Result<()> {
    fs::create_dir_all(d)?;
    let mut perm = fs::metadata(d)?.permissions();
    if perm.mode() & 0o077 != 0 {
        perm.set_mode(0o700);
        fs::set_permissions(d, perm)?;
    }
    Ok(())
}

/// Writes `data` to `path` atomically, mode 0600. A symlink at `path` is followed only to a file
/// in the same directory.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    write_atomic(path, data, Some(0o600), parent(path))
}

/// Replaces `path` with `data` atomically: a temp file with a random name next to the target,
/// created exclusively (so no planted file or symlink is reused), its mode set on the open file,
/// synced, then renamed over the target. `mode: None` keeps the target's mode (0600 if new).
/// A symlink at `path` is followed, but the real target must stay inside `root`, else nothing
/// is written.
pub fn write_atomic(path: &Path, data: &[u8], mode: Option<u32>, root: &Path) -> io::Result<()> {
    let target = target_in(path, root)?;
    let mode = mode
        .unwrap_or_else(|| fs::metadata(&target).map_or(0o600, |m| m.permissions().mode() & 0o777));
    let mut tmp = tempfile::Builder::new()
        .prefix(".guard-")
        .suffix(".tmp")
        .tempfile_in(parent(&target))?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&target).map_err(|e| e.error)?;
    Ok(())
}

/// Where a write to `path` really lands: through symlinks, and refused outside `root`. A missing
/// file (or a dangling symlink, which is then replaced) lands in its resolved directory.
fn target_in(path: &Path, root: &Path) -> io::Result<PathBuf> {
    let root = fs::canonicalize(root)?;
    let target = match fs::canonicalize(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
            fs::canonicalize(parent(path))?.join(name)
        }
        Err(e) => return Err(e),
    };
    if !target.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} leads to {}, outside {}; not written",
                path.display(),
                target.display(),
                root.display()
            ),
        ));
    }
    Ok(target)
}

/// The directory holding `path` (`.` for a bare file name).
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// The parsed JSON file, or `None` if it is missing or does not parse.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_private_is_atomic_and_private() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        fs::write(&p, "old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, b"new").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temp file left"
        );
    }

    #[test]
    fn planted_temp_symlinks_are_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        for name in [
            "settings.tmp",
            "settings.json.tmp",
            "settings.json.guard-tmp",
        ] {
            symlink(&victim, d.path().join(name)).unwrap();
        }
        let p = d.path().join("settings.json");
        write_private(&p, b"{}").unwrap();
        write_atomic(&p, b"{}", None, d.path()).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert!(!fs::symlink_metadata(&p).unwrap().file_type().is_symlink());
    }

    #[test]
    fn symlinked_target_must_stay_inside_root() {
        let (root, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let inside = root.path().join("real.json");
        fs::write(&inside, "{}").unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o640)).unwrap();
        let link = root.path().join("link.json");
        symlink(&inside, &link).unwrap();
        write_atomic(&link, b"1", None, root.path()).unwrap();
        assert_eq!(fs::read_to_string(&inside).unwrap(), "1");
        assert_eq!(mode(&inside), 0o640, "mode kept");

        let far = outside.path().join("rc");
        fs::write(&far, "keep").unwrap();
        let bad = root.path().join("bad.json");
        symlink(&far, &bad).unwrap();
        let err = write_atomic(&bad, b"x", None, root.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(write_private(&bad, b"x").is_err());
        assert_eq!(fs::read_to_string(&far).unwrap(), "keep");

        let dangling = root.path().join("dangling.json");
        symlink(outside.path().join("new-file"), &dangling).unwrap();
        write_atomic(&dangling, b"x", None, root.path()).unwrap();
        assert!(
            !outside.path().join("new-file").exists(),
            "the link is replaced"
        );
        assert_eq!(fs::read_to_string(&dangling).unwrap(), "x");
    }

    #[test]
    fn unusable_directory_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let g = d.path().join("g");
        private_dir(&g).unwrap();
        assert!(usable(&g).is_ok());
        fs::set_permissions(&g, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(usable(&g).is_err());
        fs::set_permissions(&g, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(usable(&g).is_err());
        fs::set_permissions(&g, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn read_json_is_none_when_missing_or_bad() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.json");
        assert_eq!(read_json::<serde_json::Value>(&p), None);
        fs::write(&p, "{").unwrap();
        assert_eq!(read_json::<serde_json::Value>(&p), None);
        fs::write(&p, r#"{"a": 1}"#).unwrap();
        assert_eq!(
            read_json::<serde_json::Value>(&p),
            Some(serde_json::json!({"a": 1}))
        );
    }
}
