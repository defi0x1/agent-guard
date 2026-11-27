//! Agent Guard's own directory: `~/.agent-guard` (or `$AGENT_GUARD_HOME`), mode 0700.
//! Everything in it is the user's; the hook denies the agent any write to it.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The directory, without creating it.
pub fn dir() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os("AGENT_GUARD_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".agent-guard"))
}

/// The directory, created with mode 0700 if missing (and tightened if it is looser).
pub fn ensure() -> io::Result<PathBuf> {
    let d = dir()?;
    private_dir(&d)?;
    Ok(d)
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

/// Writes `data` to `path` atomically (temp file and rename), mode 0600.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
