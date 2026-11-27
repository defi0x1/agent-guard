//! Backups for doctor fixes: `<guard home>/backups/<timestamp>/` holds a copy of every file a
//! fix changed, the old global git values, and `manifest.json`. `--undo` restores the newest one
//! and removes it, so the next `--undo` goes one fix further back.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::{Env, files, git};

/// What one `--fix` run changed.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    created: u64,
    files: Vec<FileEntry>,
    git: Vec<GitEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEntry {
    path: PathBuf,
    /// The copy's name in the backup directory, or `None` if the file did not exist.
    copy: Option<String>,
    mode: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitEntry {
    key: String,
    /// The old global value, or `None` if it was unset.
    old: Option<String>,
}

/// A backup being written. The directory is created on the first change.
pub struct Backup {
    root: PathBuf,
    dir: Option<PathBuf>,
    manifest: Manifest,
}

impl Backup {
    pub fn new(env: &Env) -> Backup {
        Backup {
            root: env.guard_home.join("backups"),
            dir: None,
            manifest: Manifest {
                created: env.now,
                ..Manifest::default()
            },
        }
    }

    /// Whether anything was saved.
    pub fn is_empty(&self) -> bool {
        self.manifest.files.is_empty() && self.manifest.git.is_empty()
    }

    /// Saves `path` (content and mode) before it is changed. Once per file per run.
    pub fn save_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.manifest.files.iter().any(|f| f.path == path) {
            return Ok(());
        }
        let dir = self.dir()?;
        let entry = match fs::read(&path) {
            Ok(data) => {
                let copy = format!("{}.bak", self.manifest.files.len());
                files::write_atomic(&dir.join(&copy), &data)?;
                FileEntry {
                    mode: Some(fs::metadata(&path)?.permissions().mode() & 0o7777),
                    path,
                    copy: Some(copy),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileEntry {
                path,
                copy: None,
                mode: None,
            },
            Err(e) => return Err(e).with_context(|| format!("backing up {}", path.display())),
        };
        self.manifest.files.push(entry);
        self.write_manifest()
    }

    /// Saves the old global value of a git config key before it is changed.
    pub fn save_git(&mut self, key: &str, old: Option<String>) -> anyhow::Result<()> {
        self.dir()?;
        self.manifest.git.push(GitEntry {
            key: key.to_string(),
            old,
        });
        self.write_manifest()
    }

    /// Puts back everything saved so far (used when a fix fails half way) and drops the backup.
    pub fn restore(self, env: &Env) -> anyhow::Result<Vec<String>> {
        let Some(dir) = self.dir else {
            return Ok(Vec::new());
        };
        restore_dir(env, &dir)
    }

    /// The backup directory, created (mode 0700) on first use.
    fn dir(&mut self) -> anyhow::Result<PathBuf> {
        if let Some(d) = &self.dir {
            return Ok(d.clone());
        }
        let mut name = self.manifest.created.to_string();
        let mut n = 1;
        while self.root.join(&name).exists() {
            name = format!("{}-{n}", self.manifest.created);
            n += 1;
        }
        let d = self.root.join(name);
        fs::create_dir_all(&d)?;
        for p in [&self.root, &d] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        }
        self.dir = Some(d.clone());
        Ok(d)
    }

    fn write_manifest(&mut self) -> anyhow::Result<()> {
        let dir = self.dir()?;
        let text = serde_json::to_vec_pretty(&self.manifest)?;
        files::write_atomic(&dir.join("manifest.json"), &text)?;
        Ok(())
    }
}

/// Restores the newest backup and removes it. Returns what was put back.
pub fn undo_last(env: &Env) -> anyhow::Result<Vec<String>> {
    let root = env.guard_home.join("backups");
    let latest = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("manifest.json").is_file())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let (ts, n) = name.split_once('-').unwrap_or((&name, "0"));
            Some(((ts.parse::<u64>().ok()?, n.parse::<u64>().ok()?), e.path()))
        })
        .max_by_key(|(key, _)| *key)
        .map(|(_, p)| p);
    match latest {
        Some(dir) => restore_dir(env, &dir),
        None => anyhow::bail!("there is no doctor fix to undo"),
    }
}

/// Restores one backup directory in reverse order, then removes it.
fn restore_dir(env: &Env, dir: &Path) -> anyhow::Result<Vec<String>> {
    let text = fs::read_to_string(dir.join("manifest.json"))
        .with_context(|| format!("reading {}", dir.display()))?;
    let m: Manifest = serde_json::from_str(&text)?;
    let mut done = Vec::new();
    for g in m.git.iter().rev() {
        let ok = match &g.old {
            Some(v) => git(env, &["config", "--global", &g.key, v]).is_some(),
            None => git(env, &["config", "--global", "--unset", &g.key]).is_some(),
        };
        if !ok {
            anyhow::bail!("could not restore git config {}", g.key);
        }
        done.push(format!("restored git config {}", g.key));
    }
    for f in m.files.iter().rev() {
        match &f.copy {
            Some(copy) => {
                let data = fs::read(dir.join(copy))?;
                files::write_atomic(&f.path, &data)?;
                if let Some(mode) = f.mode {
                    fs::set_permissions(&f.path, fs::Permissions::from_mode(mode))?;
                }
            }
            None => match fs::remove_file(&f.path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            },
        }
        done.push(format!("restored {}", env.tilde(&f.path)));
    }
    fs::remove_dir_all(dir)?;
    Ok(done)
}
