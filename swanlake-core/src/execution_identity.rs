//! A process replacement is proof of termination only within an exclusive owner.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionIdentity {
    pub version: u8,
    pub owner: Option<String>,
    pub generation: String,
}

impl Default for ExecutionIdentity {
    fn default() -> Self {
        Self {
            version: 1,
            owner: None,
            generation: Uuid::new_v4().to_string(),
        }
    }
}

impl ExecutionIdentity {
    /// The server binary calls this before creating any execution threads.
    /// Keep the lock until OS process exit, including while blocking SQL threads
    /// outlive the async server during shutdown. Never unlink or copy this file.
    pub fn for_process(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let (identity, lock) = acquire(path)?;
        std::mem::forget(lock);
        Ok(identity)
    }
}

fn acquire(path: &Path) -> anyhow::Result<(ExecutionIdentity, File)> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.try_lock()
        .map_err(|e| anyhow::anyhow!("execution owner is already locked or unavailable: {e}"))?;
    let mut owner = String::new();
    file.read_to_string(&mut owner)?;
    if owner.is_empty() {
        owner = Uuid::new_v4().to_string();
        file.write_all(owner.as_bytes())?;
        file.sync_all()?;
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
    }
    // A partial or damaged identity must fail startup, never invent continuity.
    Uuid::parse_str(&owner)?;
    Ok((
        ExecutionIdentity {
            owner: Some(owner),
            ..ExecutionIdentity::default()
        },
        file,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn lock_excludes_other_owners_and_survives_until_process_exit() {
        const CHILD: &str = "SWANLAKE_OWNER_TEST_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = std::path::PathBuf::from(path);
            let identity = ExecutionIdentity::for_process(Some(&path)).unwrap();
            std::fs::write(
                path.with_extension("ready"),
                serde_json::to_vec(&identity).unwrap(),
            )
            .unwrap();
            loop {
                std::thread::park();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "execution_identity::tests::lock_excludes_other_owners_and_survives_until_process_exit"])
            .env(CHILD, &path).stdout(Stdio::null()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.with_extension("ready").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let old = std::fs::read(path.with_extension("ready"));
        let excluded = acquire(&path).is_err();
        child.kill().unwrap();
        child.wait().unwrap();
        let old: serde_json::Value = serde_json::from_slice(&old.unwrap()).unwrap();
        assert!(excluded, "second process acquired a live owner's lock");
        let (next, _lock) = acquire(&path).unwrap();
        assert_eq!(next.owner.as_deref(), old["owner"].as_str());
        assert_ne!(next.generation, old["generation"].as_str().unwrap());
    }

    #[test]
    fn corrupt_owner_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner");
        std::fs::write(&path, "partial-identity").unwrap();
        assert!(acquire(&path).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "partial-identity");
    }
}
