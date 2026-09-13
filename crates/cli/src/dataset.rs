//! Keep a cache bound to one installation and package snapshot.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    schema_version: u32,
    packages: PathBuf,
    game_version: String,
    // All patches matter, including older blocks read by a newer package.
    files: Vec<(String, u64, u64)>,
    signatures: Option<String>,
    local_wordlist: Option<(u64, u64)>,
}
impl Identity {
    pub fn current() -> Result<Self> {
        let pm = tiger_pkg::package_manager();
        Self::from_directory(&pm.package_dir, format!("{:?}", pm.version))
    }
    fn from_directory(path: &Path, game_version: String) -> Result<Self> {
        let packages = std::fs::canonicalize(path)?;
        let mut files = vec![];
        for entry in std::fs::read_dir(&packages)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|s| s.eq_ignore_ascii_case("pkg"))
            {
                let m = entry.metadata()?;
                files.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    m.len(),
                    m.modified()?
                        .duration_since(UNIX_EPOCH)?
                        .as_nanos()
                        .try_into()?,
                ));
            }
        }
        files.sort();
        let signatures = match std::fs::read_to_string("signatures.csv") {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            schema_version: 1,
            packages,
            game_version,
            files,
            signatures,
            local_wordlist: match std::fs::metadata("local_wordlist.txt") {
                Ok(m) => Some((
                    m.len(),
                    m.modified()?
                        .duration_since(UNIX_EPOCH)?
                        .as_nanos()
                        .try_into()?,
                )),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            },
        })
    }
    pub fn verify(&self, cache: &Path) -> Result<()> {
        let file = std::fs::File::open(sidecar(cache))
            .context("cache identity missing; run index --rebuild to bind it to this dataset")?;
        let stored: Self =
            serde_json::from_reader(file).context("invalid cache identity; run index --rebuild")?;
        ensure!(
            &stored == self,
            "cache belongs to another dataset, package snapshot or signatures file; choose another cache or run index --rebuild"
        );
        Ok(())
    }
    pub fn save(&self, cache: &Path) -> Result<()> {
        serde_json::to_writer(std::fs::File::create(sidecar(cache))?, self)?;
        Ok(())
    }
}
fn sidecar(cache: &Path) -> PathBuf {
    let mut path = cache.as_os_str().to_os_string();
    path.push(".dataset.json");
    path.into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_changed_packages_and_other_versions() {
        let dir = std::env::temp_dir().join(format!(
            "quicktag-dataset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let result = (|| -> Result<()> {
            let cache = dir.join("test.cache");
            std::fs::write(dir.join("test.pkg"), [1, 2, 3])?;
            let original = Identity::from_directory(&dir, "d2_sk".into())?;
            assert!(original.verify(&cache).is_err());
            original.save(&cache)?;
            original.verify(&cache)?;
            assert!(
                Identity::from_directory(&dir, "d2_eof".into())?
                    .verify(&cache)
                    .is_err()
            );
            std::fs::write(dir.join("test.pkg"), [1, 2, 3, 4])?;
            assert!(
                Identity::from_directory(&dir, "d2_sk".into())?
                    .verify(&cache)
                    .is_err()
            );
            Ok(())
        })();
        std::fs::remove_dir_all(&dir).unwrap();
        result.unwrap();
    }
}
