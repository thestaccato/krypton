use crate::error::{Error, Result};
use crate::file_ops::{FileMetadata, FileOps};
use crate::keystore::KeyStore;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Vault {
    pub path: PathBuf,
    keystore: KeyStore,
    file_ops: Option<FileOps>,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            keystore: KeyStore::new(),
            file_ops: None,
        }
    }

    pub fn exists(&self) -> bool {
        self.path.join("vault.config").exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.keystore.is_unlocked()
    }

    fn get_config_path(&self) -> PathBuf {
        self.path.join("vault.config")
    }

    fn get_data_dir(&self) -> PathBuf {
        self.path.join("d")
    }

    pub fn init(&mut self, password: &str) -> Result<()> {
        if self.exists() {
            return Err(Error::VaultExists);
        }

        fs::create_dir_all(&self.path)?;
        fs::create_dir_all(self.get_data_dir())?;

        let config = self.keystore.init(password)?;

        let config_json = serde_json::to_string_pretty(&config)
            .map_err(|_| Error::VaultOp("Failed to serialize config".to_string()))?;

        fs::write(self.get_config_path(), config_json)?;

        let master_key = self.keystore.get_master_key()?;
        self.file_ops = Some(FileOps::new(master_key));

        let files = HashMap::new();
        self.file_ops
            .as_ref()
            .unwrap()
            .save_manifest(&self.path, &files)?;

        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if !self.exists() {
            return Err(Error::InvalidVault);
        }

        if self.keystore.is_unlocked() {
            return Err(Error::VaultUnlocked);
        }

        let config_json = fs::read_to_string(self.get_config_path())?;
        let config: crate::keystore::VaultConfig =
            serde_json::from_str(&config_json).map_err(|_| Error::InvalidVault)?;

        self.keystore.unlock(password, &config)?;

        let master_key = self.keystore.get_master_key()?;
        self.file_ops = Some(FileOps::new(master_key));

        Ok(())
    }

    pub fn lock(&mut self) {
        self.keystore.lock();
        self.file_ops = None;
    }

    pub fn add(&mut self, source_path: &Path, relative_name: Option<&str>) -> Result<()> {
        let file_ops = self.file_ops.as_ref().ok_or(Error::VaultLocked)?;

        let source = source_path
            .canonicalize()
            .map_err(|_| Error::FileNotFound(source_path.to_string_lossy().to_string()))?;

        if !source.exists() {
            return Err(Error::FileNotFound(source.to_string_lossy().to_string()));
        }

        let name: String = match relative_name {
            Some(n) => n.to_string(),
            None => source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };

        if source.is_dir() {
            file_ops.add_directory(&source, &self.path, &name)?;
        } else {
            file_ops.add_file(&source, &self.path, &name)?;
        }

        let mut manifest = file_ops.load_manifest(&self.path)?;

        let metadata = FileMetadata {
            original_name: name.clone(),
            original_size: source.metadata().map(|m| m.len()).unwrap_or(0),
            is_directory: source.is_dir(),
            children: None,
        };

        manifest.files.insert(name.clone(), metadata);
        file_ops.save_manifest(&self.path, &manifest.files)?;

        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let file_ops = self.file_ops.as_ref().ok_or(Error::VaultLocked)?;

        let enc_path = file_ops.get_encrypted_file_path(name, &self.path);
        if enc_path.exists() {
            fs::remove_file(&enc_path)?;
        }

        let mut manifest = file_ops.load_manifest(&self.path)?;
        manifest.files.remove(name);
        file_ops.save_manifest(&self.path, &manifest.files)?;

        Ok(())
    }

    pub fn list(&self) -> Result<Vec<(String, u64, bool)>> {
        let file_ops = self.file_ops.as_ref().ok_or(Error::VaultLocked)?;

        let manifest = file_ops.load_manifest(&self.path)?;

        Ok(manifest
            .files
            .iter()
            .map(|(name, meta)| (name.clone(), meta.original_size, meta.is_directory))
            .collect())
    }

    pub fn extract(&self, name: &str, dest: &Path) -> Result<()> {
        let file_ops = self.file_ops.as_ref().ok_or(Error::VaultLocked)?;

        let enc_path = file_ops.get_encrypted_file_path(name, &self.path);

        if !enc_path.exists() {
            return Err(Error::FileNotFound(name.to_string()));
        }

        let metadata = file_ops.decrypt_file(&enc_path, dest)?;

        let manifest = file_ops.load_manifest(&self.path)?;
        if let Some(mut entry) = manifest.files.get(name).cloned() {
            entry.original_size = metadata.original_size;
        }

        Ok(())
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        if !self.keystore.is_unlocked() {
            return Err(Error::VaultLocked);
        }

        let config_json = fs::read_to_string(self.get_config_path())?;
        let config: crate::keystore::VaultConfig =
            serde_json::from_str(&config_json).map_err(|_| Error::InvalidVault)?;

        let new_config = self
            .keystore
            .change_password(old_password, new_password, &config)?;

        let new_config_json = serde_json::to_string_pretty(&new_config)
            .map_err(|_| Error::VaultOp("Failed to serialize config".to_string()))?;

        fs::write(self.get_config_path(), new_config_json)?;

        Ok(())
    }

    pub fn verify(&mut self, password: &str) -> Result<(usize, usize, Vec<String>)> {
        let config_json = fs::read_to_string(self.get_config_path())?;
        let _config: crate::keystore::VaultConfig =
            serde_json::from_str(&config_json).map_err(|_| Error::InvalidVault)?;

        self.unlock(password)?;

        let files = self.list()?;
        let mut missing = Vec::new();
        let mut verified = 0;

        for (name, _size, _is_dir) in &files {
            let file_ops = self.file_ops.as_ref().unwrap();
            let enc_path = file_ops.get_encrypted_file_path(name, &self.path);

            if enc_path.exists() {
                verified += 1;
            } else {
                missing.push(name.clone());
            }
        }

        self.lock();

        Ok((files.len(), verified, missing))
    }
}
