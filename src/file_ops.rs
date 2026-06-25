use crate::crypto;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zeroize::Zeroize;

const CHUNK_SIZE: usize = 65536;

#[derive(Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    pub original_name: String,
    pub original_size: u64,
    pub is_directory: bool,
    pub children: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct FileManifest {
    pub version: u32,
    pub files: HashMap<String, FileMetadata>,
}

pub struct FileOps {
    master_key: [u8; 32],
}

impl FileOps {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    fn get_encrypted_path(&self, relative_path: &Path) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(relative_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        let hash_str = format!("{:x}", hash);

        PathBuf::from(&hash_str[..2])
            .join(&hash_str[2..50])
            .with_extension("enc")
    }

    pub fn encrypt_file(&self, source: &Path, dest_dir: &Path, relative_path: &str) -> Result<()> {
        let metadata = fs::metadata(source)?;

        let file_meta = FileMetadata {
            original_name: relative_path.to_string(),
            original_size: metadata.len(),
            is_directory: metadata.is_dir(),
            children: None,
        };

        let meta_json = serde_json::to_vec(&file_meta).map_err(|_| Error::EncryptionFailed)?;

        let encrypted_meta = crypto::encrypt_with_key(&meta_json, &self.master_key)?;

        let enc_path = self.get_encrypted_path(Path::new(relative_path));
        let full_enc_path = dest_dir.join("d").join(&enc_path);

        if let Some(parent) = full_enc_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(&full_enc_path)?;

        file.write_all(&encrypted_meta.nonce)?;
        file.write_all(&encrypted_meta.tag)?;

        let meta_len = (meta_json.len() as u32).to_le_bytes();
        file.write_all(&meta_len)?;
        file.write_all(&encrypted_meta.ciphertext)?;

        if !metadata.is_dir() {
            file.write_all(&[0x01])?;

            let mut source_file = File::open(source)?;
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read: u64 = 0;

            while total_read < metadata.len() {
                let to_read = std::cmp::min(CHUNK_SIZE, (metadata.len() - total_read) as usize);
                let bytes_read = source_file.read(&mut buffer[..to_read])?;
                if bytes_read == 0 {
                    break;
                }

                let encrypted_chunk =
                    crypto::encrypt_with_key(&buffer[..bytes_read], &self.master_key)?;

                file.write_all(&encrypted_chunk.nonce)?;
                file.write_all(&encrypted_chunk.tag)?;

                let chunk_len = (bytes_read as u32).to_le_bytes();
                file.write_all(&chunk_len)?;
                file.write_all(&encrypted_chunk.ciphertext)?;

                total_read += bytes_read as u64;
            }
        } else {
            file.write_all(&[0x00])?;
        }

        Ok(())
    }

    pub fn decrypt_file(&self, enc_path: &Path, dest: &Path) -> Result<FileMetadata> {
        let mut file = File::open(enc_path)?;
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        let mut meta_len_bytes = [0u8; 4];
        let mut has_content = [0u8; 1];

        file.read_exact(&mut nonce)?;
        file.read_exact(&mut tag)?;
        file.read_exact(&mut meta_len_bytes)?;

        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;
        let mut meta_ciphertext = vec![0u8; meta_len];
        file.read_exact(&mut meta_ciphertext)?;

        let meta_json = crypto::decrypt_with_key(&meta_ciphertext, &nonce, &self.master_key, &tag)?;
        meta_ciphertext.zeroize();

        let file_meta: FileMetadata =
            serde_json::from_slice(&meta_json).map_err(|_| Error::DecryptionFailed)?;

        file.read_exact(&mut has_content)?;

        if has_content[0] == 0x01 && !file_meta.is_directory {
            let dest_file = File::create(dest)?;
            let mut writer = std::io::BufWriter::new(dest_file);

            loop {
                let mut chunk_nonce = [0u8; 12];
                let mut chunk_tag = [0u8; 16];
                let mut chunk_len_bytes = [0u8; 4];

                match file.read_exact(&mut chunk_nonce) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(Error::Io(e)),
                }

                file.read_exact(&mut chunk_tag)?;
                file.read_exact(&mut chunk_len_bytes)?;

                let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;
                let mut chunk_data = vec![0u8; chunk_len];
                file.read_exact(&mut chunk_data)?;

                let mut plaintext = crypto::decrypt_with_key(
                    &chunk_data,
                    &chunk_nonce,
                    &self.master_key,
                    &chunk_tag,
                )?;
                chunk_data.zeroize();

                writer.write_all(&plaintext)?;
                plaintext.zeroize();
            }
        }

        Ok(file_meta)
    }

    pub fn add_file(&self, source: &Path, vault_dir: &Path, relative_path: &str) -> Result<()> {
        self.encrypt_file(source, vault_dir, relative_path)?;
        Ok(())
    }

    pub fn add_directory(
        &self,
        source: &Path,
        vault_dir: &Path,
        relative_path: &str,
    ) -> Result<()> {
        for entry in WalkDir::new(source).into_iter().filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let entry_relative = entry_path
                .strip_prefix(source)
                .map_err(|_| Error::VaultOp("Invalid path".to_string()))?;

            let full_relative = if relative_path.is_empty() {
                entry_relative.to_string_lossy().to_string()
            } else if entry_relative.to_string_lossy().is_empty() {
                relative_path.to_string()
            } else {
                format!("{}/{}", relative_path, entry_relative.to_string_lossy())
            };

            let clean_relative = full_relative.trim_start_matches('/');

            if entry_path.is_file() {
                self.encrypt_file(entry_path, vault_dir, clean_relative)?;
            } else if entry_path.is_dir() && entry_path != source {
                let dir_meta = FileMetadata {
                    original_name: clean_relative.to_string(),
                    original_size: 0,
                    is_directory: true,
                    children: None,
                };

                let temp_dir = vault_dir.join("d").join(".tmp_dir");
                fs::create_dir_all(&temp_dir)?;

                let meta_json =
                    serde_json::to_vec(&dir_meta).map_err(|_| Error::EncryptionFailed)?;

                let encrypted = crypto::encrypt_with_key(&meta_json, &self.master_key)?;
                let enc_path = self.get_encrypted_path(Path::new(clean_relative));
                let full_enc_path = vault_dir.join("d").join(&enc_path);

                if let Some(parent) = full_enc_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let mut file = File::create(&full_enc_path)?;
                file.write_all(&encrypted.nonce)?;
                file.write_all(&encrypted.tag)?;
                let meta_len = (meta_json.len() as u32).to_le_bytes();
                file.write_all(&meta_len)?;
                file.write_all(&encrypted.ciphertext)?;
                file.write_all(&[0x00])?;

                let _ = fs::remove_dir_all(temp_dir);
            }
        }
        Ok(())
    }

    pub fn list_files(&self, vault_dir: &Path) -> Result<Vec<String>> {
        let manifest_path = vault_dir.join("d").join(".manifest.enc");

        if !manifest_path.exists() {
            return Ok(Vec::new());
        }

        let mut file = File::open(&manifest_path)?;
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        let mut len_bytes = [0u8; 4];

        file.read_exact(&mut nonce)?;
        file.read_exact(&mut tag)?;
        file.read_exact(&mut len_bytes)?;

        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut ciphertext = vec![0u8; len];
        file.read_exact(&mut ciphertext)?;

        let manifest_json = crypto::decrypt_with_key(&ciphertext, &nonce, &self.master_key, &tag)?;
        ciphertext.zeroize();

        let manifest: FileManifest =
            serde_json::from_slice(&manifest_json).map_err(|_| Error::DecryptionFailed)?;

        Ok(manifest.files.keys().cloned().collect())
    }

    pub fn save_manifest(
        &self,
        vault_dir: &Path,
        files: &HashMap<String, FileMetadata>,
    ) -> Result<()> {
        let manifest = FileManifest {
            version: 1,
            files: files.clone(),
        };

        let manifest_json = serde_json::to_vec(&manifest).map_err(|_| Error::EncryptionFailed)?;

        let encrypted = crypto::encrypt_with_key(&manifest_json, &self.master_key)?;

        let manifest_path = vault_dir.join("d").join(".manifest.enc");
        let mut file = File::create(&manifest_path)?;

        file.write_all(&encrypted.nonce)?;
        file.write_all(&encrypted.tag)?;
        let len_bytes = (manifest_json.len() as u32).to_le_bytes();
        file.write_all(&len_bytes)?;
        file.write_all(&encrypted.ciphertext)?;

        Ok(())
    }

    pub fn load_manifest(&self, vault_dir: &Path) -> Result<FileManifest> {
        let manifest_path = vault_dir.join("d").join(".manifest.enc");

        if !manifest_path.exists() {
            return Ok(FileManifest {
                version: 1,
                files: HashMap::new(),
            });
        }

        let mut file = File::open(&manifest_path)?;
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        let mut len_bytes = [0u8; 4];

        file.read_exact(&mut nonce)?;
        file.read_exact(&mut tag)?;
        file.read_exact(&mut len_bytes)?;

        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut ciphertext = vec![0u8; len];
        file.read_exact(&mut ciphertext)?;

        let manifest_json = crypto::decrypt_with_key(&ciphertext, &nonce, &self.master_key, &tag)?;
        ciphertext.zeroize();

        serde_json::from_slice(&manifest_json).map_err(|_| Error::DecryptionFailed)
    }

    pub fn remove_file(&self, relative_path: &str, vault_dir: &Path) -> Result<()> {
        let enc_path = self.get_encrypted_path(Path::new(relative_path));
        let full_enc_path = vault_dir.join("d").join(&enc_path);

        if full_enc_path.exists() {
            fs::remove_file(&full_enc_path)?;
        }

        Ok(())
    }

    pub fn get_encrypted_file_path(&self, relative_path: &str, vault_dir: &Path) -> PathBuf {
        let enc_path = self.get_encrypted_path(Path::new(relative_path));
        vault_dir.join("d").join(&enc_path)
    }
}

impl Drop for FileOps {
    fn drop(&mut self) {
        crypto::zeroize_slice(&mut self.master_key);
    }
}
