use crate::crypto;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const VAULT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: u32,
    pub salt: Vec<u8>,
    pub verification_hash: Vec<u8>,
    pub encrypted_master_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

pub struct KeyStore {
    master_key: Option<[u8; 32]>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self { master_key: None }
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn get_master_key(&self) -> Result<[u8; 32]> {
        self.master_key.ok_or(Error::VaultLocked)
    }

    pub fn init(&mut self, password: &str) -> Result<VaultConfig> {
        let salt = crypto::generate_salt();
        let master_key = crypto::generate_random_key();

        let mut derived_key = crypto::derive_key(password, &salt)?;

        let mut verification_data = master_key.to_vec();
        verification_data.extend_from_slice(b"KRYPTON_VAULT_V1");
        let verification_hash = Sha256::digest(&verification_data);
        verification_data.zeroize();

        let encrypted = crypto::encrypt_with_key(&master_key, &derived_key)?;
        crypto::zeroize_slice(&mut derived_key);

        self.master_key = Some(master_key);

        Ok(VaultConfig {
            version: VAULT_VERSION,
            salt: salt.to_vec(),
            verification_hash: verification_hash.to_vec(),
            encrypted_master_key: encrypted.ciphertext,
            nonce: encrypted.nonce.to_vec(),
            tag: encrypted.tag.to_vec(),
        })
    }

    pub fn unlock(&mut self, password: &str, config: &VaultConfig) -> Result<()> {
        if config.version != VAULT_VERSION {
            return Err(Error::InvalidVault);
        }

        let mut derived_key = crypto::derive_key(password, &config.salt)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&config.nonce);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&config.tag);

        let mut master_key_bytes =
            crypto::decrypt_with_key(&config.encrypted_master_key, &nonce, &derived_key, &tag)?;

        crypto::zeroize_slice(&mut derived_key);

        if master_key_bytes.len() != 32 {
            return Err(Error::InvalidPassword);
        }

        let mut verification_data = master_key_bytes.clone();
        verification_data.extend_from_slice(b"KRYPTON_VAULT_V1");
        let verification_hash = Sha256::digest(&verification_data);
        verification_data.zeroize();

        if !crypto::secure_compare(&verification_hash, &config.verification_hash) {
            return Err(Error::InvalidPassword);
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);
        master_key_bytes.zeroize();

        self.master_key = Some(master_key);
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(ref mut key) = self.master_key {
            crypto::zeroize_slice(key);
        }
        self.master_key = None;
    }

    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        config: &VaultConfig,
    ) -> Result<VaultConfig> {
        self.unlock(old_password, config)?;
        let master_key = self.get_master_key()?;

        let new_salt = crypto::generate_salt();
        let mut new_derived_key = crypto::derive_key(new_password, &new_salt)?;

        let mut verification_data = master_key.to_vec();
        verification_data.extend_from_slice(b"KRYPTON_VAULT_V1");
        let verification_hash = Sha256::digest(&verification_data);
        verification_data.zeroize();

        let encrypted = crypto::encrypt_with_key(&master_key, &new_derived_key)?;
        crypto::zeroize_slice(&mut new_derived_key);

        Ok(VaultConfig {
            version: VAULT_VERSION,
            salt: new_salt.to_vec(),
            verification_hash: verification_hash.to_vec(),
            encrypted_master_key: encrypted.ciphertext,
            nonce: encrypted.nonce.to_vec(),
            tag: encrypted.tag.to_vec(),
        })
    }
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.lock();
    }
}
