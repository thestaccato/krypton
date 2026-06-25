use crate::crypto;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const MAGIC_HEADER: &[u8; 9] = b"KRYPTON2\n";
pub const SALT_SIZE: usize = 22;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub struct EncryptedFile {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_file(password: &str, input: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let input_path = input
        .canonicalize()
        .map_err(|_| Error::FileNotFound(input.to_string_lossy().to_string()))?;

    let original_name = input_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut file = fs::File::open(&input_path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    let mut name_bytes = original_name.as_bytes().to_vec();
    name_bytes.push(0x00);
    name_bytes.extend_from_slice(&plaintext);
    plaintext.zeroize();

    let salt = crypto::generate_salt();
    let mut key = crypto::derive_key(password, &salt)?;

    let encrypted = crypto::encrypt_with_key(&name_bytes, &key)?;
    name_bytes.zeroize();
    key.zeroize();

    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update(original_name.as_bytes());
            let hash = hasher.finalize();
            PathBuf::from(format!("{:x}.krf", hash))
        }
    };

    let mut output_file = fs::File::create(&output_path)?;
    output_file.write_all(MAGIC_HEADER)?;
    output_file.write_all(&salt)?;
    output_file.write_all(&encrypted.nonce)?;
    output_file.write_all(&encrypted.tag)?;

    let data_len = (encrypted.ciphertext.len() as u32).to_le_bytes();
    output_file.write_all(&data_len)?;
    output_file.write_all(&encrypted.ciphertext)?;

    Ok(output_path)
}

pub fn decrypt_file(password: &str, input: &Path, output: &Path) -> Result<String> {
    let mut file = fs::File::open(input)?;

    let mut magic = [0u8; 9];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC_HEADER {
        return Err(Error::InvalidVault);
    }

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    let mut tag = [0u8; TAG_SIZE];
    let mut data_len_bytes = [0u8; 4];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut tag)?;
    file.read_exact(&mut data_len_bytes)?;

    let data_len = u32::from_le_bytes(data_len_bytes) as usize;
    let mut ciphertext = vec![0u8; data_len];
    file.read_exact(&mut ciphertext)?;

    let mut key = crypto::derive_key(password, &salt)?;

    let decrypted = crypto::decrypt_with_key(&ciphertext, &nonce, &key, &tag)?;
    key.zeroize();
    ciphertext.zeroize();

    let sep_idx = decrypted
        .iter()
        .position(|&x| x == 0x00)
        .ok_or(Error::DecryptionFailed)?;

    let original_name = String::from_utf8_lossy(&decrypted[..sep_idx]).to_string();
    let file_content = &decrypted[sep_idx + 1..];

    fs::write(output, file_content)?;

    Ok(original_name)
}
