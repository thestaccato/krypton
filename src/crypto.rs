use crate::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, SaltString},
    Argon2, PasswordHasher,
};
use rand::RngCore;
use zeroize::Zeroize;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

pub struct EncryptedData {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let salt_str = std::str::from_utf8(salt).map_err(|_| Error::KeyDerivationFailed)?;

    let salt = SaltString::from_b64(salt_str).map_err(|_| Error::KeyDerivationFailed)?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 4, 4, Some(KEY_SIZE)).map_err(|_| Error::KeyDerivationFailed)?,
    );

    let mut key = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| Error::KeyDerivationFailed)?
        .hash
        .ok_or(Error::KeyDerivationFailed)?
        .as_bytes()
        .to_vec();

    let mut result = [0u8; KEY_SIZE];
    result.copy_from_slice(&key[..KEY_SIZE]);
    key.zeroize();

    Ok(result)
}

pub fn generate_salt() -> [u8; 22] {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let bytes = salt.as_str().as_bytes();
    let mut result = [0u8; 22];
    result.copy_from_slice(&bytes[..22]);
    result
}

pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::EncryptionFailed)?;

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
    let ciphertext_without_tag = &ciphertext[..ciphertext.len() - 16];

    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext: ciphertext_without_tag.to_vec(),
        tag,
    })
}

pub fn decrypt_with_key(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    key: &[u8; KEY_SIZE],
    expected_tag: &[u8; 16],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce);

    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(expected_tag);

    cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| Error::DecryptionFailed)
}

pub fn generate_random_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn zeroize_slice(slice: &mut [u8]) {
    slice.zeroize();
}
