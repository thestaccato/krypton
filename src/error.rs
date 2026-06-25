use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed: authentication error")]
    DecryptionFailed,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Vault not found or invalid format")]
    InvalidVault,

    #[error("Vault already initialized")]
    VaultExists,

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault is already unlocked")]
    VaultUnlocked,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("No active vault")]
    NoActiveVault,

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Vault operation error: {0}")]
    VaultOp(String),
}

pub type Result<T> = std::result::Result<T, Error>;
