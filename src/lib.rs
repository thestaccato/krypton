pub mod crypto;
pub mod error;
pub mod file_ops;
pub mod keystore;
pub mod single_file;
pub mod vault;

pub use error::{Error, Result};
pub use single_file::encrypt_file;
pub use single_file::decrypt_file;
pub use vault::Vault;
