# Krypton

A CLI tool for creating encrypted vaults and single-file encryption with **file's metadata protection**.

Krypton is also a Rust library, other software can use its encryption primitives without reimplementing AES-256-GCM or Argon2id.

## Library Usage

```toml
[dependencies]
krypton = { version = "0.2", default-features = false }
```

```rust
use krypton::{encrypt_file, decrypt_file, Vault};
use std::path::Path;

let out = encrypt_file("password", Path::new("document.pdf"), None)?;
let name = decrypt_file("password", Path::new("out.krf"), Path::new("restored.pdf"))?;

let mut vault = Vault::new("myvault".into());
vault.init("password")?;
vault.unlock("password")?;
vault.add(Path::new("secret.pdf"), None)?;
vault.add(Path::new("photos"), None)?;
let files = vault.list()?;
vault.extract("secret.pdf", Path::new("./out"))?;
vault.change_password("password", "newpassword")?;
vault.lock();
```

The library exposes:
- `krypton::encrypt_file` / `decrypt_file` — single file .krf format
- `krypton::Vault` — multi-file encrypted vault container
- `krypton::crypto` — low-level AES-256-GCM + Argon2id primitives
- `krypton::Error` / `Result` — error types

CLI dependencies (`clap`, `rpassword`) are optional; library users disable them with `default-features = false`.

## CLI Usage

Install:

```bash
cargo install krypton
```

### Single File Mode

```bash
# Encrypt — filename hidden
krypton encrypt taxes2024.pdf
# Output: 3b736a01...431.krf (random hashed name)

# Decrypt — recovers original filename
krypton decrypt 3b736a01...431.krf output.pdf
# Decrypted 'taxes2024.pdf' to: output.pdf
```

### Vault Mode

```bash
# Create vault
krypton init myvault

# Add files (filename hidden in vault)
krypton add myvault secret.pdf
krypton add myvault photos/

# List (shows original names — requires password)
krypton list myvault

# Extract
krypton extract myvault secret.pdf ./decrypted.pdf

# Remove
krypton remove myvault secret.pdf

# Change password
krypton change-password myvault
```

### Password Options

```bash
# Interactive (default)
krypton encrypt file.txt

# Via environment variable
KRYPTON_PASSWORD="secret" krypton encrypt file.txt
```

## Security Features

### Encryption Standards
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Argon2id (memory-hard, GPU-resistant)
- **Parameters**: Argon2id with 64MB memory, 4 iterations, 4 parallelism

### Metadata Protection
- **Filename Encryption**: All filenames are hashed and hidden
- **File Content**: Encrypted with unique nonces per chunk
- **Key Derivation**: Salt prevents rainbow table attacks
- **Memory Security**: Sensitive data zeroed after use

## File Format (.krf)

```
KRYPTON2\n      # Magic header (9 bytes)
[22 bytes]      # Salt
[12 bytes]      # Nonce
[16 bytes]      # Authentication tag
[4 bytes]       # Ciphertext length
[ciphertext]    # Encrypted [filename\0content]
```

### Filename Protection
- Original filename is **encrypted inside the ciphertext**
- Output filename is a random hash (e.g., `3b73...431.krf`)
- No metadata leakage, even filename size is hidden
- Decryption recovers original filename automatically

## Vault Structure

```
vault/
├── vault.config        # Encrypted master key + parameters
└── d/                  # Encrypted files
    ├── .manifest.enc   # Encrypted file index (names + metadata)
    └── [hash]/[hash].enc  # Hashed filenames — completely hidden
```

### Vault Filename Protection
- Original filenames are hashed with master key
- Original names only visible after unlock + list command
- Even the vault owner sees clean names only when authenticated

## Security Comparison

| Feature | Krypton | Cryptomator | GPG | 7-Zip |
|---------|---------|---------|-----|-------|
| Content encryption | ✅ AES-256-GCM | ✅ AES-256-GCM | ✅ AES-256 | ✅ AES-256 |
| Filename hidden | ✅ **YES** | ✅ **YES** | ❌ No | ❌ No |
| Key derivation | ✅ Argon2id | ⚠️ PBKDF2 | ⚠️ PBKDF2 | ⚠️ PBKDF2 |

## Architecture

### Key Hierarchy
```
User Password
     │
     ▼
Argon2id(salt, password) → Derived Key
     │
     ▼
AES-256-GCM(derived_key, master_key) → vault.config
     │
     ▼
Master Key (32 bytes)
     │
     ├──► Encrypt/decrypt all vault files
     │
     └──► Hash filenames (SHA256 keyed with master key)
```
