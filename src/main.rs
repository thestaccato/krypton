use clap::{Parser, Subcommand};
use krypton::error::Result;
use krypton::single_file;
use krypton::vault::Vault;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "krypton")]
#[command(about = "Encrypt your personal files or secrets", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Initialize a new vault")]
    Init {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
    },
    #[command(about = "Add a file or folder to the vault")]
    Add {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
        #[arg(help = "Path to the file or folder to add")]
        path: PathBuf,
        #[arg(short, long, help = "Custom name in vault")]
        name: Option<String>,
    },
    #[command(about = "Remove a file or folder from the vault")]
    Remove {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
        #[arg(help = "Name of the file/folder in vault")]
        name: String,
    },
    #[command(about = "List vault contents")]
    List {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
    },
    #[command(about = "Extract/decrypt a file from the vault")]
    Extract {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
        #[arg(help = "Name of the file in vault")]
        name: String,
        #[arg(help = "Destination path")]
        dest: PathBuf,
    },
    #[command(about = "Change vault password")]
    ChangePassword {
        #[arg(help = "Path to the vault directory")]
        vault: PathBuf,
    },
    #[command(about = "Encrypt a single file")]
    Encrypt {
        #[arg(help = "Path to the file to encrypt")]
        input: PathBuf,
        #[arg(help = "Output encrypted file (default: input.krf)")]
        output: Option<PathBuf>,
    },
    #[command(about = "Decrypt a single file")]
    Decrypt {
        #[arg(help = "Path to the encrypted file (.krf)")]
        input: PathBuf,
        #[arg(help = "Output decrypted file")]
        output: PathBuf,
    },
}

fn prompt_password(prompt: &str) -> Result<String> {
    if let Ok(pwd) = std::env::var("KRYPTON_PASSWORD") {
        return Ok(pwd);
    }

    print!("{}: ", prompt);
    io::stdout()
        .flush()
        .map_err(|_| krypton::error::Error::VaultOp("IO error".to_string()))?;

    let password = rpassword::read_password()
        .map_err(|_| krypton::error::Error::VaultOp("Failed to read password".to_string()))?;

    Ok(password)
}

fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli.command) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Init { vault } => {
            let password = prompt_password("Enter vault password")?;
            let confirm = prompt_password("Confirm password")?;

            if password != confirm {
                return Err(krypton::error::Error::VaultOp(
                    "Passwords don't match".to_string(),
                ));
            }

            let mut vault_obj = Vault::new(vault);
            vault_obj.init(&password)?;
            println!("Vault created successfully!");
            Ok(())
        }
        Commands::Add { vault, path, name } => {
            let password = prompt_password("Enter vault password")?;
            let mut vault_obj = Vault::new(vault);

            if !vault_obj.exists() {
                return Err(krypton::error::Error::InvalidVault);
            }

            vault_obj.unlock(&password)?;
            vault_obj.add(&path, name.as_deref())?;
            println!("Added successfully!");
            Ok(())
        }
        Commands::Remove { vault, name } => {
            let password = prompt_password("Enter vault password")?;
            let mut vault_obj = Vault::new(vault);

            if !vault_obj.exists() {
                return Err(krypton::error::Error::InvalidVault);
            }

            vault_obj.unlock(&password)?;
            vault_obj.remove(&name)?;
            println!("Removed successfully!");
            Ok(())
        }
        Commands::List { vault } => {
            let password = prompt_password("Enter vault password")?;
            let mut vault_obj = Vault::new(vault);

            if !vault_obj.exists() {
                return Err(krypton::error::Error::InvalidVault);
            }

            vault_obj.unlock(&password)?;
            let files = vault_obj.list()?;

            if files.is_empty() {
                println!("Vault is empty");
                return Ok(());
            }

            println!("{:<40} {:>12} {}", "NAME", "SIZE", "TYPE");
            println!("{}", "-".repeat(60));

            for (name, size, is_dir) in files {
                let type_str = if is_dir { "dir" } else { "file" };
                let size_str = if is_dir {
                    "-".to_string()
                } else {
                    format_size(size)
                };
                println!("{:<40} {:>12} {}", name, size_str, type_str);
            }
            Ok(())
        }
        Commands::Extract { vault, name, dest } => {
            let password = prompt_password("Enter vault password")?;
            let mut vault_obj = Vault::new(vault);

            if !vault_obj.exists() {
                return Err(krypton::error::Error::InvalidVault);
            }

            vault_obj.unlock(&password)?;
            vault_obj.extract(&name, &dest)?;
            println!("Extracted to: {}", dest.display());
            Ok(())
        }
        Commands::ChangePassword { vault } => {
            let old = prompt_password("Current password")?;
            let new = prompt_password("New password")?;
            let confirm = prompt_password("Confirm new password")?;

            if new != confirm {
                return Err(krypton::error::Error::VaultOp(
                    "New passwords don't match".to_string(),
                ));
            }

            let mut vault_obj = Vault::new(vault);

            if !vault_obj.exists() {
                return Err(krypton::error::Error::InvalidVault);
            }

            vault_obj.unlock(&old)?;
            vault_obj.change_password(&old, &new)?;
            println!("Password changed successfully!");
            Ok(())
        }
        Commands::Encrypt { input, output } => {
            let password = prompt_password("Enter encryption password")?;
            let output_path = single_file::encrypt_file(&password, &input, output.as_deref())?;
            println!("Encrypted to: {}", output_path.display());
            Ok(())
        }
        Commands::Decrypt { input, output } => {
            let password = prompt_password("Enter decryption password")?;
            let original_name = single_file::decrypt_file(&password, &input, &output)?;

            let dest_path = if output.to_string_lossy() == "-" {
                print!("Original filename: {} - Enter 'y' to save: ", original_name);
                io::stdout().flush().ok();
                let mut confirm = String::new();
                io::stdin().read_line(&mut confirm).ok();
                if confirm.trim() == "y" || confirm.trim().is_empty() {
                    PathBuf::from(&original_name)
                } else {
                    output.clone()
                }
            } else {
                output.clone()
            };

            println!("Decrypted '{}' to: {}", original_name, dest_path.display());
            Ok(())
        }
    }
}
