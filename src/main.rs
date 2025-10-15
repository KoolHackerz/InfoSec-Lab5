mod aes_cipher;
mod zvh_format;

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::io::{self, Write};
use ansi_term::enable_ansi_support;
use colored::*;

use aes_cipher::{key_expansion, aes_encrypt_block, aes_decrypt_block, parse_key};
use zvh_format::{ZvhHeader, calculate_sha256, read_zvh_info};

#[derive(Parser)]
#[command(name = "AES ECB Cipher")]
#[command(about = "Symmetric block cipher system AES in ECB mode (implementation from scratch)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path (.zvh extension will be added automatically)
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption key (16 hex bytes = 32 hex characters for AES-128)
        #[arg(short, long)]
        key: String,
    },
    /// Decrypt file
    Decrypt {
        /// Encrypted .zvh file path
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption key (16 hex bytes = 32 hex characters for AES-128)
        #[arg(short, long)]
        key: String,
    },
    /// Open .zvh file (interactive mode with key prompt)
    Open {
        /// .zvh file path
        file: PathBuf,
    },
}

fn main() {
    let _enabled = enable_ansi_support();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encrypt { input, output, key }) => {
            // Automatically add .zvh extension if not present
            let output = if output.extension().and_then(|s| s.to_str()) != Some("zvh") {
                output.with_extension("zvh")
            } else {
                output
            };

            match encrypt_file(&input, &output, &key) {
                Ok(_) => println!("{} File successfully encrypted: {}", "[SUCCESS]".green().bold(), output.display()),
                Err(e) => eprintln!("{} Encryption error: {}", "[ERROR]".red().bold(), e),
            }
        }
        Some(Commands::Decrypt { input, output, key }) => {
            match decrypt_file(&input, &output, &key) {
                Ok(_) => println!("{} File successfully decrypted: {}", "[SUCCESS]".green().bold(), output.display()),
                Err(e) => eprintln!("{} Decryption error: {}", "[ERROR]".red().bold(), e),
            }
        }
        Some(Commands::Open { file }) => {
            match open_zvh_interactive(&file) {
                Ok(_) => {
                    println!("\n{} File successfully decrypted and opened!", "[SUCCESS]".green().bold());
                    println!("\nPress Enter to exit...");
                    let mut buffer = String::new();
                    io::stdin().read_line(&mut buffer).ok();
                }
                Err(e) => {
                    eprintln!("{} Error: {}", "[ERROR]".red().bold(), e);
                    println!("\nPress Enter to exit...");
                    let mut buffer = String::new();
                    io::stdin().read_line(&mut buffer).ok();
                    std::process::exit(1);
                }
            }
        }
        None => {
            // Interactive mode when no command is provided
            match run_interactive_mode() {
                Ok(_) => {
                    println!("\nPress Enter to exit...");
                    let mut buffer = String::new();
                    io::stdin().read_line(&mut buffer).ok();
                }
                Err(e) => {
                    eprintln!("{} Error: {}", "[ERROR]".red().bold(), e);
                    println!("\nPress Enter to exit...");
                    let mut buffer = String::new();
                    io::stdin().read_line(&mut buffer).ok();
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Interactive mode for encryption/decryption
fn run_interactive_mode() -> Result<(), String> {
    println!("{}", "╔════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║         AES-128 ECB File Cipher (Interactive)          ║".cyan());
    println!("{}", "╚════════════════════════════════════════════════════════╝".cyan());
    println!();

    // Choose operation
    println!("{}", "Select operation:".yellow().bold());
    println!("   [1] Encrypt file");
    println!("   [2] Decrypt file (.zvh)");
    println!();
    print!("   Enter choice (1 or 2): ");
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let choice = choice.trim();

    match choice {
        "1" => run_interactive_encryption(),
        "2" => run_interactive_decryption(),
        _ => Err("Invalid choice. Please enter 1 or 2.".to_string()),
    }
}

/// Interactive encryption
fn run_interactive_encryption() -> Result<(), String> {
    println!();
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".blue());
    println!("{}", "                    FILE ENCRYPTION".blue().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".blue());
    println!();

    // Get input file
    println!("{}", "Enter input file path (you can drag and drop the file here):".yellow());
    print!("   > ");
    io::stdout().flush().unwrap();

    let mut input_path = String::new();
    io::stdin().read_line(&mut input_path)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let input_path = clean_path(&input_path);
    let input = PathBuf::from(&input_path);

    if !input.exists() {
        return Err(format!("File not found: {}", input_path));
    }

    println!("   {} File found: {}", "[OK]".green(), input.display());

    // Display file info
    if let Ok(metadata) = fs::metadata(&input) {
        println!("   Size: {} bytes", metadata.len());
    }

    println!();

    // Get output file
    let output = input.with_extension("zvh");
    println!("{}", "Output file will be saved as:".yellow());
    println!("   {}", output.display());
    println!();

    // Get encryption key
    println!("{}", "Enter encryption key (32 hex characters, 0-9, a-f):".yellow());
    println!("   Example: 2b7e151628aed2a6abf7158809cf4f3c");
    println!("   Or press Enter to generate a random key");
    print!("   > ");
    io::stdout().flush().unwrap();

    let mut key_input = String::new();
    io::stdin().read_line(&mut key_input)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let key = key_input.trim();
    let key = if key.is_empty() {
        let random_key = generate_random_key();
        println!();
        println!("{}", "Generated random key:".green().bold());
        println!("   {}", random_key.bright_white());
        println!("   {} SAVE THIS KEY! You will need it to decrypt the file!", "[WARNING]".yellow().bold());
        println!();
        random_key
    } else {
        if key.len() != 32 {
            return Err(format!("Invalid key length: {} characters (required 32)", key.len()));
        }
        key.to_string()
    };

    println!("{}", "Encrypting file...".cyan());
    println!();

    encrypt_file(&input, &output, &key)?;

    println!();
    println!("{} File successfully encrypted!", "[SUCCESS]".green().bold());
    println!("   Output: {}", output.display());
    println!();
    println!("{} Encryption key: {}", "[KEY]".bright_magenta().bold(), key.bright_white());
    println!("   {} Keep this key safe! You will need it to decrypt the file!", "[WARNING]".yellow().bold());

    Ok(())
}

/// Interactive decryption
fn run_interactive_decryption() -> Result<(), String> {
    println!();
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".blue());
    println!("{}", "                    FILE DECRYPTION".blue().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".blue());
    println!();

    // Get input file
    println!("{}", "Enter encrypted file path (you can drag and drop the .zvh file here):".yellow());
    print!("   > ");
    io::stdout().flush().unwrap();

    let mut input_path = String::new();
    io::stdin().read_line(&mut input_path)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let input_path = clean_path(&input_path);
    let input = PathBuf::from(&input_path);

    if !input.exists() {
        return Err(format!("File not found: {}", input_path));
    }

    println!("   {} File found: {}", "[OK]".green(), input.display());

    // Display file info
    if let Ok(metadata) = fs::metadata(&input) {
        println!("   Size: {} bytes", metadata.len());
    }

    println!();

    // Read ZVH info
    let orig_extension = match read_zvh_info(&input) {
        Ok(info) => {
            println!("{}", "File information:".cyan().bold());
            println!("   Format version: ZVH v{}.{}", info.0, info.1);
            println!("   Original size: {} bytes", info.2);
            let ext = info.3.clone();
            if !ext.is_empty() {
                println!("   Original extension: {}", ext);
            }
            println!();
            ext
        }
        Err(e) => {
            println!("   {} {}", "[WARNING]".yellow().bold(), e);
            println!();
            String::new()
        }
    };

    // Determine output file
    let mut output = input.with_extension("");
    if !orig_extension.is_empty() {
        let file_name = output.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decrypted");
        output.set_file_name(format!("{}{}", file_name, orig_extension));
    }

    println!("{}", "Output file will be saved as:".yellow());
    println!("   {}", output.display());
    println!();

    // Get decryption key
    println!("{}", "Enter decryption key (32 hex characters):".yellow());
    print!("   > ");
    io::stdout().flush().unwrap();

    let mut key_input = String::new();
    io::stdin().read_line(&mut key_input)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let key = key_input.trim();

    if key.len() != 32 {
        return Err(format!("Invalid key length: {} characters (required 32)", key.len()));
    }

    println!();
    println!("{}", "Decrypting file...".cyan());
    println!();

    decrypt_file(&input, &output, key)?;

    println!();
    println!("{} File successfully decrypted!", "[SUCCESS]".green().bold());
    println!("   Output: {}", output.display());

    // Try to open the file
    println!();
    println!("Attempting to open file...");
    if let Err(e) = open_file(&output) {
        println!("   {} Could not automatically open file: {}", "[WARNING]".yellow().bold(), e);
        println!("   File saved: {}", output.display());
    } else {
        println!("   {} File opened!", "[OK]".green());
    }

    Ok(())
}

/// Clean file path from quotes and whitespace
fn clean_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

/// Generate random hex key
fn generate_random_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple pseudo-random key generation using system time
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut key = String::new();
    let mut seed = timestamp;

    for _ in 0..32 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let hex_char = format!("{:x}", (seed >> 16) & 0xF);
        key.push_str(&hex_char);
    }

    key
}

/// Interactive .zvh file opening with key prompt
fn open_zvh_interactive(input_path: &PathBuf) -> Result<(), String> {
    println!("{}", "╔════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║         ZVH File Decryption (AES-128 ECB)              ║".cyan());
    println!("{}", "╚════════════════════════════════════════════════════════╝".cyan());
    println!();

    // Check file existence
    if !input_path.exists() {
        return Err(format!("File not found: {}", input_path.display()));
    }

    println!("File: {}", input_path.display());

    // Try to read metadata
    if let Ok(metadata) = fs::metadata(input_path) {
        println!("Size: {} bytes", metadata.len());
    }

    println!();

    // Read header to display information
    let orig_extension = match read_zvh_info(input_path) {
        Ok(info) => {
            println!("{}", "File information:".cyan().bold());
            println!("   Format version: ZVH v{}.{}", info.0, info.1);
            println!("   Original size: {} bytes", info.2);
            let ext = info.3.clone();
            if !ext.is_empty() {
                println!("   Original extension: {}", ext);
            }
            println!();
            ext
        }
        Err(e) => {
            println!("   {} {}", "[WARNING]".yellow().bold(), e);
            println!();
            String::new()
        }
    };

    // Request key
    println!("{}", "Enter decryption key (32 hex characters):".yellow());
    print!("   > ");
    io::stdout().flush().unwrap();

    let mut key_input = String::new();
    io::stdin().read_line(&mut key_input)
        .map_err(|e| format!("Input reading error: {}", e))?;

    let key = key_input.trim();

    // Check key length
    if key.len() != 32 {
        return Err(format!("Invalid key length: {} characters (required 32)", key.len()));
    }

    println!();
    println!("{}", "Decrypting file...".cyan());
    println!();

    // Determine output file with original extension
    let mut output_path = input_path.with_extension("");
    if !orig_extension.is_empty() {
        let file_name = output_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decrypted");
        output_path.set_file_name(format!("{}{}", file_name, orig_extension));
    }

    // Decrypt
    decrypt_file(input_path, &output_path, key)?;

    // Try to open file
    println!("\nAttempting to open file...");
    if let Err(e) = open_file(&output_path) {
        println!("   {} Could not automatically open file: {}", "[WARNING]".yellow().bold(), e);
        println!("   File saved: {}", output_path.display());
    } else {
        println!("   {} File opened: {}", "[OK]".green(), output_path.display());
    }

    Ok(())
}

/// Open file in default system application
fn open_file(path: &PathBuf) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(&["/C", "start", "", &path.to_string_lossy()])
            .spawn()
            .map_err(|e| format!("Launch error: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|e| format!("Launch error: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|e| format!("Launch error: {}", e))?;
    }

    Ok(())
}

/// File encryption
fn encrypt_file(input_path: &PathBuf, output_path: &PathBuf, key_hex: &str) -> Result<(), String> {
    let key = parse_key(key_hex)?;
    println!("{}", "Generating round keys...".cyan());
    let round_keys = key_expansion(&key);

    let data = fs::read(input_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let original_size = data.len();
    println!("Original file size: {} bytes", original_size);

    let extension = input_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext))
        .unwrap_or_default();

    if !extension.is_empty() {
        println!("Original extension: {}", extension);
    }

    println!("{}", "Calculating SHA-256 hash...".cyan());
    let hash = calculate_sha256(&data);
    println!("SHA-256: {}", hex::encode(hash));

    let mut padded_data = data;
    let padding_len = 16 - (padded_data.len() % 16);
    padded_data.extend(vec![padding_len as u8; padding_len]);
    println!("Size after padding: {} bytes", padded_data.len());

    let mut encrypted = Vec::with_capacity(padded_data.len());
    for chunk in padded_data.chunks(16) {
        let encrypted_block = aes_encrypt_block(chunk, &round_keys);
        encrypted.extend_from_slice(&encrypted_block);
    }
    println!("Encrypted {} blocks", encrypted.len() / 16);

    let header = ZvhHeader::new(original_size as u64, encrypted.len() as u64, hash, &extension);
    let mut final_data = header.to_bytes();
    final_data.extend_from_slice(&encrypted);

    fs::write(output_path, &final_data)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    let (major, minor) = header.get_version();
    println!("\n{}", "ZVH file created:".green().bold());
    println!("   Header: ZVH v{}.{}", major, minor);
    println!("   Header size: {} bytes", ZvhHeader::size());
    println!("   Original size: {} bytes", original_size);
    println!("   Encrypted size: {} bytes", encrypted.len());
    if !extension.is_empty() {
        println!("   Saved extension: {}", extension);
    }
    println!("   Total file size: {} bytes", final_data.len());

    Ok(())
}

/// File decryption
fn decrypt_file(input_path: &PathBuf, output_path: &PathBuf, key_hex: &str) -> Result<(), String> {
    let key = parse_key(key_hex)?;
    println!("{}", "Generating round keys...".cyan());
    let round_keys = key_expansion(&key);

    let data = fs::read(input_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    if data.len() < ZvhHeader::size() {
        return Err("File is too small for ZVH format".to_string());
    }

    println!("{}", "Reading ZVH header...".cyan());
    let header = ZvhHeader::from_bytes(&data)?;

    let (major, minor) = header.get_version();
    println!("\n{}", "ZVH file information:".cyan().bold());
    println!("   Header: ZVH v{}.{}", major, minor);
    println!("   Original size: {} bytes", header.original_size);
    println!("   Encrypted size: {} bytes", header.encrypted_size);

    let saved_extension = header.get_extension();
    if !saved_extension.is_empty() {
        println!("   Original extension: {}", saved_extension);
    }
    println!("   SHA-256 hash: {}", hex::encode(header.hash));

    let encrypted_data = &data[ZvhHeader::size()..];
    if encrypted_data.len() != header.encrypted_size as usize {
        return Err(format!(
            "Data size mismatch: expected {} bytes, got {} bytes",
            header.encrypted_size, encrypted_data.len()
        ));
    }

    if encrypted_data.len() % 16 != 0 {
        return Err("Encrypted data size must be a multiple of 16 bytes".to_string());
    }

    println!("\n{}", "Decrypting data...".cyan());
    let mut decrypted = Vec::with_capacity(encrypted_data.len());
    for chunk in encrypted_data.chunks(16) {
        let decrypted_block = aes_decrypt_block(chunk, &round_keys);
        decrypted.extend_from_slice(&decrypted_block);
    }
    println!("Decrypted {} blocks", encrypted_data.len() / 16);

    if let Some(&padding_len) = decrypted.last() {
        if padding_len as usize <= 16 && padding_len > 0 {
            let len = decrypted.len();
            let padding_start = len - padding_len as usize;
            if decrypted[padding_start..].iter().all(|&b| b == padding_len) {
                decrypted.truncate(padding_start);
            } else {
                return Err("Invalid padding (possibly wrong key)".to_string());
            }
        }
    }
    println!("Size after padding removal: {} bytes", decrypted.len());

    if decrypted.len() != header.original_size as usize {
        return Err(format!(
            "Warning: decrypted data size ({} bytes) does not match original ({} bytes)",
            decrypted.len(), header.original_size
        ));
    }

    println!("\n{}", "Verifying file integrity...".cyan());
    let calculated_hash = calculate_sha256(&decrypted);
    println!("Expected SHA-256: {}", hex::encode(header.hash));
    println!("Calculated SHA-256: {}", hex::encode(calculated_hash));

    if calculated_hash == header.hash {
        println!("{} Hash matches - file is not corrupted", "[OK]".green().bold());
    } else {
        return Err(format!("{} Hash mismatch! File may be corrupted or decrypted with wrong key", "[ERROR]".red().bold()));
    }

    let final_output_path = if !saved_extension.is_empty() && output_path.extension().is_none() {
        let mut path = output_path.clone();
        let file_name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decrypted");
        path.set_file_name(format!("{}{}", file_name, saved_extension));
        println!("\nRestored original extension: {}", saved_extension);
        path
    } else {
        output_path.clone()
    };

    fs::write(&final_output_path, &decrypted)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}
