use std::fs;
use std::path::PathBuf;
use sha2::{Sha256, Digest};

/// Structure for storing ZVH file metadata
pub struct ZvhHeader {
    magic: [u8; 3],           // "ZVH"
    version_major: u8,        // 2
    version_minor: u8,        // 0
    pub original_size: u64,   // Original file size
    pub encrypted_size: u64,  // Encrypted data size
    pub hash: [u8; 32],       // SHA-256 hash of the original file
    extension_len: u8,        // File extension length
    extension: [u8; 16],      // File extension (maximum 16 bytes)
}

impl ZvhHeader {
    /// Create a new ZVH header
    pub fn new(original_size: u64, encrypted_size: u64, hash: [u8; 32], extension: &str) -> Self {
        let mut ext_bytes = [0u8; 16];
        let ext_data = extension.as_bytes();
        let ext_len = ext_data.len().min(16);
        ext_bytes[..ext_len].copy_from_slice(&ext_data[..ext_len]);

        ZvhHeader {
            magic: [b'Z', b'V', b'H'],
            version_major: 2,
            version_minor: 0,
            original_size,
            encrypted_size,
            hash,
            extension_len: ext_len as u8,
            extension: ext_bytes,
        }
    }

    /// Convert header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.version_major);
        bytes.push(self.version_minor);
        bytes.extend_from_slice(&self.original_size.to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_size.to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes.push(self.extension_len);
        bytes.extend_from_slice(&self.extension);
        bytes
    }

    /// Read header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 70 {
            return Err("Insufficient data to read ZVH header".to_string());
        }

        let mut magic = [0u8; 3];
        magic.copy_from_slice(&bytes[0..3]);

        if &magic != b"ZVH" {
            return Err(format!("Invalid file signature. Expected 'ZVH', got '{}'",
                String::from_utf8_lossy(&magic)));
        }

        let version_major = bytes[3];
        let version_minor = bytes[4];

        if version_major != 2 {
            return Err(format!("Unsupported file version: {}.{}", version_major, version_minor));
        }

        let mut original_size_bytes = [0u8; 8];
        original_size_bytes.copy_from_slice(&bytes[5..13]);
        let original_size = u64::from_le_bytes(original_size_bytes);

        let mut encrypted_size_bytes = [0u8; 8];
        encrypted_size_bytes.copy_from_slice(&bytes[13..21]);
        let encrypted_size = u64::from_le_bytes(encrypted_size_bytes);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[21..53]);

        let extension_len = bytes[53];

        let mut extension = [0u8; 16];
        extension.copy_from_slice(&bytes[54..70]);

        Ok(ZvhHeader {
            magic,
            version_major,
            version_minor,
            original_size,
            encrypted_size,
            hash,
            extension_len,
            extension,
        })
    }

    /// Get file extension
    pub fn get_extension(&self) -> String {
        if self.extension_len > 0 {
            String::from_utf8_lossy(&self.extension[..self.extension_len as usize]).to_string()
        } else {
            String::new()
        }
    }

    /// Get format version
    pub fn get_version(&self) -> (u8, u8) {
        (self.version_major, self.version_minor)
    }

    /// Header size in bytes
    pub fn size() -> usize {
        70 // 3 (magic) + 1 (major) + 1 (minor) + 8 (original_size) + 8 (encrypted_size) + 32 (hash) + 1 (ext_len) + 16 (extension)
    }
}

/// Calculate SHA-256 hash
pub fn calculate_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

/// Read information from ZVH file header
pub fn read_zvh_info(path: &PathBuf) -> Result<(u8, u8, u64, String), String> {
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    if data.len() < 70 {
        return Err("File is too small for ZVH format".to_string());
    }

    let header = ZvhHeader::from_bytes(&data)?;
    let (major, minor) = header.get_version();
    Ok((
        major,
        minor,
        header.original_size,
        header.get_extension(),
    ))
}
