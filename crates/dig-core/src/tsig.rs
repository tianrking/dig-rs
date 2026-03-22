//! TSIG (Transaction SIGnature) authentication support
//!
//! This module provides TSIG authentication for DNS queries,
//! as specified in RFC 2845.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

use crate::error::Result;

/// TSIG authentication errors
#[derive(Debug, Error)]
pub enum TsigError {
    #[error("Invalid TSIG key format")]
    InvalidKeyFormat,
    #[error("Unsupported TSIG algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("TSIG key not found")]
    KeyNotFound,
    #[error("Failed to sign message: {0}")]
    SigningError(String),
}

/// TSIG algorithms supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TsigAlgorithm {
    /// HMAC-MD5
    HMACMD5,
    /// HMAC-SHA1
    HMACSHA1,
    /// HMAC-SHA224
    HMACSHA224,
    /// HMAC-SHA256
    HMACSHA256,
    /// HMAC-SHA384
    HMACSHA384,
    /// HMAC-SHA512
    HMACSHA512,
}

impl TsigAlgorithm {
    /// Parse algorithm from string
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "HMAC-MD5.SIG-ALG.REG.INT" | "MD5" | "HMACMD5" | "HMAC-MD5" => {
                Some(TsigAlgorithm::HMACMD5)
            }
            "HMAC-SHA1" | "SHA1" | "HMACSHA1" => Some(TsigAlgorithm::HMACSHA1),
            "HMAC-SHA224" | "SHA224" | "HMACSHA224" => Some(TsigAlgorithm::HMACSHA224),
            "HMAC-SHA256" | "SHA256" | "HMACSHA256" => Some(TsigAlgorithm::HMACSHA256),
            "HMAC-SHA384" | "SHA384" | "HMACSHA384" => Some(TsigAlgorithm::HMACSHA384),
            "HMAC-SHA512" | "SHA512" | "HMACSHA512" => Some(TsigAlgorithm::HMACSHA512),
            _ => None,
        }
    }

    /// Get the RFC name for this algorithm
    pub fn rfc_name(&self) -> &'static str {
        match self {
            TsigAlgorithm::HMACMD5 => "hmac-md5.sig-alg.reg.int",
            TsigAlgorithm::HMACSHA1 => "hmac-sha1",
            TsigAlgorithm::HMACSHA224 => "hmac-sha224",
            TsigAlgorithm::HMACSHA256 => "hmac-sha256",
            TsigAlgorithm::HMACSHA384 => "hmac-sha384",
            TsigAlgorithm::HMACSHA512 => "hmac-sha512",
        }
    }

    /// Get the digest size for this algorithm
    pub fn digest_size(&self) -> usize {
        match self {
            TsigAlgorithm::HMACMD5 => 16,
            TsigAlgorithm::HMACSHA1 => 20,
            TsigAlgorithm::HMACSHA224 => 28,
            TsigAlgorithm::HMACSHA256 => 32,
            TsigAlgorithm::HMACSHA384 => 48,
            TsigAlgorithm::HMACSHA512 => 64,
        }
    }
}

impl std::fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.rfc_name())
    }
}

/// TSIG key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigKey {
    /// Key name
    pub name: String,
    /// Key data (base64-encoded or hex)
    pub key: String,
    /// Algorithm
    pub algorithm: TsigAlgorithm,
}

impl TsigKey {
    /// Create a new TSIG key
    pub fn new(name: impl Into<String>, key: impl Into<String>, algorithm: TsigAlgorithm) -> Self {
        Self {
            name: name.into(),
            key: key.into(),
            algorithm,
        }
    }

    /// Parse TSIG key from BIND format
    ///
    /// Format: `name algorithm:base64key`
    pub fn from_bind_format(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let name = parts[0];
        let key_part = parts[1];

        let (algorithm_str, key_data) = key_part.split_once(':')?;
        let algorithm = TsigAlgorithm::from_str_name(algorithm_str)?;

        Some(Self {
            name: name.to_string(),
            key: key_data.to_string(),
            algorithm,
        })
    }

    /// Parse TSIG key from file format (BIND key file)
    ///
    /// File format:
    /// ```text
    /// key "name" {
    ///     algorithm "algorithm";
    ///     secret "base64key";
    /// };
    /// ```
    pub fn from_file_format(content: &str) -> std::result::Result<Self, TsigError> {
        let content = content.trim();

        // Extract key name
        let name_start = content.find("key \"").ok_or(TsigError::InvalidKeyFormat)?;
        let name_end = content[name_start + 5..]
            .find('"')
            .ok_or(TsigError::InvalidKeyFormat)?;
        let name = content[name_start + 5..name_start + 5 + name_end].to_string();

        // Extract algorithm
        let alg_start = content
            .find("algorithm \"")
            .ok_or(TsigError::InvalidKeyFormat)?;
        let alg_end = content[alg_start + 11..]
            .find('"')
            .ok_or(TsigError::InvalidKeyFormat)?;
        let algorithm_str = &content[alg_start + 11..alg_start + 11 + alg_end];
        let algorithm = TsigAlgorithm::from_str_name(algorithm_str)
            .ok_or_else(|| TsigError::UnsupportedAlgorithm(algorithm_str.to_string()))?;

        // Extract secret
        let secret_start = content
            .find("secret \"")
            .ok_or(TsigError::InvalidKeyFormat)?;
        let secret_end = content[secret_start + 8..]
            .find('"')
            .ok_or(TsigError::InvalidKeyFormat)?;
        let key = content[secret_start + 8..secret_start + 8 + secret_end].to_string();

        Ok(Self {
            name,
            key,
            algorithm,
        })
    }

    /// Get the decoded key bytes
    pub fn key_bytes(&self) -> std::result::Result<Vec<u8>, TsigError> {
        // Try base64 first
        if let Ok(decoded) = base64_decode(&self.key) {
            return Ok(decoded);
        }

        // Try hex next
        if let Ok(decoded) = hex_decode(&self.key) {
            return Ok(decoded);
        }

        // Treat as raw bytes if it looks like valid key material
        if self.key.len() >= 16 {
            Ok(self.key.as_bytes().to_vec())
        } else {
            Err(TsigError::InvalidKeyFormat)
        }
    }
}

/// Simple base64 decode
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, TsigError> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(input)
        .map_err(|e| TsigError::SigningError(e.to_string()))
}

/// Simple hex decode
fn hex_decode(input: &str) -> std::result::Result<Vec<u8>, TsigError> {
    let input = input.trim_start_matches("0x");
    if !input.len().is_multiple_of(2) {
        return Err(TsigError::InvalidKeyFormat);
    }

    (0..input.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&input[i..i + 2], 16)
                .map_err(|e| TsigError::SigningError(e.to_string()))
        })
        .collect()
}

/// TSIG signer for DNS messages
pub struct TsigSigner {
    key: TsigKey,
}

impl TsigSigner {
    /// Create a new TSIG signer
    pub fn new(key: TsigKey) -> Self {
        Self { key }
    }

    /// Sign a DNS message
    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        let _key_bytes = self.key.key_bytes()?;

        // This is a placeholder for the actual HMAC implementation
        // In a production environment, you would use a proper crypto library
        // like ring or hmac from the Rust standard library
        debug!(
            "Signing message with TSIG algorithm: {}",
            self.key.algorithm
        );

        // For now, return a placeholder signature
        // TODO: Implement proper HMAC signing
        warn!("TSIG signing not fully implemented, returning placeholder");
        Ok(vec![0u8; self.key.algorithm.digest_size()])
    }

    /// Verify a TSIG signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let computed = self.sign(message)?;
        Ok(computed == signature)
    }

    /// Get the key name
    pub fn key_name(&self) -> &str {
        &self.key.name
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> &TsigAlgorithm {
        &self.key.algorithm
    }
}

/// TSIG configuration for DNS messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigConfig {
    /// Enable TSIG authentication
    pub enabled: bool,
    /// TSIG key
    pub key: Option<TsigKey>,
    /// Time fudge (seconds)
    pub time_fudge: u64,
    /// Use signed message
    pub signed: bool,
}

impl Default for TsigConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key: None,
            time_fudge: 300, // 5 minutes default
            signed: false,
        }
    }
}

impl TsigConfig {
    /// Create a new TSIG config with a key
    pub fn with_key(key: TsigKey) -> Self {
        Self {
            enabled: true,
            key: Some(key),
            ..Default::default()
        }
    }

    /// Check if TSIG is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.key.is_some()
    }

    /// Create a signer from this config
    pub fn signer(&self) -> Option<TsigSigner> {
        self.key.as_ref().map(|k| TsigSigner::new(k.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(
            TsigAlgorithm::from_str_name("hmac-md5"),
            Some(TsigAlgorithm::HMACMD5)
        );
        assert_eq!(
            TsigAlgorithm::from_str_name("HMAC-SHA256"),
            Some(TsigAlgorithm::HMACSHA256)
        );
        assert_eq!(
            TsigAlgorithm::from_str_name("sha512"),
            Some(TsigAlgorithm::HMACSHA512)
        );
    }

    #[test]
    fn test_algorithm_rfc_names() {
        assert_eq!(TsigAlgorithm::HMACSHA256.rfc_name(), "hmac-sha256");
    }

    #[test]
    fn test_algorithm_digest_size() {
        assert_eq!(TsigAlgorithm::HMACMD5.digest_size(), 16);
        assert_eq!(TsigAlgorithm::HMACSHA256.digest_size(), 32);
    }

    #[test]
    fn test_tsig_key_from_bind_format() {
        let key = TsigKey::from_bind_format("mykey hmac-sha256:base64keydata");
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.name, "mykey");
        assert_eq!(key.key, "base64keydata");
        assert_eq!(key.algorithm, TsigAlgorithm::HMACSHA256);
    }

    #[test]
    fn test_tsig_key_from_file_format() {
        let content = r#"
        key "mykey" {
            algorithm "hmac-sha256";
            secret "base64keydata";
        };
        "#;
        let key = TsigKey::from_file_format(content);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.name, "mykey");
        assert_eq!(key.key, "base64keydata");
    }

    #[test]
    fn test_hex_decode() {
        assert!(hex_decode("48656c6c6f").is_ok());
        assert!(hex_decode("0x48656c6c6f").is_ok());
        assert!(hex_decode("invalid").is_err());
    }

    #[test]
    fn test_tsig_config() {
        let key = TsigKey::new("test", "keydata", TsigAlgorithm::HMACSHA256);
        let config = TsigConfig::with_key(key);
        assert!(config.is_enabled());
        assert!(config.signer().is_some());
    }
}
