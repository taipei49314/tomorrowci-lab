//! Canonical SHA-256 string format: `sha256:` + 64 lowercase hex digits.

use tomorrowci_core::{sha256_bytes, Result, TcError};

/// Normalize any hash string to `sha256:<64hex>` or error.
pub fn normalize_hash(s: &str) -> Result<String> {
    let t = s.trim();
    let hex = t
        .strip_prefix("sha256:")
        .or_else(|| t.strip_prefix("SHA256:"))
        .unwrap_or(t);
    // strip accidental double prefix
    let hex = hex.strip_prefix("sha256:").unwrap_or(hex);
    let hex = hex.to_ascii_lowercase();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TcError::InvalidState(format!(
            "malformed sha256 hash (expected 64 hex): {s}"
        )));
    }
    if s.contains("sha256:sha256:") || s.matches("sha256:").count() > 1 {
        return Err(TcError::InvalidState(format!(
            "double-prefixed or malformed hash: {s}"
        )));
    }
    Ok(format!("sha256:{hex}"))
}

pub fn hash_bytes(data: &[u8]) -> String {
    // sha256_bytes already returns sha256:<hex>
    let h = sha256_bytes(data);
    normalize_hash(&h).unwrap_or(h)
}

pub fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(hash_bytes(&data))
}

pub fn hashes_equal(a: &str, b: &str) -> bool {
    match (normalize_hash(a), normalize_hash(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_double_prefix() {
        assert!(normalize_hash(
            "sha256:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err());
    }

    #[test]
    fn accepts_canonical() {
        let h = hash_bytes(b"hello");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
        assert_eq!(normalize_hash(&h).unwrap(), h);
    }
}
