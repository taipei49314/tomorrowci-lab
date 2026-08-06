//! Canonical SHA-256 string format: `sha256:` + 64 lowercase hex digits only.

use tomorrowci_core::{sha256_bytes, Result, TcError};

/// Require exact canonical form `sha256:<64 lowercase hex>`.
/// Rejects uppercase prefix/hex, bare hex, and double prefixes.
pub fn normalize_hash(s: &str) -> Result<String> {
    let t = s.trim();
    if t.contains("sha256:sha256:") || t.matches("sha256:").count() > 1 {
        return Err(TcError::InvalidState(format!(
            "double-prefixed or malformed hash: {s}"
        )));
    }
    let Some(hex) = t.strip_prefix("sha256:") else {
        return Err(TcError::InvalidState(format!(
            "non-canonical hash (require sha256:<64 lowercase hex>): {s}"
        )));
    };
    // Lowercase hex only — uppercase A-F is non-canonical.
    if hex.len() != 64 || !hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(TcError::InvalidState(format!(
            "malformed sha256 hash (expected 64 lowercase hex): {s}"
        )));
    }
    Ok(format!("sha256:{hex}"))
}

pub fn hash_bytes(data: &[u8]) -> String {
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
    fn rejects_uppercase_prefix_and_hex() {
        assert!(normalize_hash(
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err());
        assert!(normalize_hash(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
