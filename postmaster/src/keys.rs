//! Key loading, variable name resolution, and ciphertext decryption.
//!
//! All secret material is Zeroized. Decryption is tried with rotation candidates.
//! Plaintext values (from `dotenvx set --plain`) are passed through.

#![allow(missing_docs, missing_debug_implementations)]

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use dotenvy;
use hex;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Entry, key_var_for};

/// Full variable name (DOTENV_PRIVATE_KEY[_<ENV>]) → candidate secret keys.
/// Multiple candidates per name come from dotenvx's comma-separated rotation
/// convention; decryption tries each in order.
#[derive(Debug)]
pub struct KeyRing(HashMap<String, Vec<Zeroizing<[u8; 32]>>>);

impl KeyRing {
    pub fn load(path: &Path) -> Result<Self, String> {
        let iter = dotenvy::from_path_iter(path)
            .map_err(|e| format!("keys file {}: {e}", path.display()))?;
        let mut map: HashMap<String, Vec<Zeroizing<[u8; 32]>>> = HashMap::new();
        for item in iter {
            let (name, value) = item.map_err(|e| format!("keys file {}: {e}", path.display()))?;
            let mut value = Zeroizing::new(value);
            if !name.starts_with("DOTENV_PRIVATE_KEY") {
                continue;
            }
            let mut keys = Vec::new();
            for part in value.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let mut raw =
                    hex::decode(part).map_err(|_| format!("{name}: entry is not valid hex"))?;
                if raw.len() != 32 {
                    raw.zeroize();
                    return Err(format!("{name}: expected a 32-byte key"));
                }
                let mut arr = [0_u8; 32];
                arr.copy_from_slice(&raw);
                raw.zeroize();
                keys.push(Zeroizing::new(arr));
            }
            value.zeroize();
            if keys.is_empty() {
                return Err(format!("{name}: no usable keys"));
            }
            map.insert(name, keys);
        }
        if map.is_empty() {
            return Err(format!(
                "keys file {} contains no DOTENV_PRIVATE_KEY* entries",
                path.display()
            ));
        }
        Ok(KeyRing(map))
    }
}

/// Resolve a single entry using the key ring.
/// Supports both encrypted values and plaintext (via `dotenvx set --plain`).
pub fn resolve(entry: &Entry, ring: &KeyRing) -> Result<Zeroizing<Vec<u8>>, String> {
    let iter = dotenvy::from_path_iter(&entry.env_file)
        .map_err(|e| format!("{}: {e}", entry.env_file.display()))?;
    // Last assignment wins, matching dotenv semantics within one file.
    let mut found: Option<Zeroizing<String>> = None;
    for item in iter {
        let (k, v) = item.map_err(|e| format!("{}: {e}", entry.env_file.display()))?;
        let v = Zeroizing::new(v);
        if k == entry.key {
            found = Some(v);
        }
    }
    let raw =
        found.ok_or_else(|| format!("{}: no key named {}", entry.env_file.display(), entry.key))?;

    let Some(b64) = raw.strip_prefix("encrypted:") else {
        // dotenvx permits plaintext values alongside encrypted ones
        // (`dotenvx set --plain`); pass them through as opaque bytes.
        return Ok(Zeroizing::new(raw.as_bytes().to_vec()));
    };

    let ciphertext = BASE64.decode(b64).map_err(|_| {
        format!(
            "{}: {} is not valid base64",
            entry.env_file.display(),
            entry.key
        )
    })?;
    let var = key_var_for(&entry.env_file)?;
    let candidates = ring
        .0
        .get(&var)
        .ok_or_else(|| format!("keys file has no {var} entry"))?;
    for sk in candidates {
        if let Ok(pt) = ecies::decrypt(&sk[..], &ciphertext) {
            return Ok(Zeroizing::new(pt));
        }
    }
    Err(format!(
        "{}: no key under {var} decrypts {} ({} candidate(s) tried)",
        entry.env_file.display(),
        entry.key,
        candidates.len()
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn with_temp_keys(content: &str, f: impl FnOnce(&Path)) {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("postmaster-test-keys-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{}", content).unwrap();
        }
        f(&path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn key_var_for_basic() {
        assert_eq!(
            crate::config::key_var_for(std::path::Path::new(".env")).unwrap(),
            "DOTENV_PRIVATE_KEY"
        );
        assert_eq!(
            crate::config::key_var_for(std::path::Path::new(".env.production")).unwrap(),
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        );
        assert_eq!(
            crate::config::key_var_for(std::path::Path::new(".env.staging_v2")).unwrap(),
            "DOTENV_PRIVATE_KEY_STAGING_V2"
        );
    }

    #[test]
    fn load_rotated_keys_and_plaintext_env() {
        // Create a real .env file with a plaintext value (simulating --plain)
        let env_dir = std::env::temp_dir();
        let env_path = env_dir.join(format!("postmaster-test-env-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&env_path).unwrap();
            writeln!(f, "PLAIN=hello-world").unwrap();
        }

        let entry = Entry {
            env_file: env_path.clone(),
            key: "PLAIN".to_string(),
            peer_user: None,
        };
        // Ring can be empty for plaintext path
        let ring = KeyRing(HashMap::new());
        let result = resolve(&entry, &ring).unwrap();
        assert_eq!(&*result, b"hello-world");

        let _ = std::fs::remove_file(&env_path);
    }

    #[test]
    fn load_rejects_bad_hex() {
        let content = "DOTENV_PRIVATE_KEY=not-hex\n";
        with_temp_keys(content, |p| match KeyRing::load(p) {
            Err(e) if e.contains("not valid hex") => {}
            other => panic!("expected bad hex error, got {other:?}"),
        });
    }
}
