//! Local disk cache for RPC-fetched WASM bytecode.
//!
//! A deployed contract's WASM is immutable for a given code hash: once a hash
//! is on-chain its bytes never change. That makes code-hash–keyed caching safe
//! and highly effective — the same bytecode is never fetched more than once per
//! machine.
//!
//! # Cache layout
//!
//! Files are stored under the platform's conventional user cache directory:
//!
//! | Platform | Path |
//! |----------|------|
//! | Linux    | `$XDG_CACHE_HOME/soroban-upgrade-safeguard/wasm/` (falls back to `~/.cache/…`) |
//! | macOS    | `~/Library/Caches/soroban-upgrade-safeguard/wasm/` |
//! | Windows  | `%LOCALAPPDATA%\soroban-upgrade-safeguard\wasm\` |
//!
//! Each cached file is named `<hex-code-hash>.wasm`, where the hex string is
//! the 64-character lower-case SHA-256 of the WASM bytecode as recorded
//! on-chain.
//!
//! # Bypassing and clearing the cache
//!
//! Pass `--no-cache` on the CLI, or set `SAFEGUARD_NO_CACHE=1` in the
//! environment, to skip both reads *and* writes for a single run. This is
//! useful when you suspect a corrupted cache entry or want to force a fresh
//! network fetch.
//!
//! To clear the cache entirely, delete the directory shown above, or run:
//!
//! ```text
//! # Linux / macOS
//! rm -rf ~/.cache/soroban-upgrade-safeguard/wasm
//!
//! # Windows (PowerShell)
//! Remove-Item -Recurse -Force "$env:LOCALAPPDATA\soroban-upgrade-safeguard\wasm"
//! ```
//!
//! # Integrity
//!
//! Entries are only written *after* the integrity check in
//! [`crate::loader::fetch_wasm_from_rpc_with_policy`] passes, so every cached
//! file has already been verified against its on-chain hash. On a cache hit the
//! file name *is* the expected hash, so the loader re-verifies the bytes before
//! returning them (see [`WasmCache::get`]).

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A handle to the on-disk WASM cache.
///
/// Create one with [`WasmCache::open`] (uses the platform default location) or
/// [`WasmCache::with_dir`] (useful in tests). Pass it to
/// [`crate::loader::fetch_wasm_from_rpc_with_policy`] via the `cache` parameter.
#[derive(Debug, Clone)]
pub struct WasmCache {
    /// Root directory that holds all `<hex>.wasm` files.
    dir: PathBuf,
}

impl WasmCache {
    /// Open (creating if necessary) the cache at the platform-default location.
    ///
    /// Returns `Ok(None)` if the user's cache base directory cannot be
    /// determined (rare on supported platforms) so the caller can degrade
    /// gracefully instead of hard-failing.
    pub fn open() -> Result<Option<Self>> {
        let base = match dirs::cache_dir() {
            Some(d) => d,
            None => return Ok(None),
        };
        let dir = base.join("soroban-upgrade-safeguard").join("wasm");
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("Failed to create WASM cache directory '{}'", dir.display())
        })?;
        Ok(Some(Self { dir }))
    }

    /// Open (creating if necessary) the cache at an explicit directory.
    ///
    /// Primarily for tests: pass a `TempDir` path to get an isolated cache.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("Failed to create WASM cache directory '{}'", dir.display())
        })?;
        Ok(Self { dir })
    }

    /// Return the directory this cache writes to.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Look up `code_hash` (32-byte raw SHA-256) in the cache.
    ///
    /// Returns `Ok(Some(bytes))` on a verified hit, `Ok(None)` on a miss or a
    /// corrupt entry (a warning is printed to stderr in that case so the caller
    /// still proceeds with a fresh network fetch).
    ///
    /// # Integrity re-verification
    ///
    /// Even though entries are only stored after passing the on-chain integrity
    /// check, they are re-verified on every read. This guards against accidental
    /// or malicious modification of the cache directory after the initial write.
    pub fn get(&self, code_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let path = self.entry_path(code_hash);
        let bytes = std::fs::read(&path).ok()?;

        // Re-verify: the file name is the expected hash.
        let computed: [u8; 32] = Sha256::digest(&bytes).into();
        if computed != *code_hash {
            eprintln!(
                "⚠️  WASM cache entry '{}' failed integrity check — discarding and refetching.",
                path.display()
            );
            // Best-effort removal; ignore errors.
            let _ = std::fs::remove_file(&path);
            return None;
        }

        Some(bytes)
    }

    /// Store `wasm_bytes` in the cache, keyed by `code_hash`.
    ///
    /// The write is atomic on platforms that support `rename` (Linux, macOS,
    /// most Windows configurations): bytes are written to a sibling `.tmp` file
    /// first, then renamed into place, so a concurrent reader never sees a
    /// partial file.
    ///
    /// Errors are non-fatal: a failed cache write only means the next run will
    /// re-fetch. The error is returned so the caller can log it if desired.
    pub fn put(&self, code_hash: &[u8; 32], wasm_bytes: &[u8]) -> Result<()> {
        let final_path = self.entry_path(code_hash);

        // Write to a temp file in the same directory so the rename is atomic.
        let tmp_path = final_path.with_extension("wasm.tmp");
        std::fs::write(&tmp_path, wasm_bytes).with_context(|| {
            format!(
                "Failed to write WASM cache temp file '{}'",
                tmp_path.display()
            )
        })?;

        std::fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "Failed to rename cache temp file '{}' to '{}'",
                tmp_path.display(),
                final_path.display()
            )
        })?;

        Ok(())
    }

    /// Return the canonical path for a cache entry.
    fn entry_path(&self, code_hash: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.wasm", hex::encode(code_hash)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Build a minimal valid-looking WASM byte vector with a recognisable body.
    fn fake_wasm(seed: u8) -> Vec<u8> {
        // Real WASM magic + version, then a custom body byte to differentiate instances.
        let mut v = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        v.push(seed);
        v
    }

    fn hash_of(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    // ── cache miss ──────────────────────────────────────────────────────────

    #[test]
    fn get_returns_none_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();
        let hash = hash_of(b"nonexistent");
        assert!(cache.get(&hash).is_none());
    }

    // ── round-trip ──────────────────────────────────────────────────────────

    #[test]
    fn put_then_get_returns_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();

        let wasm = fake_wasm(0xAA);
        let hash = hash_of(&wasm);

        cache.put(&hash, &wasm).unwrap();

        let retrieved = cache.get(&hash).expect("should be a cache hit");
        assert_eq!(retrieved, wasm);
    }

    // ── keyed by hash, not contract id ──────────────────────────────────────

    #[test]
    fn two_different_hashes_stored_independently() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();

        let wasm_a = fake_wasm(0x01);
        let wasm_b = fake_wasm(0x02);
        let hash_a = hash_of(&wasm_a);
        let hash_b = hash_of(&wasm_b);

        // Hashes must differ for the test to be meaningful.
        assert_ne!(hash_a, hash_b);

        cache.put(&hash_a, &wasm_a).unwrap();
        cache.put(&hash_b, &wasm_b).unwrap();

        assert_eq!(cache.get(&hash_a).unwrap(), wasm_a);
        assert_eq!(cache.get(&hash_b).unwrap(), wasm_b);
    }

    // ── upgraded contract is refetched ──────────────────────────────────────
    //
    // Simulates: same contract id, but the code was upgraded on-chain so the
    // new code hash is different. The old entry stays and the new hash misses.

    #[test]
    fn upgraded_hash_produces_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();

        let old_wasm = fake_wasm(0x10);
        let new_wasm = fake_wasm(0x20); // "upgraded" bytecode
        let old_hash = hash_of(&old_wasm);
        let new_hash = hash_of(&new_wasm);

        // Only the old version is cached.
        cache.put(&old_hash, &old_wasm).unwrap();

        // The new hash must not be satisfied by the old entry.
        assert!(cache.get(&new_hash).is_none());
        // The old entry is still readable.
        assert_eq!(cache.get(&old_hash).unwrap(), old_wasm);
    }

    // ── integrity re-verification ────────────────────────────────────────────

    #[test]
    fn tampered_cache_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();

        let wasm = fake_wasm(0x42);
        let hash = hash_of(&wasm);

        cache.put(&hash, &wasm).unwrap();

        // Overwrite the cache file with garbage.
        let path = cache.entry_path(&hash);
        std::fs::write(&path, b"corrupted data").unwrap();

        // get() must detect the mismatch and return None.
        assert!(cache.get(&hash).is_none());

        // The corrupt file should have been removed.
        assert!(!path.exists(), "corrupt cache entry should be removed");
    }

    // ── idempotent put ───────────────────────────────────────────────────────

    #[test]
    fn putting_same_bytes_twice_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();

        let wasm = fake_wasm(0xBB);
        let hash = hash_of(&wasm);

        cache.put(&hash, &wasm).unwrap();
        cache.put(&hash, &wasm).unwrap(); // second write must not fail

        assert_eq!(cache.get(&hash).unwrap(), wasm);
    }

    // ── entry_path naming ───────────────────────────────────────────────────

    #[test]
    fn entry_path_is_hex_hash_dot_wasm() {
        let dir = tempfile::tempdir().unwrap();
        let cache = WasmCache::with_dir(dir.path()).unwrap();
        let hash = [0xdeu8; 32];
        let path = cache.entry_path(&hash);
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()).unwrap(),
            format!("{}.wasm", hex::encode(hash))
        );
    }
}
