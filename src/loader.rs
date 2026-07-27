use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use stellar_xdr::curr::{
    ContractExecutable, Hash, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};

use wasmparser::Parser;

use crate::limits::{LimitError, ResourcePolicy};
use crate::wasm_cache::WasmCache;

/// Holds raw WASM bytes alongside the validated file path.
#[derive(Debug)]
pub struct WasmModule {
    pub path: String,
    pub bytes: Vec<u8>,
    /// SHA-256 hash of the WASM bytecode, verified against on-chain data
    /// (only populated when fetched from RPC).
    pub verified_hash: Option<[u8; 32]>,
}

/// A dedicated error type for cryptographic or payload integrity failures.
///
/// Returned instead of a generic `anyhow::Error` so callers can inspect the
/// kind of integrity failure without parsing error messages.
#[derive(Debug)]
pub struct IntegrityError {
    pub kind: IntegrityErrorKind,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityErrorKind {
    /// The computed SHA-256 hash of fetched WASM bytecode does not match the
    /// hash stored in the contract instance entry.
    HashMismatch,
    /// The ledger key returned by the RPC does not match the requested key.
    KeyMismatch,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntegrityError[{:?}]: {}", self.kind, self.details)
    }
}

impl std::error::Error for IntegrityError {}

/// Reads a WASM file from disk, validates it is a valid WASM binary,
/// and returns a `WasmModule` ready for further analysis.
///
/// Uses [`ResourcePolicy::default`] for the WASM size ceiling. Prefer
/// [`load_wasm_with_policy`] when a caller-supplied policy is available so the
/// configured `max_wasm_size` is respected.
pub fn load_wasm(path: &Path) -> Result<WasmModule> {
    load_wasm_with_policy(path, &ResourcePolicy::default())
}

/// Like [`load_wasm`], but enforces the size ceiling from `policy`.
///
/// The file size is checked against `policy.max_wasm_size` via
/// `fs::metadata` **before** the file is opened for reading, so an
/// oversized input is rejected without allocating memory for it. The
/// error is a [`LimitError::WasmSizeExceeded`] so the CLI can assign it
/// exit code 2 (resource-limit violation) rather than 1 (broken upgrade).
pub fn load_wasm_with_policy(path: &Path, policy: &ResourcePolicy) -> Result<WasmModule> {
    if path.is_dir() {
        bail!("'{}' is a directory, not a WASM file", path.display());
    }

    // Check size via metadata before allocating.
    let file_size = std::fs::metadata(path)
        .with_context(|| format!("Failed to read file metadata: {}", path.display()))?
        .len() as usize;

    if file_size > policy.max_wasm_size {
        return Err(LimitError::WasmSizeExceeded {
            limit: policy.max_wasm_size,
            actual: file_size,
        }
        .into());
    }

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

    if bytes.len() < 4 || &bytes[0..4] != b"\0asm" {
        bail!(
            "'{}' does not appear to be a valid WASM binary (bad magic bytes)",
            path.display()
        );
    }

    validate_wasm_structure(&bytes)
        .with_context(|| format!("WASM validation failed for '{}'", path.display()))?;

    Ok(WasmModule {
        path: path.to_string_lossy().into_owned(),
        bytes,
        verified_hash: None,
    })
}

fn validate_wasm_structure(bytes: &[u8]) -> Result<()> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        payload.context("Malformed WASM payload encountered")?;
    }
    Ok(())
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract
/// ID, using the default [`ResourcePolicy`].
pub fn fetch_wasm_from_rpc(contract_id: &str, rpc_url: &str) -> Result<WasmModule> {
    fetch_wasm_from_rpc_with_policy(contract_id, rpc_url, &ResourcePolicy::default())
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract
/// ID, bounding XDR (de)serialization by `policy`.
///
/// This is a convenience wrapper around [`fetch_wasm_from_rpc_with_policy_and_cache`]
/// that does not use the local cache. Prefer the cache-aware variant in the CLI
/// so repeat fetches of the same code hash are served locally.
///
/// RPC responses are attacker-influenced (the contract ID is arbitrary), so the
/// `LedgerEntry` payloads are decoded under `policy.xdr_limits()`: an oversized or
/// deeply nested entry fails with a [`LimitError`] instead of exhausting memory or
/// the stack. The returned WASM is validated structurally; its embedded spec is
/// subject to the same policy when later decoded by the caller.
pub fn fetch_wasm_from_rpc_with_policy(
    contract_id: &str,
    rpc_url: &str,
    policy: &ResourcePolicy,
) -> Result<WasmModule> {
    fetch_wasm_from_rpc_with_policy_and_cache(contract_id, rpc_url, policy, None)
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract
/// ID, with an optional local disk cache.
///
/// # Cache behaviour
///
/// When `cache` is `Some`:
///
/// 1. The contract instance is fetched from RPC to resolve the **code hash**
///    (one network round-trip).
/// 2. The cache is checked for that hash. On a hit, the bytes are returned
///    immediately — the second round-trip (fetching the code entry) is skipped.
/// 3. On a miss, the code entry is fetched, integrity-verified, and then
///    written to the cache before returning.
///
/// When `cache` is `None` the function behaves exactly like
/// [`fetch_wasm_from_rpc_with_policy`]: two round-trips, no caching.
///
/// The cache is keyed by **code hash**, not contract ID, so an upgraded
/// contract (same ID, new code) always results in a cache miss and a fresh
/// fetch.
///
/// # Errors
///
/// Returns a [`LimitError`] when the input exceeds a configured limit, or an
/// [`IntegrityError`] if the fetched WASM hash does not match what the contract
/// instance declared. Cache write failures are non-fatal: a warning is printed
/// to stderr and the successfully-fetched WASM is returned regardless.
pub fn fetch_wasm_from_rpc_with_policy_and_cache(
    contract_id: &str,
    rpc_url: &str,
    policy: &ResourcePolicy,
    cache: Option<&WasmCache>,
) -> Result<WasmModule> {
    // 1. Parse contract_id using stellar_strkey
    let strkey = stellar_strkey::Strkey::from_string(contract_id)
        .map_err(|e| anyhow::anyhow!("Invalid contract ID '{}': {}", contract_id, e))?;

    let contract_bytes = match strkey {
        stellar_strkey::Strkey::Contract(c) => c.0,
        _ => bail!("Provided ID '{}' is not a valid contract ID", contract_id),
    };

    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    // 3. Serialize LedgerKey to Base64 with policy limits (for validation).
    let _key_b64 = ledger_key
        .to_xdr_base64(policy.xdr_limits())
        .map_err(|e| anyhow::anyhow!("Failed to serialize LedgerKey to base64: {}", e))?;

    // Derive the per-request timeout from the policy once, so both round-trips
    // use the same budget. Duration::ZERO signals "no timeout" to query_rpc.
    let rpc_timeout = std::time::Duration::from_secs(policy.rpc_timeout_secs);

    // 4. Query getLedgerEntries RPC — first round-trip: resolve the code hash.
    let response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [ledger_key
                .to_xdr_base64(Limits::none())
                .map_err(|e| anyhow::anyhow!("Failed to serialize LedgerKey: {}", e))?]
        }),
        rpc_timeout,
    )?;

    let entries = response["result"]["entries"]
        .as_array()
        .context("RPC response did not contain 'entries' array")?;

    let matched_entry = find_entry_by_key(entries, &ledger_key, "contract-instance lookup")?;

    let entry_xdr_b64 = matched_entry["xdr"]
        .as_str()
        .context("RPC response entry missing 'xdr' field")?;

    // 6. Deserialize LedgerEntry
    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, policy.xdr_limits()).map_err(|e| {
        LimitError::from_xdr_error(&e, policy)
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("Failed to deserialize LedgerEntry XDR: {}", e))
    })?;

    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => bail!("Unexpected ledger entry type returned for contract instance"),
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(inst) => inst,
        _ => bail!("Expected ScVal::ContractInstance in contract data"),
    };

    let wasm_hash = match instance.executable {
        ContractExecutable::Wasm(hash) => hash,
        ContractExecutable::StellarAsset => {
            bail!(
                "Contract '{}' is a built-in Stellar Asset contract and does not have WASM bytecode",
                contract_id
            );
        }
    };

    // ── Cache check ────────────────────────────────────────────────────────
    // The code hash is now known. Check the local cache before performing the
    // second network round-trip to fetch the code entry.
    if let Some(c) = cache {
        if let Some(cached_bytes) = c.get(&wasm_hash.0) {
            return Ok(WasmModule {
                path: format!("stellar://{}", contract_id),
                bytes: cached_bytes,
                verified_hash: Some(wasm_hash.0),
            });
        }
    }

    let code_ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: wasm_hash.clone(),
    });

    let _code_key_b64 = code_ledger_key
        .to_xdr_base64(policy.xdr_limits())
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to serialize ContractCode LedgerKey to base64: {}",
                e
            )
        })?;

    let code_response = query_rpc(
        rpc_url,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [code_ledger_key
                .to_xdr_base64(Limits::none())
                .map_err(|e| anyhow::anyhow!("Failed to serialize code key: {}", e))?]
        }),
        rpc_timeout,
    )?;

    let code_entries = code_response["result"]["entries"]
        .as_array()
        .context("RPC response for contract code did not contain 'entries' array")?;

    let matched_code_entry =
        find_entry_by_key(code_entries, &code_ledger_key, "contract-code lookup")?;

    let code_entry_xdr_b64 = matched_code_entry["xdr"]
        .as_str()
        .context("RPC response code entry missing 'xdr' field")?;

    let code_entry = LedgerEntry::from_xdr_base64(code_entry_xdr_b64, policy.xdr_limits())
        .map_err(|e| {
            LimitError::from_xdr_error(&e, policy)
                .map(anyhow::Error::from)
                .unwrap_or_else(|| {
                    anyhow::anyhow!("Failed to deserialize ContractCode LedgerEntry XDR: {}", e)
                })
        })?;

    let contract_code = match code_entry.data {
        LedgerEntryData::ContractCode(code) => code,
        _ => bail!("Unexpected ledger entry type returned for contract code"),
    };

    let wasm_bytes = contract_code.code.to_vec();

    // ── Size check (RPC path) ──────────────────────────────────────────────
    // Apply the same ceiling that `load_wasm_with_policy` enforces for disk
    // files. The check runs before the hash comparison so an oversized payload
    // is rejected without doing any cryptographic work on it.
    if wasm_bytes.len() > policy.max_wasm_size {
        return Err(LimitError::WasmSizeExceeded {
            limit: policy.max_wasm_size,
            actual: wasm_bytes.len(),
        }
        .into());
    }

    let computed_hash = Sha256::digest(&wasm_bytes);
    if computed_hash[..] != wasm_hash.0[..] {
        return Err(IntegrityError {
            kind: IntegrityErrorKind::HashMismatch,
            details: format!(
                "WASM hash mismatch for contract '{}': expected {}, computed {}",
                contract_id,
                hex::encode(wasm_hash.0),
                hex::encode(computed_hash),
            ),
        }
        .into());
    }

    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        bail!(
            "Fetched WASM for contract '{}' has invalid magic bytes",
            contract_id
        );
    }

    validate_wasm_structure(&wasm_bytes).with_context(|| {
        format!(
            "WASM validation failed for fetched contract '{}'",
            contract_id
        )
    })?;

    // ── Cache store ────────────────────────────────────────────────────────
    // Only reached after both the on-chain hash comparison and structural
    // validation have passed, so only verified WASM is ever persisted.
    if let Some(c) = cache {
        if let Err(e) = c.put(&wasm_hash.0, &wasm_bytes) {
            eprintln!("⚠️  Failed to write WASM to cache: {e:#}");
        }
    }

    Ok(WasmModule {
        path: format!("stellar://{}", contract_id),
        bytes: wasm_bytes,
        verified_hash: Some(wasm_hash.0),
    })
}

/// Find and return the single RPC ledger-entry whose `"key"` base64 matches
/// `expected_key`, within the given JSON `entries` array.
///
/// # Errors
///
/// Returns an error if:
/// - `entries` is empty ("zero entries returned")
/// - No entry key matches — returns [`IntegrityError::KeyMismatch`] because the RPC
///   returning a non-matching key is a ledger-integrity violation, not a "not found"
/// - More than one entry matches ("share the same ledger key")
/// - An entry is missing its `"key"` field ("missing 'key'")
/// - An entry is missing its `"xdr"` field ("missing 'xdr'")
fn find_entry_by_key<'a>(
    entries: &'a [serde_json::Value],
    expected_key: &LedgerKey,
    context_label: &str,
) -> Result<&'a serde_json::Value> {
    if entries.is_empty() {
        anyhow::bail!(
            "{}: RPC returned zero entries for the ledger key",
            context_label
        );
    }

    let expected_b64 = expected_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| anyhow::anyhow!("{}: failed to encode expected key: {}", context_label, e))?;

    let mut matches: Vec<&serde_json::Value> = Vec::new();
    for entry in entries {
        let entry_key_b64 = entry["key"]
            .as_str()
            .with_context(|| format!("{}: entry missing 'key' field", context_label))?;
        if entry_key_b64 == expected_b64 {
            // Also verify the xdr field is present.
            let _ = entry["xdr"]
                .as_str()
                .with_context(|| format!("{}: entry missing 'xdr' field", context_label))?;
            matches.push(entry);
        }
    }

    match matches.len() {
        0 => Err(IntegrityError {
            kind: IntegrityErrorKind::KeyMismatch,
            details: format!(
                "{}: no entry matches the requested ledger key",
                context_label
            ),
        }
        .into()),
        1 => Ok(matches[0]),
        _ => anyhow::bail!(
            "{}: {} entries share the same ledger key — response is ambiguous",
            context_label,
            matches.len()
        ),
    }
}

/// Extract the host portion of a `<scheme>://<rest>` URL remainder, dropping
/// any userinfo, port, path, query, or fragment.
fn url_host(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip `user:pass@` if present.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    authority.split(':').next().unwrap_or(authority)
}

/// Validates an RPC URL for basic shape and secure transport.
///
/// This runs *before* any network request is attempted, so a URL that is simply
/// wrong (no scheme, a typo like `htps://`, an empty host) is reported as a URL
/// problem rather than surfacing later as an opaque transport error.
///
/// - Rejects a URL with no scheme, an unsupported scheme, or no host.
/// - Rejects non-`https` URLs unless `allow_http_local` is `true`.
/// - When `allow_http_local` is `true`, only `localhost` and `127.0.0.1` are
///   accepted for `http://` URLs.
pub fn validate_rpc_url(rpc_url: &str, allow_http_local: bool) -> Result<()> {
    let trimmed = rpc_url.trim();
    if trimmed.is_empty() {
        bail!("Invalid RPC URL: the value is empty. Expected an 'https://' endpoint.");
    }

    // A URL with no `scheme://` at all is the most common mistake, and the one
    // that otherwise fails deepest inside the request machinery.
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        bail!(
            "Invalid RPC URL '{}': no scheme. Expected an 'https://' endpoint \
             (e.g. https://soroban-testnet.stellar.org).",
            rpc_url
        );
    };

    let host = url_host(rest);
    if host.is_empty() {
        bail!(
            "Invalid RPC URL '{}': no host after the scheme. Expected an \
             'https://<host>' endpoint.",
            rpc_url
        );
    }

    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" => {
            if !allow_http_local {
                bail!(
                    "Insecure RPC URL scheme 'http' for '{}'. \
                     Use 'https://' for secure transport, or pass \
                     --allow-http-local for local development only.",
                    rpc_url
                );
            }
            if host != "localhost" && host != "127.0.0.1" {
                bail!(
                    "HTTP RPC URL '{}' is not allowed. \
                     --allow-http-local only permits localhost or 127.0.0.1.",
                    rpc_url
                );
            }
            Ok(())
        }
        other => bail!(
            "Invalid RPC URL '{}': unsupported scheme '{}'. Use 'https://'.",
            rpc_url,
            other
        ),
    }
}

/// Helper to execute JSON-RPC request to Stellar RPC.
///
/// Disables redirect following to prevent HTTPS-to-HTTP downgrade attacks.
/// `timeout` is the overall per-request budget (covers connect, TLS, send,
/// and read). Pass `Duration::ZERO` to disable the timeout entirely.
fn query_rpc(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
    timeout: std::time::Duration,
) -> Result<serde_json::Value> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let mut builder = ureq::AgentBuilder::new().redirects(0);
    if !timeout.is_zero() {
        builder = builder.timeout(timeout);
    }
    let agent = builder.build();

    let response: serde_json::Value = agent
        .post(rpc_url)
        .send_json(payload)
        .map_err(|e| {
            // Surface a clear, actionable message when the request timed out.
            // ureq wraps transport errors (including timeout) as io::Error;
            // the display string contains "timed out" for both kinds.
            let msg = e.to_string();
            if msg.contains("timed out") || msg.contains("Timeout") || msg.contains("timeout") {
                anyhow::anyhow!(
                    "RPC request to '{}' timed out after {} second(s). \
                     The endpoint may be unresponsive. \
                     Use --rpc-timeout-secs to adjust the timeout.",
                    rpc_url,
                    timeout.as_secs(),
                )
            } else {
                anyhow::anyhow!("RPC request to '{}' failed: {}", rpc_url, e)
            }
        })?
        .into_json()
        .map_err(|e| anyhow::anyhow!("Failed to parse RPC response from '{}': {}", rpc_url, e))?;

    if let Some(err) = response.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown RPC error");
        let code = err["code"].as_i64().unwrap_or(0);
        bail!("RPC Error (code {}): {}", code, msg);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::LedgerKeyContractData;

    #[test]
    fn test_validate_rpc_url_accepts_https() {
        assert!(validate_rpc_url("https://soroban-testnet.stellar.org", false).is_ok());
        assert!(validate_rpc_url("https://localhost:8080", true).is_ok());
    }

    #[test]
    fn test_validate_rpc_url_rejects_http_without_flag() {
        let err = validate_rpc_url("http://evil-rpc.example.com", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("Insecure"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_remote_http_even_with_flag() {
        let err = validate_rpc_url("http://evil-rpc.example.com", true).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("only permits localhost"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_accepts_local_http_with_flag() {
        assert!(validate_rpc_url("http://localhost:8080", true).is_ok());
        assert!(validate_rpc_url("http://127.0.0.1:12345", true).is_ok());
    }

    #[test]
    fn test_validate_rpc_url_rejects_unsupported_scheme() {
        let err = validate_rpc_url("ftp://rpc.example.com", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("unsupported scheme"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_missing_scheme() {
        let err = validate_rpc_url("soroban-testnet.stellar.org", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("no scheme"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_typo_scheme() {
        let err = validate_rpc_url("htps://soroban-testnet.stellar.org", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("unsupported scheme 'htps'"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_empty_host() {
        let err = validate_rpc_url("https:///path", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("no host"), "got: {}", msg);
    }

    #[test]
    fn test_validate_rpc_url_rejects_empty_value() {
        let err = validate_rpc_url("   ", false).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("empty"), "got: {}", msg);
    }

    fn dummy_ledger_key() -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: stellar_xdr::curr::ContractDataDurability::Persistent,
        })
    }

    fn key_b64(key: &LedgerKey) -> String {
        key.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_entry(key_b64: &str, xdr_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "key": key_b64,
            "xdr": xdr_b64,
        })
    }

    #[test]
    fn test_find_entry_by_key_matches_correctly() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![make_entry(&b64, "dummy")];

        let result = find_entry_by_key(&entries, &key, "test");
        assert!(result.is_ok(), "should find matching entry: {:?}", result);
    }

    #[test]
    fn test_find_entry_by_key_rejects_empty_entries() {
        let key = dummy_ledger_key();
        let entries = vec![];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("zero entries"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_mismatched_key() {
        let key = dummy_ledger_key();
        let other_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash([1u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: stellar_xdr::curr::ContractDataDurability::Persistent,
        });
        let other_b64 = key_b64(&other_key);
        let entries = vec![make_entry(&other_b64, "dummy")];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("no entry matches"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_duplicate_matches() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![make_entry(&b64, "first"), make_entry(&b64, "second")];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("share the same ledger key"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_missing_key_field() {
        let key = dummy_ledger_key();
        let entries = vec![serde_json::json!({"xdr": "dummy"})];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("missing 'key'"), "got: {}", msg);
    }

    #[test]
    fn test_find_entry_by_key_rejects_missing_xdr_field() {
        let key = dummy_ledger_key();
        let b64 = key_b64(&key);
        let entries = vec![serde_json::json!({"key": b64})];

        let err = find_entry_by_key(&entries, &key, "test").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("missing 'xdr'") || msg.contains("missing 'key'"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_load_wasm_rejects_directory() {
        let dir = std::env::temp_dir().join("soroban-upgrade-safeguard-test-dir");
        std::fs::create_dir_all(&dir).unwrap();

        let err = load_wasm(&dir).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("is a directory"), "got: {}", msg);

        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn test_load_wasm_reports_missing_file() {
        let path = std::env::temp_dir().join("soroban-upgrade-safeguard-does-not-exist.wasm");
        let _ = std::fs::remove_file(&path);

        let err = load_wasm(&path).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains(&path.display().to_string()), "got: {}", msg);
    }

    #[test]
    fn test_load_wasm_rejects_oversized_file() {
        use crate::limits::{LimitError, ResourcePolicy};

        // Write a tiny but valid-looking WASM file (magic + version).
        let path = std::env::temp_dir().join("soroban-upgrade-safeguard-oversized.wasm");
        let wasm_magic = b"\x00asm\x01\x00\x00\x00";
        std::fs::write(&path, wasm_magic).unwrap();

        // Set a limit smaller than the file so the check fires.
        let policy = ResourcePolicy {
            max_wasm_size: 4, // file is 8 bytes — smaller than magic + version
            ..ResourcePolicy::default()
        };

        let err = load_wasm_with_policy(&path, &policy).unwrap_err();

        // Must surface as a LimitError, not a generic anyhow error, so the
        // CLI can assign it exit code 2.
        let limit_err =
            crate::limits::find_limit_error(&err).expect("expected a LimitError in the chain");
        match limit_err {
            LimitError::WasmSizeExceeded { limit, actual } => {
                assert_eq!(*limit, 4);
                assert_eq!(*actual, 8);
            }
            other => panic!("expected WasmSizeExceeded, got {other:?}"),
        }

        // The error message must name both the limit and the actual size.
        let msg = err.to_string();
        assert!(
            msg.contains('4') || msg.contains("4"),
            "limit missing: {msg}"
        );
        assert!(
            msg.contains('8') || msg.contains("8"),
            "actual missing: {msg}"
        );
        assert!(msg.contains("max_wasm_size"), "hint missing: {msg}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wasm_module_default_verified_hash_none() {
        let module = WasmModule {
            path: "/tmp/test.wasm".into(),
            bytes: vec![0x00, 0x61, 0x73, 0x6d],
            verified_hash: None,
        };
        assert!(module.verified_hash.is_none());
    }
}
