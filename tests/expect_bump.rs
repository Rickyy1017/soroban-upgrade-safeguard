//! Integration tests for the `--expect-bump` release gate.
//!
//! The tool already computes a recommended SemVer bump. `--expect-bump` turns
//! that into an assertion: a release process that intends to cut a minor should
//! fail if the analysis says the changes require a major, because that mismatch
//! is exactly how a breaking change ships under a non-breaking version number.
//!
//! Fixture bumps, from the existing JSON-output tests:
//!
//! | Pair      | Recommended | Safe (non-strict) |
//! | :-------- | :---------- | :---------------- |
//! | v1 → v1   | `patch`     | yes               |
//! | v1 → v3   | `minor`     | yes               |
//! | v1 → v2   | `major`     | no                |

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Run a comparison and return `(exit_code, stderr)`.
fn run(old: &str, new: &str, extra: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(extra)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stderr)
}

// ---------------------------------------------------------------------------
// Falling short: the recommendation is more severe than what was declared
// ---------------------------------------------------------------------------

#[test]
fn expect_bump_falling_short_fails_and_names_both_levels() {
    // v1 → v3 recommends `minor`, and passes on its own. Declaring `patch`
    // must fail the run purely on the bump gate.
    let (code, stderr) = run("v1.wasm", "v3.wasm", &["--expect-bump", "patch"]);

    assert_eq!(code, 1, "a bump that falls short must exit 1");
    assert!(
        stderr.contains("minor") && stderr.contains("patch"),
        "the message must name both the required and the declared bump, got: {stderr}"
    );
    assert!(
        stderr.contains("bump gate failed"),
        "the failure must identify itself as the bump gate, got: {stderr}"
    );
}

#[test]
fn expect_bump_minor_against_major_recommendation_fails() {
    // v1 → v2 requires a major. Declaring `minor` is the exact mismatch this
    // gate exists to catch.
    let (code, stderr) = run("v1.wasm", "v2.wasm", &["--expect-bump", "minor"]);

    assert_eq!(code, 1);
    assert!(
        stderr.contains("major") && stderr.contains("minor"),
        "the message must name both levels, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Meeting or exceeding the recommendation passes
// ---------------------------------------------------------------------------

#[test]
fn expect_bump_matching_recommendation_passes() {
    let (code, stderr) = run("v1.wasm", "v3.wasm", &["--expect-bump", "minor"]);

    assert_eq!(code, 0, "a matching bump must not fail the run");
    assert!(
        !stderr.contains("bump gate failed"),
        "no gate message should be printed on a match, got: {stderr}"
    );
}

#[test]
fn expect_bump_exceeding_recommendation_passes() {
    // Declaring a larger bump than required is always allowed — over-bumping
    // is a release decision, not a safety problem.
    let (code, stderr) = run("v1.wasm", "v3.wasm", &["--expect-bump", "major"]);

    assert_eq!(code, 0, "an exceeding bump must not fail the run");
    assert!(!stderr.contains("bump gate failed"), "got: {stderr}");

    let (code, _) = run("v1.wasm", "v1.wasm", &["--expect-bump", "major"]);
    assert_eq!(code, 0, "patch recommendation under a major plan passes");
}

#[test]
fn without_expect_bump_the_exit_code_is_unchanged() {
    let (code, _) = run("v1.wasm", "v3.wasm", &[]);
    assert_eq!(code, 0, "the gate must be inert when not requested");
}

// ---------------------------------------------------------------------------
// Interaction with --strict and the existing exit codes
// ---------------------------------------------------------------------------

#[test]
fn expect_bump_is_independent_of_strict() {
    // --strict fails v1 → v3 on its warnings. The bump gate is satisfied, so
    // the failure must not be attributed to it.
    let (code, stderr) = run(
        "v1.wasm",
        "v3.wasm",
        &["--strict", "--expect-bump", "minor"],
    );
    assert_eq!(code, 1, "--strict still fails on warnings");
    assert!(
        !stderr.contains("bump gate failed"),
        "a satisfied gate must stay silent under --strict, got: {stderr}"
    );

    // And --strict does not make a satisfied gate stricter: `major` still
    // covers a `minor` recommendation.
    let (code, stderr) = run(
        "v1.wasm",
        "v3.wasm",
        &["--strict", "--expect-bump", "major"],
    );
    assert_eq!(code, 1, "--strict fails on warnings regardless of the gate");
    assert!(!stderr.contains("bump gate failed"), "got: {stderr}");
}

#[test]
fn expect_bump_reports_alongside_a_breaking_verdict() {
    // A run can fail for two reasons at once. Both must be visible: a pipeline
    // should see every reason it failed, not just the first one.
    let (code, stderr) = run("v1.wasm", "v2.wasm", &["--expect-bump", "patch"]);

    assert_eq!(code, 1);
    assert!(
        stderr.contains("bump gate failed"),
        "the gate message must still be printed for an unsafe run, got: {stderr}"
    );
}

#[test]
fn resource_limit_exit_code_takes_precedence_over_the_bump_gate() {
    // Exit 2 means "the input was rejected", which a pipeline must be able to
    // tell apart from "the gate failed".
    let (code, _) = run(
        "v1.wasm",
        "v2.wasm",
        &["--max-wasm-size", "1", "--expect-bump", "patch"],
    );
    assert_eq!(code, 2, "a limit violation must still exit 2");
}

// ---------------------------------------------------------------------------
// Batch mode gates on the most severe bump across all pairs
// ---------------------------------------------------------------------------

#[test]
fn expect_bump_in_batch_mode_uses_the_most_severe_pair() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("expect_bump_batch");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let manifest = dir.join("pairs.toml");
    std::fs::write(
        &manifest,
        format!(
            "[[pairs]]\nold = \"{}\"\nnew = \"{}\"\nname = \"clean\"\n\n\
             [[pairs]]\nold = \"{}\"\nnew = \"{}\"\nname = \"warned\"\n",
            wasm("v1.wasm").display(),
            wasm("v1.wasm").display(),
            wasm("v1.wasm").display(),
            wasm("v3.wasm").display(),
        ),
    )
    .expect("failed to write manifest");

    let run_batch = |expect: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
            .args(["--manifest", manifest.to_str().unwrap()])
            .args(["--expect-bump", expect])
            .output()
            .expect("failed to run binary");
        let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
        (output.status.code().expect("no exit code"), stderr)
    };

    // One pair recommends `patch`, the other `minor`. The batch must gate on
    // `minor` — the contracts ship together.
    let (code, stderr) = run_batch("patch");
    assert_eq!(code, 1, "the batch bump must be the most severe pair's");
    assert!(
        stderr.contains("minor") && stderr.contains("patch"),
        "the message must name both levels, got: {stderr}"
    );

    let (code, _) = run_batch("minor");
    assert_eq!(code, 0, "a bump covering every pair must pass");
}
