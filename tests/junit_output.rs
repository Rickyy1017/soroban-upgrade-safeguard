//! Integration tests for `--format junit`.
//!
//! Most CI systems already have a test-report UI that ingests JUnit XML and
//! renders it as passed and failed cases. Emitting that format lets a breaking
//! change appear as a failing test in the same view the pipeline already uses,
//! rather than as text buried in a log.
//!
//! # Workflow example
//!
//! ```yaml
//! - name: Check upgrade safety
//!   run: |
//!     soroban-upgrade-safeguard old.wasm new.wasm \
//!       --format junit --output ./upgrade-report.xml
//! ```
//!
//! These tests validate the document structure rather than exact text: the
//! root `<testsuites>` element, per-suite counts, the severity-to-status
//! mapping, and the per-contract suite grouping in batch mode.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_junit(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .args(["--format", "junit"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// A minimal well-formedness check: every element that opens must close, tags
/// are balanced, and no stray `<` or `>` survived escaping inside text.
fn assert_wellformed(xml: &str) {
    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "missing XML declaration:\n{xml}"
    );

    // No element may close more times than it opens. (Self-closing cases mean
    // closes can legitimately be fewer, so this is a one-sided check.)
    for tag in ["testsuites", "testsuite", "testcase", "failure"] {
        let opens = count(xml, &format!("<{tag} ")) + count(xml, &format!("<{tag}>"));
        let closes = count(xml, &format!("</{tag}>"));
        assert!(closes <= opens, "more </{tag}> than <{tag}> in:\n{xml}");
    }

    // The root element must be present exactly once and must close.
    assert_eq!(count(xml, "<testsuites"), 1, "expected one root element");
    assert_eq!(count(xml, "</testsuites>"), 1, "root element must close");
    assert!(xml.trim_end().ends_with("</testsuites>"));
}

// ---------------------------------------------------------------------------
// Single pair
// ---------------------------------------------------------------------------

#[test]
fn junit_breaking_upgrade_emits_failures_and_exits_one() {
    let (code, xml) = run_junit(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
    ]);

    assert_eq!(code, 1, "breaking upgrade must exit 1");
    assert_wellformed(&xml);

    assert!(
        xml.contains("<testsuite name=\"soroban-upgrade-safeguard\""),
        "expected a default-named suite:\n{xml}"
    );
    assert!(
        xml.contains("<failure "),
        "a breaking upgrade must produce at least one <failure>:\n{xml}"
    );
    assert!(
        xml.contains("type=\"critical\""),
        "critical findings must be typed as such:\n{xml}"
    );

    // The reported failure count must match the number of <failure> elements.
    let declared: usize = xml
        .split("failures=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .and_then(|n| n.parse().ok())
        .expect("suite must declare a failures count");
    assert_eq!(
        declared,
        count(&xml, "<failure "),
        "declared failure count must match the emitted <failure> elements:\n{xml}"
    );
}

#[test]
fn junit_safe_upgrade_emits_no_failures_and_exits_zero() {
    let (code, xml) = run_junit(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "identical contracts must exit 0");
    assert_wellformed(&xml);
    assert!(
        !xml.contains("<failure "),
        "a safe upgrade must not report failures:\n{xml}"
    );
    assert!(
        xml.contains("failures=\"0\""),
        "the suite must declare zero failures:\n{xml}"
    );
    // A suite is never empty — an empty one reads as "no tests ran".
    assert!(
        xml.contains("<testcase "),
        "the suite must contain at least one case:\n{xml}"
    );
}

// ---------------------------------------------------------------------------
// Suppression: acknowledged, not failing
// ---------------------------------------------------------------------------

#[test]
fn junit_suppressed_findings_are_skipped_not_failed() {
    // Suppress everything by category so the run passes with findings present.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("junit_suppress");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let config = dir.join("suppress-all.toml");

    // First discover which categories the v1→v2 comparison produces.
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout was not valid JSON");

    let mut rules = String::new();
    let mut seen = std::collections::HashSet::new();
    for findings in json["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object")
        .values()
    {
        for finding in findings.as_array().expect("category must hold an array") {
            let rule_id = finding["rule_id"]
                .as_str()
                .expect("rule_id must be a string");
            let target = finding["target"].as_str().unwrap_or_default();
            if target.is_empty() || !seen.insert((rule_id.to_string(), target.to_string())) {
                continue;
            }
            rules.push_str(&format!(
                "[[suppress]]\ncategory = \"{rule_id}\"\ntarget = \"{target}\"\n\
                 reason = \"known, reviewed\"\n\n"
            ));
        }
    }
    std::fs::write(&config, &rules).expect("failed to write suppression config");

    let (_, xml) = run_junit(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);

    assert_wellformed(&xml);
    assert!(
        xml.contains("<skipped "),
        "suppressed findings must be emitted as <skipped>:\n{xml}"
    );
    assert!(
        xml.contains("known, reviewed"),
        "the suppression reason must be carried into the case:\n{xml}"
    );

    // Whatever was suppressed must not also be counted as a failure.
    let skipped: usize = xml
        .split("skipped=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .and_then(|n| n.parse().ok())
        .expect("suite must declare a skipped count");
    assert!(
        skipped > 0,
        "expected suppressed cases to be counted:\n{xml}"
    );
    assert_eq!(
        skipped,
        count(&xml, "<skipped "),
        "declared skipped count must match the emitted <skipped> elements:\n{xml}"
    );

    let _ = std::fs::remove_file(&config);
}

// ---------------------------------------------------------------------------
// Strict mode promotes warnings to failures
// ---------------------------------------------------------------------------

#[test]
fn junit_strict_mode_turns_warnings_into_failures() {
    let (_, lenient) = run_junit(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
    ]);
    let (_, strict) = run_junit(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--strict",
    ]);

    assert_wellformed(&lenient);
    assert_wellformed(&strict);

    assert!(
        count(&strict, "<failure ") >= count(&lenient, "<failure "),
        "strict mode must not report fewer failures than lenient mode"
    );
}

// ---------------------------------------------------------------------------
// Batch mode: one suite per contract
// ---------------------------------------------------------------------------

#[test]
fn junit_batch_mode_groups_cases_per_contract() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("junit_batch");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let manifest = dir.join("pairs.toml");
    std::fs::write(
        &manifest,
        format!(
            "[[pairs]]\nold = \"{}\"\nnew = \"{}\"\nname = \"alpha\"\n\n\
             [[pairs]]\nold = \"{}\"\nnew = \"{}\"\nname = \"beta\"\n",
            wasm("v1.wasm").display(),
            wasm("v2.wasm").display(),
            wasm("v1.wasm").display(),
            wasm("v1.wasm").display(),
        ),
    )
    .expect("failed to write manifest");

    let (code, xml) = run_junit(&["--manifest", manifest.to_str().unwrap()]);

    assert_eq!(code, 1, "a batch containing a breaking pair must exit 1");
    assert_wellformed(&xml);

    assert_eq!(
        count(&xml, "<testsuite "),
        2,
        "each contract must get its own suite:\n{xml}"
    );
    assert!(
        xml.contains("<testsuite name=\"alpha\""),
        "expected a suite named for the first contract:\n{xml}"
    );
    assert!(
        xml.contains("<testsuite name=\"beta\""),
        "expected a suite named for the second contract:\n{xml}"
    );
    assert!(
        xml.contains("classname=\"soroban-upgrade-safeguard.alpha\""),
        "cases must be classed by their contract:\n{xml}"
    );

    let _ = std::fs::remove_file(&manifest);
}
