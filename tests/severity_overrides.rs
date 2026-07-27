//! Integration tests for the `[severity]` table in `.safeguard.toml`.
//!
//! These drive the compiled binary against the checked-in fixtures:
//!
//! - `v1 -> v2` produces three Critical findings and one Info, so the run
//!   FAILS. Demoting all three Criticals is the case that turns a failing gate
//!   green — the outcome the report must never let a reader miss.
//! - `v1 -> v3` produces two `Parameter Renamed` Warnings and PASSES, so
//!   promoting that one category is the case that turns a passing gate red.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Write `contents` to a uniquely named TOML file in the per-test temp dir.
fn write_config(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.safeguard.toml"));
    std::fs::write(&path, contents).expect("failed to write temp config");
    path
}

/// Run the binary over `old -> new` with an optional config and format.
/// Returns `(stdout, stderr, exit code)`.
fn run(
    old: &str,
    new: &str,
    config: Option<&PathBuf>,
    format: Option<&str>,
) -> (String, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm(old)).arg(wasm(new));
    if let Some(format) = format {
        cmd.args(["--format", format]);
    }
    if let Some(path) = config {
        cmd.args(["--config".as_ref(), path.as_os_str()]);
    }
    let output = cmd.output().expect("failed to run binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

/// A config demoting every Critical category `v1 -> v2` produces.
const DEMOTE_ALL: &str = r#"
[severity]
"Enum Case Value Changed"    = "warning"
"Function Signature Changed" = "warning"
"Struct Field Removed"       = "warning"
"#;

// ── Baselines: the fixtures behave as these tests assume ────────────────────

#[test]
fn fixtures_have_the_verdicts_these_tests_build_on() {
    let (_, _, code) = run("v1.wasm", "v2.wasm", None, None);
    assert_eq!(code, 1, "v1 -> v2 must fail without overrides");

    let (_, _, code) = run("v1.wasm", "v3.wasm", None, None);
    assert_eq!(code, 0, "v1 -> v3 must pass without overrides");
}

// ── Demotion ────────────────────────────────────────────────────────────────

#[test]
fn demotion_that_changes_the_exit_code_is_announced() {
    let config = write_config("demote_flips", DEMOTE_ALL);
    let (stdout, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("json"));

    assert_eq!(code, 0, "demoting every Critical must flip the exit code");

    let json: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(json["is_safe"], true);
    assert_eq!(json["counts"]["critical"], 0, "no Critical should remain");
    assert_eq!(json["counts"]["warning"], 3);
    assert_eq!(json["severity_overridden_count"], 3);
    assert_eq!(
        json["verdict_changed_by_override"], true,
        "a gate that only passes because of config must say so"
    );

    // Each overridden finding remembers what the engine itself concluded.
    let overridden: Vec<&Value> = json["findings_by_category"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|v| v.as_array().unwrap())
        .filter(|f| f.get("original_severity").is_some())
        .collect();
    assert_eq!(overridden.len(), 3);
    for finding in overridden {
        assert_eq!(finding["original_severity"], "critical");
        assert_eq!(finding["severity"], "warning");
    }
}

#[test]
fn demotion_that_does_not_change_the_verdict_is_marked_but_not_announced() {
    // `v1 -> v3` passes either way; demoting its warnings only relabels them.
    let config = write_config(
        "demote_no_flip",
        "[severity]\n\"Parameter Renamed\" = \"info\"\n",
    );
    let (stdout, _, code) = run("v1.wasm", "v3.wasm", Some(&config), Some("json"));

    assert_eq!(code, 0);
    let json: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(json["counts"]["warning"], 0);
    assert_eq!(json["counts"]["info"], 2);
    assert_eq!(json["severity_overridden_count"], 2);
    assert_eq!(
        json["verdict_changed_by_override"], false,
        "the verdict was the same with and without the override"
    );
}

// ── Promotion ───────────────────────────────────────────────────────────────

#[test]
fn promotion_that_changes_the_exit_code_is_announced() {
    let config = write_config(
        "promote_flips",
        "[severity]\n\"Parameter Renamed\" = \"critical\"\n",
    );
    let (stdout, _, code) = run("v1.wasm", "v3.wasm", Some(&config), Some("json"));

    assert_eq!(code, 1, "promoting to Critical must fail a passing run");

    let json: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(json["is_safe"], false);
    assert_eq!(json["counts"]["critical"], 2);
    assert_eq!(json["severity_overridden_count"], 2);
    assert_eq!(json["verdict_changed_by_override"], true);
}

#[test]
fn a_rule_id_key_and_a_legacy_alias_resolve_to_the_same_category() {
    // The display label, the stable rule id, and the pre-1.0 event-flavored
    // alias must all address the same finding, exactly as suppression does.
    for key in [
        "\"Struct Field Removed\"",
        "struct_field_removed",
        "\"Event Field Removed\"",
    ] {
        let config = write_config("alias_key", &format!("[severity]\n{key} = \"info\"\n"));
        let (stdout, _, _) = run("v1.wasm", "v2.wasm", Some(&config), Some("json"));
        let json: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json["severity_overridden_count"], 1,
            "key {key} should have matched Struct Field Removed"
        );
        assert_eq!(json["counts"]["critical"], 2);
    }
}

// ── Invalid input ───────────────────────────────────────────────────────────

#[test]
fn an_unknown_category_is_rejected_at_load_time_with_suggestions() {
    let config = write_config(
        "bad_category",
        "[severity]\n\"Struct Field Remvoed\" = \"info\"\n",
    );
    let (_, stderr, code) = run("v1.wasm", "v2.wasm", Some(&config), None);

    assert_eq!(code, 1, "an invalid category must stop the run");
    assert!(
        stderr.contains("Struct Field Remvoed"),
        "the error must quote the offending name back: {stderr}"
    );
    assert!(
        stderr.contains("Struct Field Removed"),
        "the error must suggest the near match: {stderr}"
    );
}

#[test]
fn an_unknown_severity_value_is_rejected() {
    let config = write_config(
        "bad_severity",
        "[severity]\n\"Struct Field Removed\" = \"blocker\"\n",
    );
    let (_, _, code) = run("v1.wasm", "v2.wasm", Some(&config), None);
    assert_eq!(code, 1, "an invalid severity value must stop the run");
}

// ── Every output format ─────────────────────────────────────────────────────

#[test]
fn overrides_are_applied_consistently_across_all_output_formats() {
    let config = write_config("all_formats", DEMOTE_ALL);

    let (text, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("text"));
    assert_eq!(code, 0);
    assert!(text.contains("SEVERITY critical → warning"), "text: {text}");
    assert!(
        text.contains("VERDICT CHANGED BY CONFIG"),
        "text must announce the changed verdict: {text}"
    );

    let (markdown, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("markdown"));
    assert_eq!(code, 0);
    assert!(
        markdown.contains("[SEVERITY critical → warning]"),
        "markdown: {markdown}"
    );
    assert!(markdown.contains("VERDICT CHANGED BY CONFIG"), "markdown");
    assert!(
        markdown.contains("| **Severity overridden** | 3 |"),
        "markdown"
    );

    let (html, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("html"));
    assert_eq!(code, 0);
    assert!(
        html.contains("severity critical → warning"),
        "html must badge each overridden finding"
    );
    assert!(html.contains("VERDICT CHANGED BY CONFIG"), "html");

    let (json, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("json"));
    assert_eq!(code, 0);
    let json: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["verdict_changed_by_override"], true);

    let (gha, _, code) = run("v1.wasm", "v2.wasm", Some(&config), Some("github-actions"));
    assert_eq!(code, 0);
    assert!(
        gha.contains("::warning::VERDICT CHANGED BY CONFIG"),
        "github-actions must annotate the changed verdict: {gha}"
    );
}

// ── Batch mode ──────────────────────────────────────────────────────────────

#[test]
fn overrides_apply_in_batch_mode() {
    let manifest = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "renaming_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v3.wasm").to_str().unwrap(),
    );
    let manifest_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("severity_batch.toml");
    std::fs::write(&manifest_path, manifest).expect("failed to write manifest");

    let config = write_config("batch_overrides", DEMOTE_ALL);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--config".as_ref(), config.as_os_str()])
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let code = output.status.code().expect("process terminated by signal");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("batch stdout must be valid JSON");

    assert_eq!(
        code, 0,
        "with every Critical demoted the whole batch should pass"
    );
    assert_eq!(json["is_safe"], true);

    let breaking = &json["results"]["breaking_contract"];
    assert_eq!(breaking["severity_overridden_count"], 3);
    assert_eq!(breaking["verdict_changed_by_override"], true);
    assert_eq!(breaking["counts"]["critical"], 0);

    // The other pair has no overridden category, so it is untouched.
    let renaming = &json["results"]["renaming_contract"];
    assert_eq!(renaming["severity_overridden_count"], 0);
    assert_eq!(renaming["verdict_changed_by_override"], false);
}
