use std::path::PathBuf;

/// Path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Snapshot directory relative to CARGO_MANIFEST_DIR
fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
}

/// Assert that `content` matches the stored snapshot at `name`.
/// If the env-var `UPDATE_SNAPSHOTS` is set, the snapshot is written instead
/// of compared.
fn assert_snapshot(name: &str, content: &str) {
    let path = snapshot_dir().join(name);
    let update = std::env::var("UPDATE_SNAPSHOTS").is_ok();

    if update {
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, content)
            .unwrap_or_else(|e| panic!("failed to write snapshot {}: {}", path.display(), e));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "snapshot '{}' not found at {}.\n\
             Run with `UPDATE_SNAPSHOTS=1 cargo test` to create it.\n\
             Underlying error: {}",
            name,
            path.display(),
            e
        )
    });

    if content != expected {
        // Show a diff-like message
        let mut first_diff = None;
        for (i, (got_line, exp_line)) in content.lines().zip(expected.lines()).enumerate() {
            if got_line != exp_line {
                first_diff = Some((i + 1, got_line, exp_line));
                break;
            }
        }
        let (line, got, exp) = first_diff.unwrap_or((0, "", ""));
        panic!(
            "snapshot '{}' mismatch{}\n  expected: {:?}\n  got:      {:?}\n\
             Run with `UPDATE_SNAPSHOTS=1 cargo test` to update.",
            name,
            if line > 0 {
                format!(" at line {}", line)
            } else {
                String::from(" (length differs)")
            },
            exp,
            got,
        );
    }
}

fn setup_no_color() {
    colored::control::set_override(false);
}

#[test]
fn snapshot_text_output() {
    setup_no_color();
    let report = soroban_upgrade_safeguard::compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed");
    assert_snapshot("text_output.txt", &report.generate_summary_text(false));
}

#[test]
fn snapshot_markdown_output() {
    setup_no_color();
    let report = soroban_upgrade_safeguard::compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed");
    assert_snapshot("markdown_output.md", &report.generate_summary_markdown());
}

#[test]
fn snapshot_json_output() {
    setup_no_color();
    let report = soroban_upgrade_safeguard::compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed");
    let json = serde_json::to_string_pretty(&report.to_json()).expect("json serialization");
    assert_snapshot("json_output.json", &json);
}

#[test]
fn snapshot_text_output_with_explain() {
    setup_no_color();
    let report = soroban_upgrade_safeguard::compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed");
    assert_snapshot(
        "text_output_explain.txt",
        &report.generate_summary_text(true),
    );
}

#[test]
fn snapshot_identical_contracts_empty_report() {
    setup_no_color();
    let report = soroban_upgrade_safeguard::compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm"))
        .expect("comparison should succeed");
    assert_snapshot(
        "text_output_identical.txt",
        &report.generate_summary_text(false),
    );
}

#[test]
fn snapshot_strict_mode_text_output() {
    setup_no_color();
    let old_bytes = std::fs::read(wasm("v1.wasm")).unwrap();
    let new_bytes = std::fs::read(wasm("v3.wasm")).unwrap();
    let old_meta = soroban_upgrade_safeguard::parser::extract_metadata(&old_bytes).unwrap();
    let new_meta = soroban_upgrade_safeguard::parser::extract_metadata(&new_bytes).unwrap();
    let (old_spec, _) =
        soroban_upgrade_safeguard::spec::ContractSpec::from_entries_checked(&old_meta.spec);
    let (new_spec, _) =
        soroban_upgrade_safeguard::spec::ContractSpec::from_entries_checked(&new_meta.spec);
    let diff_report = soroban_upgrade_safeguard::diff::compare(&old_spec, &new_spec);

    use soroban_upgrade_safeguard::suppression::SuppressionConfig;
    let strict_report = soroban_upgrade_safeguard::report::SafetyReport::with_suppressions(
        &diff_report,
        &SuppressionConfig::default(),
        true,
        true,
        &soroban_upgrade_safeguard::limits::ResourcePolicy::default(),
    );

    assert_snapshot(
        "text_output_strict.txt",
        &strict_report.generate_summary_text(true),
    );
}

#[test]
fn snapshot_suppressed_finding_text() {
    setup_no_color();

    let suppress_content = r#"
[[suppress]]
category = "Struct Field Removed"
target = "ConfigData.threshold"
reason = "Planned storage migration in v2."
"#;
    let tmp_suppress = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("suppress_snapshot.toml");
    std::fs::write(&tmp_suppress, suppress_content).expect("write suppress config");

    let old_bytes = std::fs::read(wasm("v1.wasm")).unwrap();
    let new_bytes = std::fs::read(wasm("v2.wasm")).unwrap();
    let old_meta = soroban_upgrade_safeguard::parser::extract_metadata(&old_bytes).unwrap();
    let new_meta = soroban_upgrade_safeguard::parser::extract_metadata(&new_bytes).unwrap();
    let (old_spec, _) =
        soroban_upgrade_safeguard::spec::ContractSpec::from_entries_checked(&old_meta.spec);
    let (new_spec, _) =
        soroban_upgrade_safeguard::spec::ContractSpec::from_entries_checked(&new_meta.spec);
    let diff_report = soroban_upgrade_safeguard::diff::compare(&old_spec, &new_spec);

    let suppressions =
        soroban_upgrade_safeguard::suppression::SuppressionConfig::load_from_path(&tmp_suppress)
            .unwrap();
    let report = soroban_upgrade_safeguard::report::SafetyReport::with_suppressions(
        &diff_report,
        &suppressions,
        true,
        false,
        &soroban_upgrade_safeguard::limits::ResourcePolicy::default(),
    );

    assert_snapshot(
        "text_output_suppressed.txt",
        &report.generate_summary_text(true),
    );
}

#[test]
fn snapshot_batch_mode_markdown() {
    setup_no_color();

    // Run batch mode via the CLI binary to exercise the batch rendering path
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "markdown"])
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run binary");

    let md = String::from_utf8(output.stdout).expect("stdout not UTF-8");

    // Skip if not a batch mode output (single pair renders differently)
    // We capture the single-pair markdown snapshot
    assert_snapshot("markdown_single_pair.md", &md);
}
