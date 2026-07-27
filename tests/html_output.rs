//! Integration tests for `--format html`.
//!
//! The HTML report exists to be published as a build artifact, read by people
//! who never open the job log. That imposes two hard constraints the other
//! formats do not have:
//!
//! 1. It must render offline, from artifact storage, with no network access.
//! 2. Everything in it is derived from an untrusted WASM binary, so unescaped
//!    output is an injection vector into whoever opens the report.

use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::diff::{DiffReport, Finding, Severity};
use soroban_upgrade_safeguard::report::SafetyReport;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Run the binary over `old -> new` in HTML mode; returns `(stdout, code)`.
fn run_html(old: &str, new: &str) -> (String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "html"])
        .output()
        .expect("failed to run binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

#[test]
fn html_output_is_a_single_self_contained_document() {
    let (stdout, code) = run_html("v1.wasm", "v2.wasm");

    assert_eq!(code, 1, "the verdict must be unchanged by the format");
    assert!(
        stdout.trim_start().starts_with("<!DOCTYPE html>"),
        "{stdout}"
    );
    assert!(stdout.contains("</html>"));
    assert!(stdout.contains("<style>"), "CSS must be inline");

    // Nothing may be fetched at render time: these reports are opened from
    // artifact storage with no network assumed.
    for external in [
        "http://", "https://", "//cdn", "src=\"//", "@import", "url(", "<img", "<link",
    ] {
        assert!(
            !stdout.contains(external),
            "HTML report must make no external request, found '{external}'"
        );
    }
}

#[test]
fn html_carries_the_same_information_as_the_other_formats() {
    let (stdout, _) = run_html("v1.wasm", "v2.wasm");

    // Verdict, scope, counts, and the recommended bump.
    assert!(stdout.contains("FAILED"), "{stdout}");
    assert!(stdout.contains("Storage layout"), "scope must be stated");
    assert!(stdout.contains("Recommended SemVer bump"));
    assert!(stdout.contains("Critical"));

    // Findings, grouped by category with counts.
    for category in [
        "Enum Case Value Changed",
        "Function Signature Changed",
        "Struct Field Removed",
        "Enum Case Added",
    ] {
        assert!(stdout.contains(category), "missing category: {category}");
    }
    assert!(stdout.contains("<details"), "categories must be groupable");
    assert!(
        stdout.contains("class=\"count\""),
        "groups must show counts"
    );

    // Severity filtering in the page.
    assert!(stdout.contains("sev-toggle"), "severity filter missing");
    assert!(stdout.contains("hide-info"), "info filtering missing");

    // Build metrics.
    assert!(stdout.contains("Build Metrics"));
}

#[test]
fn suppressed_findings_and_their_reasons_appear_in_html() {
    let config_path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("html_suppress.safeguard.toml");
    std::fs::write(
        &config_path,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Planned migration in v3 drops the threshold field."
        "#,
    )
    .expect("failed to write config");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "html"])
        .args(["--config".as_ref(), config_path.as_os_str()])
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(stdout.contains("badge-suppressed"), "{stdout}");
    assert!(
        stdout.contains("Planned migration in v3 drops the threshold field."),
        "the suppression reason must survive into HTML"
    );
    assert!(
        stdout.contains("Applied Suppressions Audit Log"),
        "the audit log must be present"
    );
}

#[test]
fn explain_guidance_is_included_when_requested() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "html", "--explain"])
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(stdout.contains("guidance:"), "{stdout}");
}

// ── Escaping ────────────────────────────────────────────────────────────────

/// A report whose finding text carries HTML metacharacters, as a hostile WASM
/// binary's type and field names could.
fn report_with_hostile_names() -> SafetyReport {
    SafetyReport::new(&DiffReport {
        findings: vec![Finding {
            severity: Severity::Critical,
            category: "Struct Field Removed".to_string(),
            message: "Struct field <script>alert('xss')</script> of type \
                      \"Data\" & Co was removed"
                .to_string(),
            type_name: Some("<img src=x onerror=alert(1)>".to_string()),
            target: Some("<b>Data</b>.amount".to_string()),
            classification: None,
        }],
    })
}

#[test]
fn wasm_derived_content_is_escaped() {
    let html = report_with_hostile_names().generate_summary_html();

    // The raw markup must never reach the document.
    assert!(
        !html.contains("<script>alert('xss')</script>"),
        "a script tag from the WASM input reached the page unescaped"
    );
    assert!(
        !html.contains("<img src=x onerror=alert(1)>"),
        "an event-handler tag from the WASM input reached the page unescaped"
    );
    assert!(
        !html.contains("<b>Data</b>.amount"),
        "a target from the WASM input reached the page unescaped"
    );

    // It must still be *present*, just inert.
    assert!(
        html.contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
        "the escaped message must still be readable: {html}"
    );
    assert!(html.contains("&quot;Data&quot; &amp; Co"), "{html}");
    assert!(html.contains("&lt;b&gt;Data&lt;/b&gt;.amount"), "{html}");

    // The page's own structural markup is of course still real markup.
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("<details"));
}

#[test]
fn escaping_covers_every_metacharacter() {
    use soroban_upgrade_safeguard::report::escape_html;

    assert_eq!(
        escape_html(r#"<a href="x" o='y'>&</a>"#),
        "&lt;a href=&quot;x&quot; o=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
    );
    // Ordinary text, including non-ASCII, passes through untouched.
    assert_eq!(escape_html("Data.amount → i128"), "Data.amount → i128");
}

// ── Batch mode ──────────────────────────────────────────────────────────────

#[test]
fn batch_mode_renders_every_pair_into_one_document() {
    let manifest = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "renaming_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v3.wasm").to_str().unwrap(),
    );
    let manifest_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("html_batch.toml");
    std::fs::write(&manifest_path, manifest).expect("failed to write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--format", "html"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "one breaking pair must still fail the batch");

    // Exactly one document, containing all three pairs.
    assert_eq!(
        stdout.matches("<!DOCTYPE html>").count(),
        1,
        "batch mode must emit one document, not one per pair"
    );
    assert_eq!(stdout.matches("</html>").count(), 1);
    for name in ["breaking_contract", "clean_contract", "renaming_contract"] {
        assert!(
            stdout.contains(name),
            "pair '{name}' missing from the document"
        );
    }
    assert_eq!(
        stdout.matches("class=\"report\"").count(),
        3,
        "each pair must contribute its own report section"
    );

    // The batch-level summary and status are present too.
    assert!(stdout.contains("Batch Mode"), "{stdout}");
    assert!(stdout.contains("Some contracts have breaking changes"));

    // Still self-contained.
    assert!(!stdout.contains("http://") && !stdout.contains("https://"));
}

#[test]
fn html_can_be_written_to_a_file_with_output() {
    let out_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("report.html");
    let _ = std::fs::remove_file(&out_path);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "html"])
        .args(["--output".as_ref(), out_path.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(1));
    let written = std::fs::read_to_string(&out_path).expect("report file must exist");
    assert!(written.trim_start().starts_with("<!DOCTYPE html>"));
    assert!(written.contains("Struct Field Removed"));

    // stdout stays empty so the file is the whole artifact.
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim().is_empty(), "stdout should be clean: {stdout}");
}
