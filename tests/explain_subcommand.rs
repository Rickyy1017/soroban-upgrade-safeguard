//! Integration tests for the `explain` subcommand.
//!
//! The guidance paragraphs used to be reachable only by running a full
//! comparison with `--explain`, and only for the categories that comparison
//! happened to produce. `explain` makes them addressable directly, which is
//! what a reviewer reading a CI report or someone writing a suppression rule
//! actually needs.
//!
//! The last test here is the important one: adding a subcommand must not
//! disturb any of the four existing usage modes.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Run the binary with the given arguments; returns `(stdout, stderr, code)`.
fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

#[test]
fn explain_prints_the_guidance_for_a_named_category() {
    let (stdout, _, code) = run(&["explain", "Union Case Reordered"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Union Case Reordered"), "{stdout}");
    assert!(
        stdout.contains(
            "Reordering union cases breaks positional discriminant serialization. \
             Restore the original case order."
        ),
        "the full guidance paragraph must be printed: {stdout}"
    );
    // The stable rule id and default severity make the output directly usable
    // for writing a [[suppress]] rule or a [severity] override.
    assert!(stdout.contains("union_case_reordered"), "{stdout}");
    assert!(stdout.contains("critical"), "{stdout}");
}

#[test]
fn a_category_can_be_named_by_rule_id_or_in_any_case() {
    let (canonical, _, _) = run(&["explain", "Union Case Reordered"]);
    let guidance = "Reordering union cases breaks positional discriminant serialization.";
    assert!(canonical.contains(guidance));

    for alias in [
        "union_case_reordered",
        "union case reordered",
        "UNION CASE REORDERED",
    ] {
        let (stdout, stderr, code) = run(&["explain", alias]);
        assert_eq!(code, 0, "'{alias}' should resolve: {stderr}");
        assert!(stdout.contains(guidance), "'{alias}' gave: {stdout}");
    }
}

#[test]
fn explain_with_no_argument_lists_every_known_category() {
    let (stdout, _, code) = run(&["explain"]);

    assert_eq!(code, 0);

    // Every registered category must appear, not just the ones a comparison
    // over the fixtures happens to emit.
    for label in soroban_upgrade_safeguard::rules::all_category_labels() {
        assert!(
            stdout.contains(label),
            "category '{label}' missing from the listing"
        );
    }

    // The listing is only useful for writing config if it also carries the
    // exact strings that matching uses.
    assert!(stdout.contains("union_case_reordered"), "{stdout}");
    assert!(stdout.contains("cascading_layout_break"), "{stdout}");
}

#[test]
fn an_unknown_category_suggests_near_matches_rather_than_failing_bare() {
    let (_, stderr, code) = run(&["explain", "Union Case Reorderd"]);

    assert_ne!(code, 0, "an unknown category must be an error");
    assert!(stderr.contains("Union Case Reorderd"), "{stderr}");
    assert!(
        stderr.contains("Did you mean"),
        "a near miss must be corrected, not merely rejected: {stderr}"
    );
    assert!(stderr.contains("Union Case Reordered"), "{stderr}");
}

#[test]
fn a_partial_name_suggests_the_categories_containing_it() {
    let (_, stderr, code) = run(&["explain", "union case"]);

    assert_ne!(code, 0);
    assert!(stderr.contains("Did you mean"), "{stderr}");
    assert!(
        stderr.contains("Union Case Removed") || stderr.contains("Union Case Added"),
        "a substring should surface the whole family: {stderr}"
    );
}

#[test]
fn every_category_in_the_listing_can_be_explained() {
    // The listing is a promise: each name it prints must be one `explain`
    // accepts, or the reference is worse than useless for writing config.
    for label in soroban_upgrade_safeguard::rules::all_category_labels() {
        let (stdout, stderr, code) = run(&["explain", label]);
        assert_eq!(code, 0, "explain '{label}' failed: {stderr}");
        assert!(
            !stdout.trim().is_empty(),
            "explain '{label}' printed nothing"
        );
    }
}

// ── The four existing usage modes are unaffected ────────────────────────────

#[test]
fn all_four_usage_modes_still_work() {
    // 1. Local: two positional WASM paths.
    let (_, _, code) = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "local mode must still run and report the breaks");

    let (_, _, code) = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "local mode must still pass an identical pair");

    // 2. RPC: --contract-id/--rpc-url are still co-dependent and still parse.
    //    (No network call is made: validation rejects it before any request.)
    let (_, stderr, code) = run(&["--contract-id", "CABC", wasm("v2.wasm").to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("rpc-url") || stderr.contains("rpc_url"),
        "RPC mode must still require --rpc-url: {stderr}"
    );

    // 3. Manifest: a missing manifest is still a manifest-mode error, which
    //    proves the flag still routes to batch mode.
    let (_, stderr, code) = run(&["--manifest", "definitely-not-here.toml"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("manifest"),
        "manifest mode must still be reached: {stderr}"
    );

    // 4. Dir scan: --old-dir still requires --new-dir.
    let (_, stderr, code) = run(&["--old-dir", "some-dir"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("new-dir") || stderr.contains("new_dir"),
        "dir-scan mode must still require --new-dir: {stderr}"
    );
}

#[test]
fn the_usage_text_is_unchanged_and_lists_the_four_modes() {
    let (stdout, _, code) = run(&["--help"]);

    assert_eq!(code, 0);
    for line in [
        "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]",
        "soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]",
        "soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]",
        "soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]",
    ] {
        assert!(
            stdout.contains(line),
            "usage line missing: {line}\n{stdout}"
        );
    }

    // The new subcommand is discoverable without displacing any of the above.
    assert!(stdout.contains("explain"), "{stdout}");
}

#[test]
fn explain_help_describes_the_subcommand() {
    let (stdout, _, code) = run(&["explain", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("explain [CATEGORY]"), "{stdout}");
}
