//! Integration tests for duplicate contractspecv0 spec-entry detection.
//!
//! Acceptance criteria exercised here:
//! - Conflicting duplicates → Critical finding, `is_safe: false`, exit code 1.
//! - Identical duplicates   → Warning finding (non-compat) / Info (compat mode).
//! - All five entry kinds: function, struct, enum, union, error enum.
//! - `scope.old_spec_section_count` / `new_spec_section_count` reflected in JSON.
//! - `scope.old_duplicate_names` / `new_duplicate_names` reflected in JSON.
//! - A WASM with two conflicting sections does NOT silently produce is_safe: true.
//! - Existing single-section fixtures are unaffected.

use soroban_upgrade_safeguard::spec::{ContractSpec, TaggedSpecEntry};
use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, diff::Severity, CompareOptions};
use stellar_xdr::curr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0,
    ScSpecUdtStructV0, ScSpecUdtUnionV0, StringM, VecM,
};

// -----------------------------------------------------------------------
// WASM builder helpers
// -----------------------------------------------------------------------

/// Encode a single XDR spec entry to bytes.
fn encode_entry(entry: &ScSpecEntry) -> Vec<u8> {
    use stellar_xdr::curr::{Limited, Limits, WriteXdr};
    let unlimited = Limits {
        depth: u32::MAX,
        len: usize::MAX,
    };
    let mut buf = Limited::new(Vec::new(), unlimited);
    entry.write_xdr(&mut buf).expect("entry must encode");
    buf.inner
}

/// Build a minimal valid WASM binary with one or two `contractspecv0` sections.
///
/// `sections` is a slice of byte payloads — each element becomes a separate
/// custom section with name `contractspecv0`.  This is the exact WASM structure
/// that triggers the multi-section concatenation path in the parser.
fn wasm_with_spec_sections(sections: &[Vec<u8>]) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    for data in sections {
        let name = b"contractspecv0";
        // Section payload = name_len_leb128 + name_bytes + data_bytes
        let name_leb = leb128_u32(name.len() as u32);
        let payload_len = name_leb.len() + name.len() + data.len();

        wasm.push(0x00); // custom section id
        wasm.extend(leb128_u32(payload_len as u32));
        wasm.extend(&name_leb);
        wasm.extend_from_slice(name);
        wasm.extend_from_slice(data);
    }

    wasm
}

fn leb128_u32(mut n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// Encode a list of spec entries as one raw XDR payload (one section's worth).
fn spec_payload(entries: &[ScSpecEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    for e in entries {
        buf.extend(encode_entry(e));
    }
    buf
}

// -----------------------------------------------------------------------
// Entry-kind builders
// -----------------------------------------------------------------------

fn fn_entry(name: &str, doc: &str) -> ScSpecEntry {
    ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: doc.try_into().unwrap(),
        name: name.try_into().unwrap(),
        inputs: VecM::default(),
        outputs: VecM::default(),
    })
}

fn struct_entry(name: &str, doc: &str) -> ScSpecEntry {
    ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: doc.try_into().unwrap(),
        lib: StringM::default(),
        name: name.try_into().unwrap(),
        fields: VecM::default(),
    })
}

/// A struct with one u32 field (used to create non-identical duplicates).
fn struct_entry_with_field(name: &str, field_name: &str) -> ScSpecEntry {
    use stellar_xdr::curr::ScSpecTypeDef;
    ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: name.try_into().unwrap(),
        fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: field_name.try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        }])
        .unwrap(),
    })
}

fn enum_entry(name: &str, doc: &str) -> ScSpecEntry {
    ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
        doc: doc.try_into().unwrap(),
        lib: StringM::default(),
        name: name.try_into().unwrap(),
        cases: VecM::default(),
    })
}

fn union_entry(name: &str, doc: &str) -> ScSpecEntry {
    ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
        doc: doc.try_into().unwrap(),
        lib: StringM::default(),
        name: name.try_into().unwrap(),
        cases: VecM::default(),
    })
}

fn error_enum_entry(name: &str, doc: &str) -> ScSpecEntry {
    ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
        doc: doc.try_into().unwrap(),
        lib: StringM::default(),
        name: name.try_into().unwrap(),
        cases: VecM::default(),
    })
}

// -----------------------------------------------------------------------
// Helper: run the pipeline on two in-memory WASMs and check findings.
// -----------------------------------------------------------------------

fn run(old: &[u8], new: &[u8]) -> soroban_upgrade_safeguard::report::SafetyReport {
    compare_wasm_bytes_with_options(old, new, &CompareOptions::default())
        .expect("pipeline must not error on structurally valid WASM")
}

fn run_compat(old: &[u8], new: &[u8]) -> soroban_upgrade_safeguard::report::SafetyReport {
    compare_wasm_bytes_with_options(
        old,
        new,
        &CompareOptions {
            compat_duplicates: true,
            ..Default::default()
        },
    )
    .expect("pipeline must not error on structurally valid WASM")
}

// -----------------------------------------------------------------------
// Minimal "clean" WASM used as the unchanged side in tests.
// -----------------------------------------------------------------------

fn clean_wasm() -> Vec<u8> {
    wasm_with_spec_sections(&[spec_payload(&[fn_entry("noop", "")])])
}

// -----------------------------------------------------------------------
// Test 1: single-section WASMs are unaffected (regression guard).
// -----------------------------------------------------------------------

#[test]
fn single_section_wasm_produces_no_duplicate_findings() {
    let old = wasm_with_spec_sections(&[spec_payload(&[fn_entry("transfer", "")])]);
    let new = wasm_with_spec_sections(&[spec_payload(&[fn_entry("transfer", "")])]);

    let report = run(&old, &new);

    let dup_findings: Vec<_> = report
        .findings_by_category
        .keys()
        .filter(|k| k.contains("Spec Entry"))
        .collect();
    assert!(
        dup_findings.is_empty(),
        "single-section identical WASM must produce no Spec Entry findings, got: {:?}",
        dup_findings
    );
}

// -----------------------------------------------------------------------
// Test 2: conflicting struct in two sections → Critical, is_safe=false.
//
// This is the attack scenario from the issue: section 0 has Ledger{balances:
// Vec<i128>} and section 1 has Ledger with a different layout.  The tool
// must NOT silently analyze only the first definition.
// -----------------------------------------------------------------------

#[test]
fn conflicting_struct_in_two_sections_is_critical() {
    // old WASM: section 0 has "Ledger" without fields, section 1 has "Ledger"
    // with a field — these are byte-different, so it's a conflict.
    let section0 = spec_payload(&[struct_entry("Ledger", "v1")]);
    let section1 = spec_payload(&[struct_entry_with_field("Ledger", "balances")]);
    let old = wasm_with_spec_sections(&[section0, section1]);

    // new WASM: a clean single-section build (unchanged)
    let new = wasm_with_spec_sections(&[spec_payload(&[struct_entry("Ledger", "v1")])]);

    let report = run(&old, &new);

    assert!(
        !report.is_safe,
        "a conflicting duplicate in the old WASM must make is_safe=false"
    );

    let conflict_findings: Vec<_> = report
        .findings_by_category
        .get("Spec Entry Conflict")
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .collect();

    assert!(
        !conflict_findings.is_empty(),
        "must produce at least one Spec Entry Conflict finding"
    );
    assert_eq!(
        conflict_findings[0].finding.severity,
        Severity::Critical,
        "conflicting duplicate must be Critical"
    );
    assert!(
        conflict_findings[0].finding.message.contains("old WASM"),
        "finding must identify the offending side"
    );
}

// -----------------------------------------------------------------------
// Test 3: identical struct in two sections → Warning (non-compat mode).
// -----------------------------------------------------------------------

#[test]
fn identical_struct_in_two_sections_is_warning_without_compat() {
    let entry = struct_entry("Ledger", "same doc");
    let section = spec_payload(&[entry]);
    // Same section bytes used twice → identical duplicate spanning two sections.
    let old = wasm_with_spec_sections(&[section.clone(), section]);
    let new = wasm_with_spec_sections(&[spec_payload(&[struct_entry("Ledger", "same doc")])]);

    let report = run(&old, &new);

    let dup_findings: Vec<_> = report
        .findings_by_category
        .get("Spec Entry Duplicate")
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .collect();

    assert!(
        !dup_findings.is_empty(),
        "identical duplicate must produce a Spec Entry Duplicate finding"
    );
    assert_eq!(
        dup_findings[0].finding.severity,
        Severity::Warning,
        "identical duplicate in non-compat mode must be Warning"
    );
}

// -----------------------------------------------------------------------
// Test 4: identical struct in two sections → Info in compat mode.
// -----------------------------------------------------------------------

#[test]
fn identical_struct_in_two_sections_is_info_with_compat() {
    let entry = struct_entry("Ledger", "same doc");
    let section = spec_payload(&[entry]);
    let old = wasm_with_spec_sections(&[section.clone(), section]);
    let new = wasm_with_spec_sections(&[spec_payload(&[struct_entry("Ledger", "same doc")])]);

    let report = run_compat(&old, &new);

    let dup_findings: Vec<_> = report
        .findings_by_category
        .get("Spec Entry Duplicate")
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .collect();

    assert!(
        !dup_findings.is_empty(),
        "identical duplicate must still appear in compat mode"
    );
    assert_eq!(
        dup_findings[0].finding.severity,
        Severity::Info,
        "identical duplicate in compat mode must be Info"
    );
}

// -----------------------------------------------------------------------
// Test 5: conflicting duplicate is Critical even in compat mode.
// -----------------------------------------------------------------------

#[test]
fn conflicting_duplicate_is_critical_even_in_compat_mode() {
    let section0 = spec_payload(&[struct_entry("Data", "v1")]);
    let section1 = spec_payload(&[struct_entry_with_field("Data", "amount")]);
    let old = wasm_with_spec_sections(&[section0, section1]);
    let new = clean_wasm();

    let report = run_compat(&old, &new);

    let conflict_findings: Vec<_> = report
        .findings_by_category
        .get("Spec Entry Conflict")
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .collect();

    assert!(
        !conflict_findings.is_empty(),
        "conflicting duplicate must produce Spec Entry Conflict even in compat mode"
    );
    assert_eq!(
        conflict_findings[0].finding.severity,
        Severity::Critical,
        "conflicting duplicate must remain Critical in compat mode"
    );
    assert!(
        !report.is_safe,
        "is_safe must be false even in compat mode for a conflicting duplicate"
    );
}

// -----------------------------------------------------------------------
// Test 6: all five entry kinds — conflicting.
// -----------------------------------------------------------------------

#[test]
fn all_entry_kinds_detected_conflicting() {
    use soroban_upgrade_safeguard::spec::SpecEntryKind;

    let cases: &[(&str, ScSpecEntry, ScSpecEntry, SpecEntryKind)] = &[
        (
            "function",
            fn_entry("foo", "v1"),
            fn_entry("foo", "v2"),
            SpecEntryKind::Function,
        ),
        (
            "struct",
            struct_entry("Bar", "v1"),
            struct_entry("Bar", "v2"),
            SpecEntryKind::Struct,
        ),
        (
            "enum",
            enum_entry("Baz", "v1"),
            enum_entry("Baz", "v2"),
            SpecEntryKind::Enum,
        ),
        (
            "union",
            union_entry("Qux", "v1"),
            union_entry("Qux", "v2"),
            SpecEntryKind::Union,
        ),
        (
            "error enum",
            error_enum_entry("MyErr", "v1"),
            error_enum_entry("MyErr", "v2"),
            SpecEntryKind::ErrorEnum,
        ),
    ];

    for (label, entry1, entry2, _kind) in cases {
        let section0 = spec_payload(&[entry1.clone()]);
        let section1 = spec_payload(&[entry2.clone()]);
        let old = wasm_with_spec_sections(&[section0, section1]);
        let new = clean_wasm();

        let report = run(&old, &new);

        assert!(
            !report.is_safe,
            "{label}: conflicting duplicate must make is_safe=false"
        );

        let conflict = report
            .findings_by_category
            .get("Spec Entry Conflict")
            .and_then(|v| v.first());
        assert!(
            conflict.is_some(),
            "{label}: must have a Spec Entry Conflict finding"
        );
        assert_eq!(
            conflict.unwrap().finding.severity,
            Severity::Critical,
            "{label}: conflict must be Critical"
        );
    }
}

// -----------------------------------------------------------------------
// Test 7: all five entry kinds — identical.
// -----------------------------------------------------------------------

#[test]
fn all_entry_kinds_detected_identical() {
    let cases: &[(&str, ScSpecEntry)] = &[
        ("function", fn_entry("foo", "same")),
        ("struct", struct_entry("Bar", "same")),
        ("enum", enum_entry("Baz", "same")),
        ("union", union_entry("Qux", "same")),
        ("error enum", error_enum_entry("MyErr", "same")),
    ];

    for (label, entry) in cases {
        let section = spec_payload(&[entry.clone()]);
        let old = wasm_with_spec_sections(&[section.clone(), section]);
        let new = clean_wasm();

        let report = run(&old, &new);

        let dup = report
            .findings_by_category
            .get("Spec Entry Duplicate")
            .and_then(|v| v.first());
        assert!(
            dup.is_some(),
            "{label}: identical duplicate must have a Spec Entry Duplicate finding"
        );
        assert_eq!(
            dup.unwrap().finding.severity,
            Severity::Warning,
            "{label}: identical duplicate must be Warning in non-compat mode"
        );
    }
}

// -----------------------------------------------------------------------
// Test 8: scope JSON fields are populated correctly.
// -----------------------------------------------------------------------

#[test]
fn scope_json_reflects_section_count_and_duplicate_names() {
    let section0 = spec_payload(&[struct_entry("Ledger", "v1")]);
    let section1 = spec_payload(&[struct_entry_with_field("Ledger", "balances")]);
    let old = wasm_with_spec_sections(&[section0, section1]);
    let new = clean_wasm();

    let report = run(&old, &new);

    // old side has 2 sections
    assert_eq!(
        report.scope.old_spec_section_count, 2,
        "old scope must record 2 contractspecv0 sections"
    );
    assert_eq!(
        report.scope.new_spec_section_count, 1,
        "new scope must record 1 contractspecv0 section"
    );

    // duplicate name "Ledger" must appear in old_duplicate_names
    assert!(
        report
            .scope
            .old_duplicate_names
            .contains(&"Ledger".to_string()),
        "old_duplicate_names must contain 'Ledger', got: {:?}",
        report.scope.old_duplicate_names
    );
    assert!(
        report.scope.new_duplicate_names.is_empty(),
        "new_duplicate_names must be empty for a clean WASM"
    );
}

// -----------------------------------------------------------------------
// Test 9: duplicate within the same section (not just cross-section).
// -----------------------------------------------------------------------

#[test]
fn within_section_duplicate_is_detected() {
    // Two definitions for the same name within a SINGLE section.
    let section = spec_payload(&[struct_entry("Dual", "v1"), struct_entry("Dual", "v2")]);
    let old = wasm_with_spec_sections(&[section]);
    let new = clean_wasm();

    let report = run(&old, &new);

    // Conflicting because v1 ≠ v2 (different doc).
    let conflict = report.findings_by_category.get("Spec Entry Conflict");
    assert!(
        conflict.is_some(),
        "within-section conflict must be detected"
    );
}

// -----------------------------------------------------------------------
// Test 10: duplicate only in new WASM is also detected.
// -----------------------------------------------------------------------

#[test]
fn duplicate_in_new_wasm_is_detected() {
    let section0 = spec_payload(&[fn_entry("pay", "a")]);
    let section1 = spec_payload(&[fn_entry("pay", "b")]);
    let new = wasm_with_spec_sections(&[section0, section1]);
    let old = clean_wasm();

    let report = run(&old, &new);

    let conflict = report.findings_by_category.get("Spec Entry Conflict");
    assert!(
        conflict.is_some(),
        "conflict in new WASM must also be detected"
    );
    assert!(
        conflict.unwrap()[0].finding.message.contains("new WASM"),
        "finding message must name the 'new' side"
    );
}

// -----------------------------------------------------------------------
// Test 11: conflicting duplicate in old WASM side is detected
//          and properly attributed to the "old" side.
// -----------------------------------------------------------------------

#[test]
fn conflict_attributed_to_correct_side() {
    // old: two conflicting sections
    let section0 = spec_payload(&[fn_entry("transfer", "a")]);
    let section1 = spec_payload(&[fn_entry("transfer", "b")]);
    let old = wasm_with_spec_sections(&[section0, section1]);

    // new: clean
    let section2 = spec_payload(&[fn_entry("other", "")]);
    let new = wasm_with_spec_sections(&[section2]);

    let report = run(&old, &new);

    let conflicts: Vec<_> = report
        .findings_by_category
        .get("Spec Entry Conflict")
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .collect();

    let old_side = conflicts
        .iter()
        .any(|f| f.finding.message.starts_with("old WASM:"));
    assert!(old_side, "conflict must be attributed to old WASM");
}

// -----------------------------------------------------------------------
// Test 12: the `from_entries_checked` API directly — provenance and
//          section count threading.
// -----------------------------------------------------------------------

#[test]
fn from_entries_checked_section_provenance() {
    let e1 = TaggedSpecEntry::new(fn_entry("foo", "v1"), 0);
    let e2 = TaggedSpecEntry::new(fn_entry("foo", "v2"), 1);

    let (spec, dups) = ContractSpec::from_entries_checked(&[e1, e2]);

    assert_eq!(spec.functions.len(), 1, "only one entry in the spec");
    assert_eq!(
        spec.functions["foo"].doc.to_string(),
        "v1",
        "first definition wins"
    );
    assert_eq!(dups.len(), 1);
    assert_eq!(dups[0].sections, vec![0, 1]);
    assert!(!dups[0].is_identical);
}

// -----------------------------------------------------------------------
// Test 13: very many identical sections — interplay with entry cap.
//          (does not hit the cap, just ensures no panic/overflow).
// -----------------------------------------------------------------------

#[test]
fn many_identical_sections_do_not_panic() {
    let section = spec_payload(&[fn_entry("noop", "")]);
    // 20 identical sections — well within default entry cap
    let sections: Vec<Vec<u8>> = std::iter::repeat(section).take(20).collect();
    let old = wasm_with_spec_sections(&sections);
    let new = clean_wasm();

    let report = run(&old, &new);

    // Must not panic; must produce at least one duplicate finding.
    let dup = report.findings_by_category.get("Spec Entry Duplicate");
    assert!(dup.is_some(), "must detect the many identical duplicates");
}
