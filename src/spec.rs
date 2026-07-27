use std::collections::BTreeMap;
use std::collections::HashMap;

use stellar_xdr::curr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0,
    ScSpecUdtUnionV0,
};

/// A spec entry annotated with which `contractspecv0` section it came from
/// (zero-indexed). Provenance is tracked so duplicate analysis can report
/// exactly which sections carry conflicting definitions.
#[derive(Debug, Clone)]
pub struct TaggedSpecEntry {
    /// The decoded entry.
    pub entry: ScSpecEntry,
    /// Index of the `contractspecv0` section this entry was decoded from.
    pub section_index: usize,
}

impl TaggedSpecEntry {
    pub fn new(entry: ScSpecEntry, section_index: usize) -> Self {
        Self {
            entry,
            section_index,
        }
    }
}

/// The kind of a spec entry, used in duplicate-detection reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecEntryKind {
    Function,
    Struct,
    Enum,
    Union,
    ErrorEnum,
}

impl SpecEntryKind {
    pub fn label(self) -> &'static str {
        match self {
            SpecEntryKind::Function => "function",
            SpecEntryKind::Struct => "struct",
            SpecEntryKind::Enum => "enum",
            SpecEntryKind::Union => "union",
            SpecEntryKind::ErrorEnum => "error enum",
        }
    }
}

/// A duplicate entry found during `from_entries_checked`.
#[derive(Debug, Clone)]
pub struct DuplicateEntry {
    /// Kind of the duplicated entry.
    pub kind: SpecEntryKind,
    /// Name shared by the conflicting definitions.
    pub name: String,
    /// Sections (0-indexed) that carried a definition for this name.
    pub sections: Vec<usize>,
    /// Whether all definitions are byte-identical.
    pub is_identical: bool,
}

/// A structured representation of a Soroban contract's public interface,
/// organized by type for easy comparison between contract versions.
#[derive(Debug, Default, Clone)]
pub struct ContractSpec {
    /// Contract functions, keyed by name.
    pub functions: HashMap<String, ScSpecFunctionV0>,
    /// User-defined structs, keyed by name.
    pub structs: HashMap<String, ScSpecUdtStructV0>,
    /// User-defined enums, keyed by name.
    pub enums: HashMap<String, ScSpecUdtEnumV0>,
    /// User-defined unions (tagged enums with data), keyed by name.
    pub unions: HashMap<String, ScSpecUdtUnionV0>,
    /// Error enums, keyed by name.
    pub error_enums: HashMap<String, ScSpecUdtErrorEnumV0>,
}

impl ContractSpec {
    /// Build a `ContractSpec` from a list of decoded `ScSpecEntry` objects,
    /// returning both the spec and a list of any duplicate entries found.
    ///
    /// The duplicate-detection policy:
    ///
    /// - **Identical duplicates**: two definitions that are structurally equal
    ///   are treated as informational — they are safe to deduplicate
    ///   deterministically, but the caller should still surface the condition
    ///   so an operator knows the WASM is non-canonical.
    ///   `DuplicateEntry::is_identical` is `true`.
    ///
    /// - **Conflicting duplicates**: two definitions that differ under the same
    ///   name produce a critical finding.  The first-encountered definition is
    ///   used so behaviour is deterministic and independent of HashMap
    ///   iteration order; the second definition is recorded in the returned
    ///   `DuplicateEntry` but is NOT silently discarded — callers must fail
    ///   the run for conflicting duplicates.
    ///   `DuplicateEntry::is_identical` is `false`.
    ///
    /// Provenance (which section each entry came from) is available via
    /// `TaggedSpecEntry::section_index`.
    pub fn from_entries_checked(entries: &[TaggedSpecEntry]) -> (Self, Vec<DuplicateEntry>) {
        let mut spec = ContractSpec::default();
        let mut duplicates: Vec<DuplicateEntry> = Vec::new();

        // Per-kind name → (first_section, serialized_xdr) maps for identity
        // comparison without re-implementing structural equality manually.
        // We use `BTreeMap` for deterministic iteration in tests.
        let mut fn_seen: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();
        let mut struct_seen: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();
        let mut enum_seen: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();
        let mut union_seen: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();
        let mut err_seen: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();

        for tagged in entries {
            let section = tagged.section_index;
            match &tagged.entry {
                ScSpecEntry::FunctionV0(f) => {
                    let name = f.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut fn_seen,
                        &mut duplicates,
                        SpecEntryKind::Function,
                        || {
                            spec.functions
                                .entry(name.clone())
                                .or_insert_with(|| f.clone());
                        },
                    );
                }
                ScSpecEntry::UdtStructV0(s) => {
                    let name = s.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut struct_seen,
                        &mut duplicates,
                        SpecEntryKind::Struct,
                        || {
                            spec.structs
                                .entry(name.clone())
                                .or_insert_with(|| s.clone());
                        },
                    );
                }
                ScSpecEntry::UdtEnumV0(e) => {
                    let name = e.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut enum_seen,
                        &mut duplicates,
                        SpecEntryKind::Enum,
                        || {
                            spec.enums.entry(name.clone()).or_insert_with(|| e.clone());
                        },
                    );
                }
                ScSpecEntry::UdtUnionV0(u) => {
                    let name = u.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut union_seen,
                        &mut duplicates,
                        SpecEntryKind::Union,
                        || {
                            spec.unions.entry(name.clone()).or_insert_with(|| u.clone());
                        },
                    );
                }
                ScSpecEntry::UdtErrorEnumV0(e) => {
                    let name = e.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut err_seen,
                        &mut duplicates,
                        SpecEntryKind::ErrorEnum,
                        || {
                            spec.error_enums
                                .entry(name.clone())
                                .or_insert_with(|| e.clone());
                        },
                    );
                }
            }
        }

        (spec, duplicates)
    }

    /// Convenience wrapper over [`from_entries_checked`] that accepts bare
    /// `ScSpecEntry` slices (section index 0 for all entries). Intended for
    /// callers that do not track section provenance and do not need the
    /// duplicate report.
    ///
    /// When duplicates are detected they are silently discarded (first-wins),
    /// exactly as before; use [`from_entries_checked`] to surface them.
    pub fn from_entries(entries: &[ScSpecEntry]) -> Self {
        let tagged: Vec<TaggedSpecEntry> = entries
            .iter()
            .map(|e| TaggedSpecEntry::new(e.clone(), 0))
            .collect();
        let (spec, _) = Self::from_entries_checked(&tagged);
        spec
    }

    /// Returns a summary string of the spec contents.
    pub fn summary(&self) -> String {
        format!(
            "Functions: {}, Structs: {}, Enums: {}, Unions: {}, Errors: {}",
            self.functions.len(),
            self.structs.len(),
            self.enums.len(),
            self.unions.len(),
            self.error_enums.len(),
        )
    }
}

/// Serialize a `ScSpecEntry` to raw XDR bytes for structural identity comparison.
///
/// This is the canonical way to check whether two entries with the same name
/// are truly identical without implementing a custom `PartialEq` for every
/// variant. An XDR round-trip is deterministic so byte equality implies
/// structural equality.
fn entry_to_xdr(entry: &ScSpecEntry) -> Vec<u8> {
    use stellar_xdr::curr::{Limited, Limits, WriteXdr};
    // Unlimited budget — we only need byte equality, not security bounding.
    // If encoding fails we return an empty Vec, which will never equal any
    // other entry's bytes, steering us to the more conservative conflicting-
    // duplicate path.
    let unlimited = Limits {
        depth: u32::MAX,
        len: usize::MAX,
    };
    let mut buf = Limited::new(Vec::new(), unlimited);
    let _ = entry.write_xdr(&mut buf);
    buf.inner
}

/// Core per-entry deduplication helper.
///
/// `seen` maps `name → (first_section_index, first_xdr_bytes)`.
/// `insert_fn` is called exactly once — when inserting the first occurrence.
/// `duplicates` is appended to when a second occurrence is found.
fn check_and_insert(
    name: &str,
    section: usize,
    xdr: Vec<u8>,
    seen: &mut BTreeMap<String, (usize, Vec<u8>)>,
    duplicates: &mut Vec<DuplicateEntry>,
    kind: SpecEntryKind,
    insert_fn: impl FnOnce(),
) {
    match seen.get(name) {
        None => {
            seen.insert(name.to_string(), (section, xdr));
            insert_fn();
        }
        Some((first_section, first_xdr)) => {
            let is_identical = *first_xdr == xdr;
            if let Some(dup) = duplicates
                .iter_mut()
                .find(|d| d.kind == kind && d.name == name)
            {
                dup.sections.push(section);
                if !is_identical {
                    dup.is_identical = false;
                }
            } else {
                duplicates.push(DuplicateEntry {
                    kind,
                    name: name.to_string(),
                    sections: vec![*first_section, section],
                    is_identical,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{StringM, VecM};

    // ---------------------------------------------------------------
    // Helper builders
    // ---------------------------------------------------------------
    fn make_fn(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: doc.try_into().unwrap(),
            name: name.try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        })
    }

    fn make_struct(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: VecM::default(),
        })
    }

    fn make_enum(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn make_union(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn make_err(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn tagged(entry: ScSpecEntry, section: usize) -> TaggedSpecEntry {
        TaggedSpecEntry::new(entry, section)
    }

    // ---------------------------------------------------------------
    // Identical duplicates — informational, first definition wins
    // ---------------------------------------------------------------
    #[test]
    fn identical_duplicate_function_is_informational() {
        let e1 = make_fn("my_func", "same doc");
        let e2 = make_fn("my_func", "same doc"); // byte-identical
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1, "only one entry inserted");
        assert_eq!(dups.len(), 1);
        assert!(
            dups[0].is_identical,
            "identical duplicate must be flagged as identical"
        );
        assert_eq!(dups[0].kind, SpecEntryKind::Function);
        assert_eq!(dups[0].sections, vec![0, 1]);
    }

    #[test]
    fn identical_duplicate_struct_is_informational() {
        let e1 = make_struct("MyStruct", "same doc");
        let e2 = make_struct("MyStruct", "same doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 0)]; // same section

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.structs.len(), 1);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Struct);
        assert_eq!(dups[0].sections, vec![0, 0]);
    }

    #[test]
    fn identical_duplicate_enum_is_informational() {
        let e1 = make_enum("MyEnum", "doc");
        let e2 = make_enum("MyEnum", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Enum);
    }

    #[test]
    fn identical_duplicate_union_is_informational() {
        let e1 = make_union("MyUnion", "doc");
        let e2 = make_union("MyUnion", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Union);
    }

    #[test]
    fn identical_duplicate_error_enum_is_informational() {
        let e1 = make_err("MyErr", "doc");
        let e2 = make_err("MyErr", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::ErrorEnum);
    }

    // ---------------------------------------------------------------
    // Conflicting duplicates — critical, different definitions
    // ---------------------------------------------------------------
    #[test]
    fn conflicting_duplicate_function_is_not_identical() {
        let e1 = make_fn("transfer", "v1 doc");
        let e2 = make_fn("transfer", "v2 doc different"); // differs in doc → different XDR
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        // First definition wins
        assert_eq!(
            spec.functions["transfer"].doc.to_string(),
            "v1 doc",
            "first definition must be retained"
        );
        assert_eq!(dups.len(), 1);
        assert!(
            !dups[0].is_identical,
            "conflicting duplicate must not be identical"
        );
        assert_eq!(dups[0].kind, SpecEntryKind::Function);
        assert_eq!(dups[0].name, "transfer");
        assert_eq!(dups[0].sections, vec![0, 1]);
    }

    #[test]
    fn conflicting_duplicate_struct_is_not_identical() {
        let e1 = make_struct("Ledger", "v1");
        let e2 = make_struct("Ledger", "v2"); // doc differs
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.structs["Ledger"].doc.to_string(), "v1");
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Struct);
    }

    #[test]
    fn conflicting_duplicate_enum_is_not_identical() {
        let e1 = make_enum("Status", "a");
        let e2 = make_enum("Status", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Enum);
    }

    #[test]
    fn conflicting_duplicate_union_is_not_identical() {
        let e1 = make_union("Action", "a");
        let e2 = make_union("Action", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Union);
    }

    #[test]
    fn conflicting_duplicate_error_enum_is_not_identical() {
        let e1 = make_err("ContractError", "a");
        let e2 = make_err("ContractError", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::ErrorEnum);
    }

    // ---------------------------------------------------------------
    // Three occurrences accumulate into a single DuplicateEntry
    // ---------------------------------------------------------------
    #[test]
    fn three_occurrences_accumulate_into_one_duplicate_entry() {
        let e1 = make_fn("foo", "v1");
        let e2 = make_fn("foo", "v1"); // identical to e1
        let e3 = make_fn("foo", "v3"); // conflicts
        let entries = vec![tagged(e1, 0), tagged(e2, 1), tagged(e3, 2)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions["foo"].doc.to_string(), "v1", "first wins");
        assert_eq!(dups.len(), 1, "all three collapsed into one DuplicateEntry");
        assert_eq!(dups[0].sections, vec![0, 1, 2]);
        assert!(
            !dups[0].is_identical,
            "conflicting third makes the whole group conflicting"
        );
    }

    // ---------------------------------------------------------------
    // Multiple different names do not produce spurious duplicates
    // ---------------------------------------------------------------
    #[test]
    fn unique_names_produce_no_duplicates() {
        let entries = vec![
            tagged(make_fn("a", ""), 0),
            tagged(make_fn("b", ""), 0),
            tagged(make_struct("S", ""), 0),
        ];
        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 2);
        assert_eq!(spec.structs.len(), 1);
        assert!(dups.is_empty(), "no duplicates expected for unique names");
    }

    // ---------------------------------------------------------------
    // Same name, different kinds — NOT a duplicate
    // ---------------------------------------------------------------
    #[test]
    fn same_name_different_kinds_is_not_a_duplicate() {
        // A function named "Token" and a struct named "Token" are distinct namespaces.
        let entries = vec![
            tagged(make_fn("Token", ""), 0),
            tagged(make_struct("Token", ""), 0),
        ];
        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.structs.len(), 1);
        assert!(dups.is_empty(), "different kinds share no namespace");
    }

    // ---------------------------------------------------------------
    // from_entries backward-compat wrapper — still works, no duplicates surfaced
    // ---------------------------------------------------------------
    #[test]
    fn from_entries_backward_compat_accepts_duplicate_silently() {
        let entries = vec![make_fn("my_func", "doc1"), make_fn("my_func", "doc2")];
        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions["my_func"].doc.to_string(), "doc1");
    }

    // ---------------------------------------------------------------
    // Provenance: section indices are correctly threaded through
    // ---------------------------------------------------------------
    #[test]
    fn provenance_section_indices_are_tracked() {
        let e1 = make_struct("Foo", "a");
        let e2 = make_struct("Foo", "b");
        let entries = vec![tagged(e1, 3), tagged(e2, 7)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups[0].sections, vec![3, 7]);
    }

    // ---------------------------------------------------------------
    // Duplicate only-differs-in-doc: still conflicting (structural
    // equality uses XDR bytes, doc is part of the XDR encoding)
    // ---------------------------------------------------------------
    #[test]
    fn doc_only_difference_is_conflicting() {
        // Two structs with same name/fields but different doc strings.
        // The issue acceptance criterion says doc-only differences should
        // still be detected (the second definition DIFFERS from the first).
        let e1 = make_struct("Data", "documented");
        let e2 = make_struct("Data", ""); // empty doc
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(
            !dups[0].is_identical,
            "doc-only difference is still a conflict"
        );
    }

    // ---------------------------------------------------------------
    // Old test parity: from_entries_checked equivalent of the original tests
    // ---------------------------------------------------------------
    #[test]
    fn test_from_entries_duplicate_function_first_wins() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];
        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 1);
        let resolved = spec.functions.get("my_func").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_unique_names_no_warning() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func1".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func2".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];
        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 2);
    }
}
