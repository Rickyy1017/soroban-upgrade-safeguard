//! Benchmarks for the four independent stages of the analysis pipeline:
//! spec building, diffing, cascade detection, and report rendering.
//!
//! The checked-in `tests/wasm` fixtures are too small to show how cost scales
//! with contract size, so these benchmarks generate synthetic specs
//! programmatically across a range of sizes instead of relying on one small,
//! real-world input. See docs/contributing.md#benchmarking for how to run
//! these and interpret the results.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use soroban_upgrade_safeguard::diff;
use soroban_upgrade_safeguard::limits::ResourcePolicy;
use soroban_upgrade_safeguard::mapper::LayoutMapper;
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::spec::{ContractSpec, TaggedSpecEntry};

use stellar_xdr::curr::{
    Limited, Limits, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeUdt,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM, WriteXdr,
};

/// Sizes exercised by every stage. Chosen to span two orders of magnitude so
/// a benchmark run shows whether cost grows linearly with input size or
/// worse, rather than reporting a single data point.
const SIZES: [usize; 3] = [10, 100, 1000];

fn udt(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: name.try_into().unwrap(),
    })
}

/// `n` functions with unique names and no parameters. Exercises spec building
/// and diffing cost as a function of interface width.
fn make_function_entries(n: usize) -> Vec<ScSpecEntry> {
    (0..n)
        .map(|i| {
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: StringM::default(),
                name: format!("fn_{i}").try_into().unwrap(),
                inputs: VecM::default(),
                outputs: VecM::default(),
            })
        })
        .collect()
}

/// A linear dependency chain of `n` structs: `Struct_0` holds a plain `u32`,
/// and `Struct_i` (i >= 1) embeds `Struct_{i-1}`. This gives
/// `detect_cascading_layout_breaks`'s reverse-dependency walk a real graph to
/// traverse instead of a flat, dependency-free set of types.
fn make_struct_chain(n: usize) -> ContractSpec {
    let mut spec = ContractSpec::default();
    for i in 0..n {
        let field_type = if i == 0 {
            ScSpecTypeDef::U32
        } else {
            udt(&format!("Struct_{}", i - 1))
        };
        let fields: Vec<ScSpecUdtStructFieldV0> = vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "field".try_into().unwrap(),
            type_: field_type,
        }];
        spec.structs.insert(
            format!("Struct_{i}"),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: format!("Struct_{i}").try_into().unwrap(),
                fields: VecM::try_from(fields).unwrap(),
            },
        );
    }
    spec
}

/// Serializes spec entries to the same concatenated-XDR wire format
/// `parser::decode_spec_entries` reads from a `contractspecv0` section, so the
/// parsing benchmark exercises the real decode loop rather than a synthetic
/// stand-in for it.
fn encode_entries(entries: &[ScSpecEntry]) -> Vec<u8> {
    let unlimited = Limits {
        depth: u32::MAX,
        len: usize::MAX,
    };
    let mut buf = Limited::new(Vec::new(), unlimited);
    for entry in entries {
        entry
            .write_xdr(&mut buf)
            .expect("synthetic entry must encode");
    }
    buf.inner
}

fn tagged(entries: Vec<ScSpecEntry>) -> Vec<TaggedSpecEntry> {
    entries
        .into_iter()
        .map(|e| TaggedSpecEntry::new(e, 0))
        .collect()
}

/// Stage 1: decoding concatenated `ScSpecEntry` XDR bytes — the same loop
/// `parser::decode_spec_entries` runs against a real `contractspecv0` section.
fn bench_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");
    for size in SIZES {
        let bytes = encode_entries(&make_function_entries(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &bytes, |b, bytes| {
            b.iter(|| soroban_upgrade_safeguard::parser::decode_spec_entries(bytes).unwrap());
        });
    }
    group.finish();
}

/// Stage 2: building a `ContractSpec` from decoded entries, including the
/// duplicate-detection pass every entry goes through.
fn bench_spec_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("spec_building");
    for size in SIZES {
        let entries = tagged(make_function_entries(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &entries, |b, entries| {
            b.iter(|| ContractSpec::from_entries_checked(entries));
        });
    }
    group.finish();
}

/// Stage 3: structural diffing between two specs of matching size, covering
/// function/struct/enum/union comparison.
fn bench_diffing(c: &mut Criterion) {
    let mut group = c.benchmark_group("diffing");
    for size in SIZES {
        let old = ContractSpec::from_entries(&make_function_entries(size));
        let new = ContractSpec::from_entries(&make_function_entries(size));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(old, new),
            |b, (old, new)| {
                b.iter(|| diff::compare(old, new));
            },
        );
    }
    group.finish();
}

/// Stage 4: cascade detection's reverse-dependency graph build — the walk
/// over every field of every type that issue #135 identifies as one of the
/// pipeline's more expensive stages on a large type graph.
fn bench_cascade_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("cascade_detection");
    let policy = ResourcePolicy::default();
    for size in SIZES {
        let spec = make_struct_chain(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &spec, |b, spec| {
            b.iter(|| {
                let mapper = LayoutMapper::new_with_policy(spec, &policy);
                mapper.try_build_reverse_dependencies().unwrap()
            });
        });
    }
    group.finish();
}

/// Stage 5: rendering a `SafetyReport` to text, the cheapest of the three
/// output formats and a reasonable proxy for markdown/JSON rendering cost,
/// which share the same underlying finding traversal.
fn bench_report_rendering(c: &mut Criterion) {
    let mut group = c.benchmark_group("report_rendering");
    for size in SIZES {
        let old = ContractSpec::from_entries(&make_function_entries(size));
        // Rename every function so the diff produces one finding per
        // function instead of an empty report with nothing to render.
        let new_entries: Vec<ScSpecEntry> = (0..size)
            .map(|i| {
                ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                    doc: StringM::default(),
                    name: format!("renamed_fn_{i}").try_into().unwrap(),
                    inputs: VecM::default(),
                    outputs: VecM::default(),
                })
            })
            .collect();
        let new = ContractSpec::from_entries(&new_entries);
        let diff_report = diff::compare(&old, &new);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &diff_report,
            |b, diff_report| {
                b.iter(|| SafetyReport::new(diff_report).generate_summary_text(false));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_parsing,
    bench_spec_building,
    bench_diffing,
    bench_cascade_detection,
    bench_report_rendering,
);
criterion_main!(benches);
