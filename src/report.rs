use crate::diff::{DiffReport, Finding, Severity};
use crate::limits::ResourcePolicy;
use crate::rules::{canonical_rule_id, guidance_for_rule_id};
use crate::suppression::SuppressionConfig;
use colored::Colorize;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

/// One-line summary of exactly what a verdict from this tool certifies.
///
/// Displayed under the status in every human-readable format and mirrored into
/// the JSON `certifies` field. It exists to stop a green result from being read
/// as "storage-compatible": the analysis only sees the exported `contractspecv0`
/// interface and environment metadata, never the internal storage layout that
/// actually governs on-chain upgrade compatibility.
pub const SCOPE_SUMMARY_LINE: &str = "Exported interface + environment metadata only — \
     storage layout is NOT verified by this result.";

/// Longer bounded-claim paragraph appended to reports so an operator cannot
/// mistake "no exported-interface breaks" for "storage-compatible".
pub const STORAGE_NOT_VERIFIED_NOTE: &str = "Note: this result does NOT certify storage-layout \
     compatibility. Internal value types serialized into storage and storage-key discriminants \
     need not appear in the exported spec, so a green verdict here says nothing about whether \
     stored data will still deserialize after the upgrade.";

/// Whether — and how much — storage layout was analyzed for this run.
///
/// A verdict is only as trustworthy as its scope. When no storage schema is
/// supplied the tool has no view of internal storage layout at all, and this
/// state records that plainly so neither a human nor a machine consumer mistakes
/// "no exported-interface breaks" for "storage-compatible".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageScopeState {
    /// No storage schema was supplied — storage layout was not analyzed.
    NotAnalyzed,
    /// A storage schema was supplied and diffed; coverage is bounded to the
    /// declared key and value types.
    Analyzed {
        key_types: usize,
        value_types: usize,
    },
}

/// A structured description of what a given run actually inspected.
///
/// Every field answers "was this dimension analyzed?" so the scope can be
/// reported faithfully in all formats and consumed as machine-readable coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisScope {
    /// The exported `contractspecv0` interface is always compared.
    pub exported_interface: bool,
    /// Whether environment metadata (`contractenvmetav0`) was compared.
    pub env_metadata: bool,
    /// The storage-layout analysis state for this run.
    pub storage_schema: StorageScopeState,
    /// Number of distinct `contractspecv0` sections in the old WASM (0 if not parsed).
    pub old_spec_section_count: usize,
    /// Number of distinct `contractspecv0` sections in the new WASM (0 if not parsed).
    pub new_spec_section_count: usize,
    /// Names of duplicate entries found in the old WASM, sorted for stable output.
    pub old_duplicate_names: Vec<String>,
    /// Names of duplicate entries found in the new WASM, sorted for stable output.
    pub new_duplicate_names: Vec<String>,
}

impl Default for AnalysisScope {
    /// The conservative default: exported interface analyzed, environment
    /// metadata not compared, storage layout not analyzed. Callers that do more
    /// (the CLI compares env metadata; a schema-backed run analyzes storage)
    /// widen the scope explicitly, so the report never overstates coverage.
    fn default() -> Self {
        Self {
            exported_interface: true,
            env_metadata: false,
            storage_schema: StorageScopeState::NotAnalyzed,
            old_spec_section_count: 0,
            new_spec_section_count: 0,
            old_duplicate_names: Vec::new(),
            new_duplicate_names: Vec::new(),
        }
    }
}

impl AnalysisScope {
    /// Whether a storage schema was analyzed for this run.
    pub fn storage_analyzed(&self) -> bool {
        matches!(self.storage_schema, StorageScopeState::Analyzed { .. })
    }

    /// One-sentence bounded claim describing what this verdict certifies. When
    /// no schema was supplied it reduces to [`SCOPE_SUMMARY_LINE`].
    pub fn summary_line(&self) -> String {
        match &self.storage_schema {
            StorageScopeState::NotAnalyzed => SCOPE_SUMMARY_LINE.to_string(),
            StorageScopeState::Analyzed {
                key_types,
                value_types,
            } => format!(
                "Exported interface + environment metadata, plus a declared storage schema \
                 ({key_types} key type(s), {value_types} value type(s)). Storage coverage is \
                 limited to the declared types."
            ),
        }
    }

    /// A single line stating the storage-layout coverage explicitly.
    pub fn storage_status_line(&self) -> String {
        match &self.storage_schema {
            StorageScopeState::NotAnalyzed => {
                "Storage layout: NOT analyzed — no storage schema supplied.".to_string()
            }
            StorageScopeState::Analyzed {
                key_types,
                value_types,
            } => format!(
                "Storage layout: analyzed against the declared schema \
                 ({key_types} key type(s), {value_types} value type(s))."
            ),
        }
    }
}

/// A machine-readable view of an [`AnalysisScope`] for `--format json`.
#[derive(Serialize, JsonSchema)]
pub struct ScopeJson {
    pub exported_interface_analyzed: bool,
    pub env_metadata_analyzed: bool,
    pub storage_layout_analyzed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_key_types: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_value_types: Option<usize>,
    /// Number of `contractspecv0` sections found in the old WASM.
    pub old_spec_section_count: usize,
    /// Number of `contractspecv0` sections found in the new WASM.
    pub new_spec_section_count: usize,
    /// Names of duplicate entries detected in the old WASM (empty when clean).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub old_duplicate_names: Vec<String>,
    /// Names of duplicate entries detected in the new WASM (empty when clean).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_duplicate_names: Vec<String>,
    pub summary: String,
}

impl AnalysisScope {
    /// Build the serializable coverage view of this scope.
    pub fn to_json(&self) -> ScopeJson {
        let (storage_key_types, storage_value_types) = match &self.storage_schema {
            StorageScopeState::NotAnalyzed => (None, None),
            StorageScopeState::Analyzed {
                key_types,
                value_types,
            } => (Some(*key_types), Some(*value_types)),
        };
        ScopeJson {
            exported_interface_analyzed: self.exported_interface,
            env_metadata_analyzed: self.env_metadata,
            storage_layout_analyzed: self.storage_analyzed(),
            storage_key_types,
            storage_value_types,
            old_spec_section_count: self.old_spec_section_count,
            new_spec_section_count: self.new_spec_section_count,
            old_duplicate_names: self.old_duplicate_names.clone(),
            new_duplicate_names: self.new_duplicate_names.clone(),
            summary: self.summary_line(),
        }
    }
}

/// A finding as it appears in the report, augmented with suppression state.
///
/// The raw [`Finding`] from the diff layer is left untouched; suppression is a
/// report-time concern layered on top. A suppressed finding is still listed in
/// full — it simply does not count toward the failing set.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReportedFinding {
    /// Stable rule id for this finding.
    pub rule_id: String,
    /// The underlying finding, flattened so JSON keeps its original shape
    /// (`severity`, `category`, `message`, `type_name`, `target`).
    #[serde(flatten)]
    pub finding: Finding,
    /// The SHA-256 fingerprint computed for this finding.
    pub fingerprint: String,
    /// Whether a suppression rule acknowledged this finding.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub suppressed: bool,
    /// The justification copied from the matching rule, if it provided one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    /// The author copied from the matching rule, if it provided one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_author: Option<String>,
    /// The expiry copied from the matching rule, if it provided one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_expiry: Option<String>,
    /// The fingerprint copied from the matching rule, if it provided one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_fingerprint: Option<String>,
    /// Optional remediation/explanation advice for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The severity the analysis engine originally assigned, present only when
    /// a `[severity]` override changed it.
    ///
    /// `finding.severity` always carries the *effective* severity — what the
    /// verdict, counts, and exit code were computed from. This field preserves
    /// what the tool would have said on its own, so a reader can always tell an
    /// engine verdict apart from a configured one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_severity: Option<Severity>,
    /// Whether this finding is new or persisting relative to a `--baseline`
    /// report. `None` when no baseline was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_status: Option<crate::baseline::BaselineStatus>,
}

/// Per-build size and interface-count metrics, carried in the report for all
/// three output formats. These are purely informational and never affect
/// `is_safe`, the exit code, or the recommended bump.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BuildMetrics {
    /// Total WASM binary size in bytes for the old build.
    pub old_size_bytes: usize,
    /// Total WASM binary size in bytes for the new build.
    pub new_size_bytes: usize,
    /// Byte delta: `new_size_bytes as i64 - old_size_bytes as i64`.
    pub size_delta_bytes: i64,
    /// Number of exported functions in the old spec.
    pub old_function_count: usize,
    /// Number of exported functions in the new spec.
    pub new_function_count: usize,
    /// Number of structs in the old spec.
    pub old_struct_count: usize,
    /// Number of structs in the new spec.
    pub new_struct_count: usize,
    /// Number of enums in the old spec.
    pub old_enum_count: usize,
    /// Number of enums in the new spec.
    pub new_enum_count: usize,
    /// Number of unions in the old spec.
    pub old_union_count: usize,
    /// Number of unions in the new spec.
    pub new_union_count: usize,
    /// Number of error enums in the old spec.
    pub old_error_enum_count: usize,
    /// Number of error enums in the new spec.
    pub new_error_enum_count: usize,
}

impl BuildMetrics {
    /// Construct metrics from raw byte lengths and spec counts.
    pub fn new(
        old_size_bytes: usize,
        new_size_bytes: usize,
        old_fn: usize,
        new_fn: usize,
        old_struct: usize,
        new_struct: usize,
        old_enum: usize,
        new_enum: usize,
        old_union: usize,
        new_union: usize,
        old_err: usize,
        new_err: usize,
    ) -> Self {
        Self {
            old_size_bytes,
            new_size_bytes,
            size_delta_bytes: new_size_bytes as i64 - old_size_bytes as i64,
            old_function_count: old_fn,
            new_function_count: new_fn,
            old_struct_count: old_struct,
            new_struct_count: new_struct,
            old_enum_count: old_enum,
            new_enum_count: new_enum,
            old_union_count: old_union,
            new_union_count: new_union,
            old_error_enum_count: old_err,
            new_error_enum_count: new_err,
        }
    }

    /// Format byte size as a human-readable string (bytes / KB / MB).
    pub fn format_bytes(n: usize) -> String {
        if n >= 1_048_576 {
            format!("{:.2} MB", n as f64 / 1_048_576.0)
        } else if n >= 1024 {
            format!("{:.2} KB", n as f64 / 1024.0)
        } else {
            format!("{} B", n)
        }
    }

    /// Format a signed byte delta as "+X KB" / "-X KB" etc.
    pub fn format_delta(d: i64) -> String {
        let abs = d.unsigned_abs() as usize;
        let sign = if d >= 0 { "+" } else { "-" };
        format!("{}{}", sign, Self::format_bytes(abs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportSettings {
    pub strict: bool,
    pub explain: bool,
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    pub max_xdr_depth: u32,
    pub max_xdr_len: usize,
    pub max_entries: usize,
    pub max_walk_depth: usize,
}

/// A structured container for aggregated comparison findings.
pub struct SafetyReport {
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    /// Number of findings (of any severity) acknowledged by a suppression rule.
    pub suppressed_count: usize,
    /// Number of findings hidden by category filtering.
    pub filtered_count: usize,
    /// Number of findings whose severity a `[severity]` override changed.
    pub severity_overridden_count: usize,
    /// Whether the pass/fail verdict differs from what it would have been
    /// without the `[severity]` overrides.
    ///
    /// Reported prominently in every format. An override that turns a failing
    /// gate green is exactly the case a reader must not be able to miss.
    pub verdict_changed_by_override: bool,
    pub suppressed_critical_count: usize,
    pub total_findings: usize,
    pub is_safe: bool,
    pub findings_by_category: HashMap<String, Vec<ReportedFinding>>,
    pub strict: bool,
    pub settings: ReportSettings,
    /// What this run actually inspected. Drives the scope reporting so a verdict
    /// is never read as broader than the analysis that produced it.
    pub scope: AnalysisScope,
    /// Where the baseline (old) contract was sourced from (e.g. "RPC", "Local File").
    pub baseline_source: Option<String>,
    /// Verified SHA-256 hash of the baseline WASM bytecode (hex), if verified.
    pub verified_code_hash: Option<String>,
    /// Active category filter, if any.
    pub category_filter: CategoryFilter,
    /// Human-readable summary of the old contract spec (e.g. "3 fns, 2 types").
    /// Populated by the canonical pipeline so callers don't need to re-extract metadata.
    pub old_spec_summary: Option<String>,
    /// Human-readable summary of the new contract spec.
    /// Populated by the canonical pipeline so callers don't need to re-extract metadata.
    pub new_spec_summary: Option<String>,
    /// Build size and interface-count metrics. `None` when the pipeline did not
    /// supply byte sizes (e.g. in some library callers that use `compare_wasm_bytes`
    /// without access to the original slices' lengths — though in practice the
    /// canonical pipeline always populates this).
    pub metrics: Option<BuildMetrics>,
    /// Suppression rules from the config that matched no finding during this run.
    /// Non-empty indicates a potential typo or a stale rule, surfaced to stderr.
    pub unmatched_suppressions: Vec<crate::suppression::SuppressionRule>,
    /// Set by [`crate::baseline::apply`] when a `--baseline` report was
    /// supplied. `None` means no baseline comparison was requested.
    pub baseline_diff: Option<crate::baseline::BaselineDiff>,
    /// When `true`, [`Self::generate_summary_text`] appends a highlighted
    /// two-line type diff after each type-change finding.  Set from the
    /// `--diff-types` CLI flag.  Has no effect on JSON or Markdown output.
    pub diff_types: bool,
    /// Whether color is enabled for this report's text rendering.
    ///
    /// Mirrors the process-wide color decision made by `main` and stored here
    /// so [`Self::generate_summary_text`] can pass the right value to
    /// [`crate::type_diff::render_type_diff`] without accessing global state.
    pub use_color: bool,
}

/// Severity counts, serialized as a nested `counts` object.
#[derive(Serialize, JsonSchema)]
pub struct SeverityCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

/// A machine-readable view of a [`SafetyReport`] for `--format json`.
///
/// Borrows from the owning report. Categories are stored in a [`BTreeMap`]
/// so the emitted JSON has a stable, diffable key order.
#[derive(Serialize, JsonSchema)]
pub struct SafetyReportJson<'a> {
    pub is_safe: bool,
    pub strict: bool,
    /// One-sentence bounded claim describing what this verdict certifies.
    /// Machine consumers should not equate `is_safe` with storage compatibility.
    pub certifies: String,
    /// Structured coverage: which analysis dimensions actually ran.
    pub scope: ScopeJson,
    pub counts: SeverityCounts,
    /// Findings (of any severity) acknowledged by the suppression config.
    pub suppressed_count: usize,
    /// Findings hidden by category filtering.
    pub filtered_count: usize,
    /// Findings whose severity a `[severity]` config override changed. Each one
    /// also carries its pre-override `original_severity`.
    pub severity_overridden_count: usize,
    /// Whether the verdict differs from what it would have been without the
    /// `[severity]` overrides. A machine consumer treating `is_safe` as a gate
    /// should surface this rather than pass silently.
    pub verdict_changed_by_override: bool,
    pub total_findings: usize,
    pub recommended_bump: &'static str,
    pub baseline_source: Option<&'a str>,
    pub verified_code_hash: Option<&'a str>,
    pub findings_by_category: BTreeMap<&'a str, &'a Vec<ReportedFinding>>,
    /// Build size and interface-count metrics (always present in CLI output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<&'a BuildMetrics>,
    /// Suppression rules from the config that matched no finding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unmatched_suppressions: Vec<UnmatchedSuppressionJson>,
    /// This tool's version, so a later run can detect an incompatible
    /// baseline before comparing against this report via `--baseline`.
    pub tool_version: &'static str,
    /// Present when `--baseline` was supplied: classifies this run's
    /// findings as new/persisting relative to it, and lists resolved ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_diff: Option<&'a crate::baseline::BaselineDiff>,
}

/// JSON representation of a suppression rule that matched no finding.
#[derive(Serialize, JsonSchema)]
pub struct UnmatchedSuppressionJson {
    pub category: String,
    pub target: Option<String>,
}

impl SafetyReport {
    pub fn new(diff: &DiffReport) -> Self {
        Self::with_suppressions(
            diff,
            &SuppressionConfig::default(),
            false,
            false,
            &ResourcePolicy::default(),
        )
    }

    /// Compute a safety report, applying a suppression config.
    ///
    /// Every finding is still listed; those matched by a rule are flagged as
    /// suppressed and excluded from the failing set. `is_safe` is therefore
    /// true when no *unsuppressed* Critical finding remains — a deliberately
    /// acknowledged breaking change no longer fails the run.
    pub fn with_suppressions(
        diff: &DiffReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
        policy: &ResourcePolicy,
    ) -> Self {
        let _ = policy;

        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut suppressed_count = 0;
        let mut suppressed_critical_count = 0;
        let mut failing_critical_count = 0;
        let mut failing_warning_count = 0;
        // The same failing tallies computed from the engine's own severities,
        // used only to detect a verdict that flipped because of an override.
        let mut engine_failing_critical_count = 0;
        let mut engine_failing_warning_count = 0;
        let mut severity_overridden_count = 0;
        let mut findings_by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();

        // Track which rule indices actually matched at least one finding.
        let mut matched_rule_indices: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        let overrides = &suppressions.severity_overrides;

        for finding in &diff.findings {
            // Policy is applied here, in the report layer, alongside suppression
            // — the diff layer stays a pure description of what changed.
            let engine_severity = finding.severity.clone();
            let severity = overrides
                .severity_for(&finding.category)
                .unwrap_or_else(|| engine_severity.clone());
            let overridden = severity != engine_severity;
            if overridden {
                severity_overridden_count += 1;
            }

            match severity {
                Severity::Critical => critical_count += 1,
                Severity::Warning => warning_count += 1,
                Severity::Info => info_count += 1,
            }

            // Suppression matches on category, target, and fingerprint — never
            // on severity — so an override can never move a finding out from
            // under an existing suppression rule.
            let rule = suppressions.matching_rule_with_index(finding);
            let suppressed = rule.is_some();
            if suppressed {
                suppressed_count += 1;
                if severity == Severity::Critical {
                    suppressed_critical_count += 1;
                }
            } else {
                match severity {
                    Severity::Critical => failing_critical_count += 1,
                    Severity::Warning => failing_warning_count += 1,
                    _ => {}
                }
                match engine_severity {
                    Severity::Critical => engine_failing_critical_count += 1,
                    Severity::Warning => engine_failing_warning_count += 1,
                    _ => {}
                }
            }

            // Record which rule index matched (if any).
            if let Some((idx, _)) = rule {
                matched_rule_indices.insert(idx);
            }

            let rule_ref = rule.map(|(_, r)| r);

            let rule_id = canonical_rule_id(&finding.category)
                .unwrap_or(finding.category.as_str())
                .to_string();
            let remediation = if explain {
                get_remediation_guidance(&rule_id).map(String::from)
            } else {
                None
            };

            // The fingerprint covers category, target, and message — not
            // severity — so overriding a category does not invalidate the
            // fingerprints in an existing suppression config.
            let fingerprint = crate::suppression::compute_fingerprint(finding);
            let mut effective_finding = finding.clone();
            effective_finding.severity = severity;
            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(ReportedFinding {
                    rule_id,
                    finding: effective_finding,
                    fingerprint,
                    suppressed,
                    suppression_reason: rule_ref.and_then(|r| r.reason.clone()),
                    suppression_author: rule_ref.and_then(|r| r.author.clone()),
                    suppression_expiry: rule_ref.and_then(|r| r.expiry.clone()),
                    suppression_fingerprint: rule_ref.and_then(|r| r.fingerprint.clone()),
                    remediation,
                    original_severity: overridden.then_some(engine_severity),
                    baseline_status: None,
                });
        }

        // Build the list of suppression rules that never matched any finding.
        let unmatched_suppressions: Vec<crate::suppression::SuppressionRule> = suppressions
            .rules
            .iter()
            .enumerate()
            .filter(|(idx, _)| !matched_rule_indices.contains(idx))
            .map(|(_, r)| r.clone())
            .collect();

        let verdict = |critical: usize, warning: usize| {
            if strict {
                critical == 0 && warning == 0
            } else {
                critical == 0
            }
        };
        let is_safe = verdict(failing_critical_count, failing_warning_count);
        // A demotion that turns a failing gate green is the one outcome a reader
        // must never miss, so the difference is computed here and stated in the
        // report rather than left for the user to infer.
        let verdict_changed_by_override =
            is_safe != verdict(engine_failing_critical_count, engine_failing_warning_count);

        let settings = ReportSettings {
            strict,
            explain,
            max_suppressions: suppressions.max_suppressions,
            allow_targetless: suppressions.allow_targetless,
            max_xdr_depth: policy.max_xdr_depth,
            max_xdr_len: policy.max_xdr_len,
            max_entries: policy.max_entries,
            max_walk_depth: policy.max_walk_depth,
        };

        Self {
            critical_count,
            warning_count,
            info_count,
            suppressed_count,
            filtered_count: 0,
            severity_overridden_count,
            verdict_changed_by_override,
            suppressed_critical_count,
            total_findings: diff.findings.len(),
            is_safe,
            findings_by_category,
            strict,
            settings,
            baseline_source: None,
            verified_code_hash: None,
            category_filter: CategoryFilter::default(),
            scope: AnalysisScope::default(),
            old_spec_summary: None,
            new_spec_summary: None,
            metrics: None,
            unmatched_suppressions,
            baseline_diff: None,
            diff_types: false,
            use_color: false,
        }
    }

    /// The passing status label, widened only as far as the analysis actually
    /// went. Without a storage schema the claim stays bounded to the exported
    /// interface; with one it may also speak to the declared storage types.
    pub fn passed_status_label(&self) -> &'static str {
        if self.scope.storage_analyzed() {
            "✅ PASSED (No exported-interface or declared-storage breaks)"
        } else {
            "✅ PASSED (No exported-interface breaking changes)"
        }
    }

    /// The failing status label, naming the scopes a break could have come from.
    pub fn failed_status_label(&self) -> &'static str {
        if self.scope.storage_analyzed() {
            "❌ FAILED (Breaking changes detected in the exported interface or declared storage)"
        } else {
            "❌ FAILED (Exported-interface breaking changes detected)"
        }
    }

    /// The sentence stating that a `[severity]` override changed the verdict,
    /// or `None` when it did not.
    ///
    /// A tool that can be quietly reconfigured into always passing is worse than
    /// no tool, so this is the one line that must appear, unhedged, in every
    /// format whenever configuration — not analysis — decided the outcome.
    pub fn override_verdict_notice(&self) -> Option<String> {
        if !self.verdict_changed_by_override {
            return None;
        }
        Some(if self.is_safe {
            "VERDICT CHANGED BY CONFIG: this run passes only because the [severity] table \
             lowered one or more findings. Without those overrides it would have FAILED."
                .to_string()
        } else {
            "VERDICT CHANGED BY CONFIG: this run fails only because the [severity] table \
             raised one or more findings. Without those overrides it would have PASSED."
                .to_string()
        })
    }

    /// The override notice rendered for text output, empty when not applicable.
    fn override_verdict_notice_text(&self) -> String {
        match self.override_verdict_notice() {
            // Red rather than dimmed: a demotion that greens a failing gate is
            // the case this line exists to make impossible to skim past.
            Some(notice) => format!("{}\n", format!("⚠️  {notice}").red().bold()),
            None => String::new(),
        }
    }

    /// The `[SEVERITY: critical → warning]` tag for a finding whose severity an
    /// override changed, or an empty string when it was left alone.
    fn override_tag(reported: &ReportedFinding) -> String {
        match &reported.original_severity {
            Some(original) => format!(
                "[SEVERITY {} → {}] ",
                original.label(),
                reported.finding.severity.label()
            ),
            None => String::new(),
        }
    }

    /// Attach an [`AnalysisScope`] describing what this run inspected.
    ///
    /// Consuming builder so a caller can widen the reported scope (for example
    /// the CLI, which compares environment metadata, or a schema-backed run that
    /// analyzed declared storage types) without the report ever overstating it.
    pub fn with_scope(mut self, scope: AnalysisScope) -> Self {
        self.scope = scope;
        self
    }

    /// Derive the recommended SemVer bump from safety report findings:
    /// - `Critical` findings present -> `major` (breaking interface or storage changes).
    /// - `Warning` findings present -> `minor` (we map warnings like `Parameter Renamed`
    ///   or `Struct Field Added` explicitly to `minor` because they represent changes
    ///   that are not strictly breaking for all contexts, but require caller adjustments
    ///   or data migrations).
    /// - `Info` findings present -> `minor` (additive, non-breaking changes).
    /// - No findings -> `patch` (identical interface).
    pub fn recommended_bump(&self) -> &'static str {
        if self.critical_count > 0 {
            "major"
        } else if self.warning_count > 0 || self.info_count > 0 {
            "minor"
        } else {
            "patch"
        }
    }

    /// Build a serializable, machine-readable view of this report.
    pub fn to_json(&self) -> SafetyReportJson<'_> {
        let unmatched_suppressions = self
            .unmatched_suppressions
            .iter()
            .map(|r| UnmatchedSuppressionJson {
                category: r.rule_id.clone(),
                target: r.target.clone(),
            })
            .collect();
        SafetyReportJson {
            is_safe: self.is_safe,
            strict: self.strict,
            certifies: self.scope.summary_line(),
            scope: self.scope.to_json(),
            counts: SeverityCounts {
                critical: self.critical_count,
                warning: self.warning_count,
                info: self.info_count,
            },
            suppressed_count: self.suppressed_count,
            filtered_count: self.filtered_count,
            severity_overridden_count: self.severity_overridden_count,
            verdict_changed_by_override: self.verdict_changed_by_override,
            total_findings: self.total_findings,
            recommended_bump: self.recommended_bump(),
            baseline_source: self.baseline_source.as_deref(),
            verified_code_hash: self.verified_code_hash.as_deref(),
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
            metrics: self.metrics.as_ref(),
            unmatched_suppressions,
            tool_version: env!("CARGO_PKG_VERSION"),
            baseline_diff: self.baseline_diff.as_ref(),
        }
    }

    /// Generate a structured, human-readable text output for the CLI.
    fn categories_sorted_by_severity(&self) -> Vec<&String> {
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort_by(|a, b| {
            let rank = |name: &str| {
                let findings = self.findings_by_category.get(name).unwrap();
                if findings
                    .iter()
                    .any(|r| r.finding.severity == Severity::Critical)
                {
                    0
                } else if findings
                    .iter()
                    .any(|r| r.finding.severity == Severity::Warning)
                {
                    1
                } else {
                    2
                }
            };
            rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
        });
        categories
    }

    pub fn generate_summary_text(&self, explain: bool) -> String {
        let mut output = String::new();
        output.push_str(
            &"\n========================================\n"
                .bold()
                .to_string(),
        );
        output.push_str(
            &"    SOROBAN UPGRADE SAFETY REPORT\n"
                .bold()
                .cyan()
                .to_string(),
        );
        if self.strict {
            output.push_str(&"    [STRICT MODE ACTIVE]\n".bold().yellow().to_string());
        }
        output.push_str(
            &"========================================\n"
                .bold()
                .to_string(),
        );

        let status = if self.is_safe {
            self.passed_status_label().green().bold()
        } else if self.strict && self.critical_count == 0 {
            "❌ FAILED (Warnings detected in strict mode)".red().bold()
        } else {
            self.failed_status_label().red().bold()
        };
        output.push_str(&format!("Status: {}\n", status));
        output.push_str(&format!("Scope:  {}\n", self.scope.summary_line().dimmed()));
        let storage_status = self.scope.storage_status_line();
        let storage_status = if self.scope.storage_analyzed() {
            storage_status.dimmed()
        } else {
            // No schema: make the "not analyzed" gap visible rather than dim.
            storage_status.yellow()
        };
        output.push_str(&format!("        {}\n", storage_status));

        // Spec-section integrity summary (non-zero section count or duplicates).
        if self.scope.old_spec_section_count > 1 || self.scope.new_spec_section_count > 1 {
            output.push_str(
                &format!(
                    "        Spec sections: old={}, new={} (multi-section WASMs detected)\n",
                    self.scope.old_spec_section_count, self.scope.new_spec_section_count,
                )
                .yellow()
                .to_string(),
            );
        }
        let all_dups: Vec<String> = self
            .scope
            .old_duplicate_names
            .iter()
            .map(|n| format!("old:{n}"))
            .chain(
                self.scope
                    .new_duplicate_names
                    .iter()
                    .map(|n| format!("new:{n}")),
            )
            .collect();
        if !all_dups.is_empty() {
            output.push_str(
                &format!(
                    "        Duplicate entries detected: {}\n",
                    all_dups.join(", ")
                )
                .red()
                .bold()
                .to_string(),
            );
        }

        let crit_str = if self.critical_count > 0 {
            self.critical_count.to_string().red().bold()
        } else {
            self.critical_count.to_string().green()
        };
        let warn_str = if self.warning_count > 0 {
            self.warning_count.to_string().yellow().bold()
        } else {
            self.warning_count.to_string().normal()
        };
        let info_str = self.info_count.to_string().blue();

        output.push_str(&format!("Critical: {}\n", crit_str));
        output.push_str(&format!("Warnings: {}\n", warn_str));
        output.push_str(&format!("Info:     {}\n", info_str));
        if self.suppressed_count > 0 {
            output.push_str(&format!(
                "Suppressed: {}\n",
                self.suppressed_count.to_string().magenta().bold()
            ));
        }
        if self.filtered_count > 0 {
            output.push_str(&format!(
                "Filtered:   {}\n",
                self.filtered_count.to_string().yellow().bold()
            ));
            output.push_str(&format!(
                "{}",
                "  ↳ Findings were hidden by --include-category/--exclude-category.\n"
                    .yellow()
                    .dimmed()
            ));
        }
        if self.severity_overridden_count > 0 {
            output.push_str(&format!(
                "Overridden: {}\n",
                self.severity_overridden_count.to_string().magenta().bold()
            ));
            output.push_str(&format!(
                "{}",
                "  ↳ Severities were changed by the [severity] table in the config.\n"
                    .magenta()
                    .dimmed()
            ));
        }
        output.push_str(&self.override_verdict_notice_text());
        let bump = self.recommended_bump();
        let bump_str = match bump {
            "major" => "major".red().bold(),
            "minor" => "minor".yellow().bold(),
            "patch" => "patch".green().bold(),
            _ => bump.normal(),
        };
        output.push_str(&format!("Recommended Bump: {}\n", bump_str));

        if let Some(source) = &self.baseline_source {
            output.push_str(&format!("Baseline Source: {}\n", source));
        }
        if let Some(hash) = &self.verified_code_hash {
            output.push_str(&format!("Verified Code Hash: {}\n", hash.dimmed()));
        }
        if let Some(bd) = &self.baseline_diff {
            output.push_str(&format!(
                "Baseline: {} new, {} persisting, {} resolved (vs. tool v{}){}\n",
                bd.new_count.to_string().bold(),
                bd.persisting_count,
                bd.resolved.len(),
                bd.baseline_tool_version,
                if bd.fail_on_new_only {
                    " — verdict reflects new findings only"
                } else {
                    ""
                },
            ));
        }

        output.push_str(
            &"----------------------------------------\n\n"
                .dimmed()
                .to_string(),
        );

        if self.total_findings == 0 {
            output.push_str(&"No relevant changes detected. The exported interface is identical in its exports and types.\n".green().to_string());
            output.push_str(&format!("\n{}\n", STORAGE_NOT_VERIFIED_NOTE.dimmed()));
            self.append_metrics_text(&mut output);
            return output;
        }

        let categories = self.categories_sorted_by_severity();

        for category in categories {
            output.push_str(
                &format!("--- [{}] ---\n", category.to_ascii_uppercase())
                    .magenta()
                    .bold()
                    .to_string(),
            );
            let mut group = self.findings_by_category.get(category).unwrap().clone();
            group.sort_by(|a, b| a.finding.message.cmp(&b.finding.message));
            for reported in &group {
                let finding = &reported.finding;

                let override_tag = Self::override_tag(reported);

                if reported.suppressed {
                    // Suppressed findings are still listed, but clearly marked
                    // and dimmed so they read as acknowledged, not active.
                    let label = format!("🔕 [SUPPRESSED] {override_tag}{}", finding.message)
                        .dimmed()
                        .to_string();
                    output.push_str(&format!("{}\n", label));
                    if let Some(reason) = &reported.suppression_reason {
                        output
                            .push_str(&format!("    ↳ reason: {}\n", reason).dimmed().to_string());
                    }
                    if explain {
                        if let Some(remediation) = &reported.remediation {
                            output.push_str(
                                &format!("    ↳ guidance: {}\n", remediation)
                                    .dimmed()
                                    .to_string(),
                            );
                        }
                    }
                    continue;
                }

                let baseline_tag = match reported.baseline_status {
                    Some(crate::baseline::BaselineStatus::New) => "[NEW] ",
                    _ => "",
                };
                let body = format!("{baseline_tag}{override_tag}{}", finding.message);
                let formatted = match finding.severity {
                    Severity::Critical => format!("🔴 {body}").red(),
                    Severity::Warning => format!("🟡 {body}").yellow(),
                    Severity::Info => format!("🔵 {body}").cyan(),
                };
                output.push_str(&format!("{}\n", formatted));
                if explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(
                            &format!("    ↳ guidance: {}\n", remediation)
                                .green()
                                .to_string(),
                        );
                    }
                }
                if self.diff_types && crate::type_diff::is_type_change_category(&finding.category) {
                    if let Some((old_ty, new_ty)) =
                        crate::type_diff::extract_type_pair(&finding.message)
                    {
                        output.push_str(&crate::type_diff::render_type_diff(
                            &old_ty,
                            &new_ty,
                            self.use_color,
                        ));
                    }
                }
            }
            output.push('\n');
        }

        if let Some(bd) = &self.baseline_diff {
            if !bd.resolved.is_empty() {
                output.push_str(&"✅ RESOLVED SINCE BASELINE\n".green().bold().to_string());
                for r in &bd.resolved {
                    output.push_str(&format!("{}\n", r.message).green().to_string());
                }
                output.push('\n');
            }
        }

        if !self.is_safe {
            if self.strict && self.critical_count == 0 {
                output.push_str(
                    &"⚠️  ACTION REQUIRED: Strict mode is active and warnings were detected.\n"
                        .yellow()
                        .bold()
                        .to_string(),
                );
                output.push_str(
                    &"These warnings must be resolved or strict mode disabled to proceed.\n"
                        .yellow()
                        .to_string(),
                );
            } else {
                output.push_str(&"⚠️  ACTION REQUIRED: The new contract version modifies existing storage layouts or function interfaces.\n".red().bold().to_string());
                output.push_str(&"Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n".red().to_string());
            }
        }

        let mut suppressed_list = Vec::new();
        for group in self.findings_by_category.values() {
            for reported in group {
                if reported.suppressed {
                    suppressed_list.push(reported);
                }
            }
        }

        if !suppressed_list.is_empty() {
            output.push_str(
                &"\n========================================\n"
                    .bold()
                    .to_string(),
            );
            output.push_str(
                &"🔕 APPLIED SUPPRESSIONS AUDIT LOG\n"
                    .bold()
                    .magenta()
                    .to_string(),
            );
            output.push_str(
                &"========================================\n"
                    .bold()
                    .to_string(),
            );
            for reported in suppressed_list {
                let f = &reported.finding;
                let target_str = f.target.as_deref().unwrap_or("<no target>");
                output.push_str(&format!(
                    " - Category:    {}\n   Target:      {}\n",
                    f.category, target_str
                ));
                if let Some(fp) = &reported.suppression_fingerprint {
                    output.push_str(&format!("   Fingerprint: {}\n", fp));
                }
                if let Some(author) = &reported.suppression_author {
                    let expiry_str = reported.suppression_expiry.as_deref().unwrap_or("never");
                    output.push_str(&format!(
                        "   Author:      {} (expires {})\n",
                        author, expiry_str
                    ));
                }
                if let Some(reason) = &reported.suppression_reason {
                    output.push_str(&format!("   Reason:      {}\n", reason));
                }
                output.push('\n');
            }
        }

        self.append_metrics_text(&mut output);

        output
    }

    /// Append the informational build-metrics block to text output.
    fn append_metrics_text(&self, output: &mut String) {
        if let Some(ref m) = self.metrics {
            output.push_str(
                &"\n========================================\n"
                    .bold()
                    .to_string(),
            );
            output.push_str(&"📊 BUILD METRICS\n".bold().cyan().to_string());
            output.push_str(
                &"========================================\n"
                    .bold()
                    .to_string(),
            );
            output.push_str(&format!(
                "WASM size:  {} → {} ({})\n",
                BuildMetrics::format_bytes(m.old_size_bytes),
                BuildMetrics::format_bytes(m.new_size_bytes),
                BuildMetrics::format_delta(m.size_delta_bytes),
            ));
            output.push_str(&format!(
                "Functions:  {} → {}\n",
                m.old_function_count, m.new_function_count
            ));
            output.push_str(&format!(
                "Structs:    {} → {}\n",
                m.old_struct_count, m.new_struct_count
            ));
            output.push_str(&format!(
                "Enums:      {} → {}\n",
                m.old_enum_count, m.new_enum_count
            ));
            output.push_str(&format!(
                "Unions:     {} → {}\n",
                m.old_union_count, m.new_union_count
            ));
            output.push_str(&format!(
                "Error Enums:{} → {}\n",
                m.old_error_enum_count, m.new_error_enum_count
            ));
        }
    }

    /// Generate a structured Markdown output.
    pub fn generate_summary_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str("# Soroban Upgrade Safety Report\n\n");

        if self.strict {
            output
                .push_str("> ⚠️ **[STRICT MODE ACTIVE]** — Warnings are treated as failures.\n\n");
        }

        let status = if self.is_safe {
            self.passed_status_label()
        } else if self.strict && self.critical_count == 0 {
            "❌ FAILED (Warnings detected in strict mode)"
        } else {
            self.failed_status_label()
        };
        output.push_str(&format!("## Status: {}\n\n", status));
        output.push_str(&format!("_{}_\n\n", self.scope.summary_line()));
        output.push_str(&format!(
            "**Scope:** {}\n\n",
            self.scope.storage_status_line()
        ));

        // Spec-section integrity (multi-section or duplicates).
        if self.scope.old_spec_section_count > 1 || self.scope.new_spec_section_count > 1 {
            output.push_str(&format!(
                "> ⚠️ Multi-section WASM detected: old has {} contractspecv0 section(s), new has {}.\n\n",
                self.scope.old_spec_section_count,
                self.scope.new_spec_section_count,
            ));
        }
        let all_dups: Vec<String> = self
            .scope
            .old_duplicate_names
            .iter()
            .map(|n| format!("`old:{n}`"))
            .chain(
                self.scope
                    .new_duplicate_names
                    .iter()
                    .map(|n| format!("`new:{n}`")),
            )
            .collect();
        if !all_dups.is_empty() {
            output.push_str(&format!(
                "> ❌ Duplicate spec entries detected: {}\n\n",
                all_dups.join(", ")
            ));
        }

        output.push_str("### Summary Table\n\n");
        output.push_str("| Finding Severity | Count |\n");
        output.push_str("| :--- | :--- |\n");
        output.push_str(&format!("| **Critical** | {} |\n", self.critical_count));
        output.push_str(&format!("| **Warning** | {} |\n", self.warning_count));
        output.push_str(&format!("| **Info** | {} |\n", self.info_count));
        if self.suppressed_count > 0 {
            output.push_str(&format!("| **Suppressed** | {} |\n", self.suppressed_count));
        }
        if self.filtered_count > 0 {
            output.push_str(&format!("| **Filtered** | {} |\n", self.filtered_count));
            output.push_str("\n> ⚠️  Findings were hidden by `--include-category`/`--exclude-category`. The verdict reflects the remaining visible findings only.\n\n");
        }
        if self.severity_overridden_count > 0 {
            output.push_str(&format!(
                "| **Severity overridden** | {} |\n",
                self.severity_overridden_count
            ));
        }
        if let Some(notice) = self.override_verdict_notice() {
            output.push_str(&format!("\n> ⚠️ **{}**\n\n", notice));
        }
        output.push_str(&format!(
            "\n**Recommended SemVer Bump**: `{}`\n\n",
            self.recommended_bump()
        ));

        if let Some(source) = &self.baseline_source {
            output.push_str(&format!("**Baseline Source**: `{}`\n\n", source));
        }
        if let Some(hash) = &self.verified_code_hash {
            output.push_str(&format!("**Verified Code Hash**: `{}`\n\n", hash));
        }
        if let Some(bd) = &self.baseline_diff {
            output.push_str(&format!(
                "**Baseline**: {} new, {} persisting, {} resolved (vs. tool v{}){}\n\n",
                bd.new_count,
                bd.persisting_count,
                bd.resolved.len(),
                bd.baseline_tool_version,
                if bd.fail_on_new_only {
                    " — verdict reflects new findings only"
                } else {
                    ""
                },
            ));
        }

        output.push_str("---\n\n");

        if self.total_findings == 0 {
            output.push_str("No relevant changes detected. The exported interface is identical in its exports and types.\n\n");
            output.push_str(&format!("> {}\n", STORAGE_NOT_VERIFIED_NOTE));
            self.append_metrics_markdown(&mut output);
            return output;
        }

        let categories = self.categories_sorted_by_severity();

        for category in categories {
            output.push_str(&format!("### {}\n\n", category));
            let mut group = self.findings_by_category.get(category).unwrap().clone();
            group.sort_by(|a, b| a.finding.message.cmp(&b.finding.message));
            for reported in &group {
                let finding = &reported.finding;

                let override_tag = match &reported.original_severity {
                    Some(original) => format!(
                        "**[SEVERITY {} → {}]** ",
                        original.label(),
                        finding.severity.label()
                    ),
                    None => String::new(),
                };

                if reported.suppressed {
                    output.push_str(&format!(
                        "- 🔕 **[SUPPRESSED]** {override_tag}{}\n",
                        finding.message
                    ));
                    if let Some(reason) = &reported.suppression_reason {
                        output.push_str(&format!("  - ↳ reason: {}\n", reason));
                    }
                    if self.settings.explain {
                        if let Some(remediation) = &reported.remediation {
                            output.push_str(&format!("  - ↳ guidance: {}\n", remediation));
                        }
                    }
                    continue;
                }

                let emoji = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::Warning => "🟡",
                    Severity::Info => "🔵",
                };
                let baseline_tag = match reported.baseline_status {
                    Some(crate::baseline::BaselineStatus::New) => "**[NEW]** ",
                    _ => "",
                };
                output.push_str(&format!(
                    "- {} {}{}{}\n",
                    emoji, baseline_tag, override_tag, finding.message
                ));
                if self.settings.explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(&format!("  - ↳ guidance: {}\n", remediation));
                    }
                }
            }
            output.push('\n');
        }

        if let Some(bd) = &self.baseline_diff {
            if !bd.resolved.is_empty() {
                output.push_str("### ✅ Resolved Since Baseline\n\n");
                for r in &bd.resolved {
                    output.push_str(&format!("- {}\n", r.message));
                }
                output.push('\n');
            }
        }

        if !self.is_safe {
            output.push_str("### ⚠️ Action Required\n\n");
            output.push_str("- The new contract version modifies existing storage layouts or function interfaces.\n");
            output.push_str("- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n");
        }

        let mut suppressed_list = Vec::new();
        for group in self.findings_by_category.values() {
            for reported in group {
                if reported.suppressed {
                    suppressed_list.push(reported);
                }
            }
        }

        if !suppressed_list.is_empty() {
            output.push_str("### 🔕 Applied Suppressions Audit Log\n\n");
            output.push_str("| Category | Target | Fingerprint | Author | Expiry | Reason |\n");
            output.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for reported in suppressed_list {
                let f = &reported.finding;
                let category = &f.category;
                let target = f.target.as_deref().unwrap_or("-");
                let fingerprint = reported.suppression_fingerprint.as_deref().unwrap_or("-");
                let author = reported.suppression_author.as_deref().unwrap_or("-");
                let expiry = reported.suppression_expiry.as_deref().unwrap_or("-");
                let reason = reported.suppression_reason.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "| {} | `{}` | `{}` | {} | {} | {} |\n",
                    category, target, fingerprint, author, expiry, reason
                ));
            }
            output.push_str("\n---\n\n");
        }

        self.append_metrics_markdown(&mut output);

        output
    }

    /// Generate GitHub Actions workflow command output.
    ///
    /// Emits one [workflow command] per non-suppressed finding, levelled to
    /// match the finding's severity:
    ///
    /// - `Critical` → `::error`
    /// - `Warning`  → `::warning`
    /// - `Info`     → `::notice`
    ///
    /// Suppressed findings are emitted as `::notice` (not at their original
    /// severity) so they appear in the log without blocking the run.
    ///
    /// A short human-readable summary follows the annotations so the log is
    /// still useful when read directly.
    ///
    /// [workflow command]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions
    pub fn generate_summary_github_actions(&self, group_title: Option<&str>) -> String {
        let mut output = String::new();

        // Optional log grouping (used in batch mode to separate contract pairs).
        if let Some(title) = group_title {
            output.push_str(&format!("::group::{}\n", title));
        }

        // Sort categories for deterministic output.
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort();

        for category in categories {
            let group = self.findings_by_category.get(category).unwrap();
            for reported in group {
                let finding = &reported.finding;
                let override_tag = Self::override_tag(reported);
                let text = format!("[{}] {override_tag}{}", finding.category, finding.message);

                if reported.suppressed {
                    // Suppressed findings are demoted to notice so they are
                    // visible in the run summary without failing the check.
                    output.push_str(&format!("::notice::{}\n", text));
                } else {
                    let level = match finding.severity {
                        Severity::Critical => "error",
                        Severity::Warning => "warning",
                        Severity::Info => "notice",
                    };
                    output.push_str(&format!("::{level}::{text}\n"));
                }
            }
        }

        // Human-readable summary after the annotations.
        let status = if self.is_safe { "PASSED" } else { "FAILED" };
        output.push_str(&format!(
            "\nSoroban Upgrade Safeguard: {} — {} critical, {} warning(s), {} info ({} suppressed, {} severity-overridden)\n",
            status,
            self.critical_count,
            self.warning_count,
            self.info_count,
            self.suppressed_count,
            self.severity_overridden_count,
        ));

        // A configured verdict is escalated to a warning annotation so it shows
        // up in the checks UI, not just buried in the log body.
        if let Some(notice) = self.override_verdict_notice() {
            output.push_str(&format!("::warning::{}\n", notice));
        }

        if group_title.is_some() {
            output.push_str("::endgroup::\n");
        }

        output
    }

    /// Generate a single JUnit `<testsuite>` element for this report.
    ///
    /// Each finding becomes one `<testcase>`, named by its category and target,
    /// so a CI system's existing test-report UI renders a breaking change as a
    /// failing test rather than as text buried in a log.
    ///
    /// Status mapping:
    ///
    /// - `Critical` → `<failure>`.
    /// - `Warning`  → `<failure>` under `--strict`, otherwise a passing case.
    /// - `Info`     → a passing case.
    /// - Suppressed → `<skipped>` carrying the suppression reason, at any
    ///   severity. A skipped case reads as *acknowledged* in every CI UI, which
    ///   is exactly what a suppression is; it is never reported as a failure.
    ///
    /// `suite_name` names the suite (the contract name in batch mode). A report
    /// with no findings still emits one passing case so the suite is never empty
    /// — an empty suite renders as "no tests ran", which reads as a broken job
    /// rather than as a clean upgrade.
    pub fn generate_summary_junit(&self, suite_name: Option<&str>) -> String {
        let suite = suite_name.unwrap_or("soroban-upgrade-safeguard");
        let classname = format!("soroban-upgrade-safeguard.{}", suite);

        // Sort categories for deterministic output.
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort();

        let mut cases = String::new();
        let (mut tests, mut failures, mut skipped) = (0usize, 0usize, 0usize);

        for category in categories {
            for reported in self.findings_by_category.get(category).unwrap() {
                let finding = &reported.finding;
                tests += 1;

                let case_name = match finding.target.as_deref() {
                    Some(target) if !target.is_empty() => {
                        format!("{}: {}", finding.category, target)
                    }
                    _ => finding.category.clone(),
                };

                cases.push_str(&format!(
                    "    <testcase classname=\"{}\" name=\"{}\"",
                    escape_xml(&classname),
                    escape_xml(&case_name),
                ));

                if reported.suppressed {
                    skipped += 1;
                    let reason = reported
                        .suppression_reason
                        .as_deref()
                        .unwrap_or("acknowledged by a suppression rule");
                    cases.push_str(&format!(
                        ">\n      <skipped message=\"{}\"/>\n    </testcase>\n",
                        escape_xml(reason),
                    ));
                    continue;
                }

                let fails = match finding.severity {
                    Severity::Critical => true,
                    Severity::Warning => self.strict,
                    Severity::Info => false,
                };

                if fails {
                    failures += 1;
                    cases.push_str(&format!(
                        ">\n      <failure type=\"{}\" message=\"{}\">{}</failure>\n    </testcase>\n",
                        escape_xml(finding.severity.label()),
                        escape_xml(&finding.message),
                        escape_xml(&Self::junit_case_body(reported)),
                    ));
                } else {
                    // A passing case still carries the message so a reader who
                    // opens it sees what the tool actually observed.
                    cases.push_str(&format!(
                        ">\n      <system-out>{}</system-out>\n    </testcase>\n",
                        escape_xml(&Self::junit_case_body(reported)),
                    ));
                }
            }
        }

        if tests == 0 {
            tests = 1;
            cases.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"no breaking changes detected\"/>\n",
                escape_xml(&classname),
            ));
        }

        format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"{}\">\n\
             {}  </testsuite>\n",
            escape_xml(suite),
            tests,
            failures,
            skipped,
            cases,
        )
    }

    /// The body text of a JUnit `<testcase>`: the finding's message plus the
    /// stable rule id and any severity-override or remediation context.
    fn junit_case_body(reported: &ReportedFinding) -> String {
        let mut body = format!(
            "[{}] {}\nrule_id: {}\nfingerprint: {}",
            reported.finding.severity.label(),
            reported.finding.message,
            reported.rule_id,
            reported.fingerprint,
        );
        if let Some(ref original) = reported.original_severity {
            body.push_str(&format!(
                "\nseverity overridden: {} -> {}",
                original.label(),
                reported.finding.severity.label(),
            ));
        }
        if let Some(ref remediation) = reported.remediation {
            body.push_str(&format!("\nremediation: {}", remediation));
        }
        body
    }

    /// Append the informational build-metrics table to Markdown output.
    fn append_metrics_markdown(&self, output: &mut String) {
        if let Some(ref m) = self.metrics {
            output.push_str("## 📊 Build Metrics\n\n");
            output.push_str("| Metric | Old | New | Delta |\n");
            output.push_str("| :--- | ---: | ---: | ---: |\n");
            output.push_str(&format!(
                "| **WASM size** | {} | {} | {} |\n",
                BuildMetrics::format_bytes(m.old_size_bytes),
                BuildMetrics::format_bytes(m.new_size_bytes),
                BuildMetrics::format_delta(m.size_delta_bytes),
            ));
            let delta_fn = m.new_function_count as i64 - m.old_function_count as i64;
            let delta_struct = m.new_struct_count as i64 - m.old_struct_count as i64;
            let delta_enum = m.new_enum_count as i64 - m.old_enum_count as i64;
            let delta_union = m.new_union_count as i64 - m.old_union_count as i64;
            let delta_err = m.new_error_enum_count as i64 - m.old_error_enum_count as i64;
            let fmt_count = |d: i64| {
                if d >= 0 {
                    format!("+{}", d)
                } else {
                    format!("{}", d)
                }
            };
            output.push_str(&format!(
                "| **Functions** | {} | {} | {} |\n",
                m.old_function_count,
                m.new_function_count,
                fmt_count(delta_fn)
            ));
            output.push_str(&format!(
                "| **Structs** | {} | {} | {} |\n",
                m.old_struct_count,
                m.new_struct_count,
                fmt_count(delta_struct)
            ));
            output.push_str(&format!(
                "| **Enums** | {} | {} | {} |\n",
                m.old_enum_count,
                m.new_enum_count,
                fmt_count(delta_enum)
            ));
            output.push_str(&format!(
                "| **Unions** | {} | {} | {} |\n",
                m.old_union_count,
                m.new_union_count,
                fmt_count(delta_union)
            ));
            output.push_str(&format!(
                "| **Error Enums** | {} | {} | {} |\n",
                m.old_error_enum_count,
                m.new_error_enum_count,
                fmt_count(delta_err)
            ));
            output.push('\n');
        }
    }

    /// Render this report as a complete, self-contained HTML document.
    ///
    /// Intended for publishing as a build artifact, where the reader never
    /// opens the job log. See [`html_document`] for the offline guarantees.
    pub fn generate_summary_html(&self) -> String {
        html_document(
            "Soroban Upgrade Safety Report",
            &self.html_section(None, true),
        )
    }

    /// Render this report as an HTML fragment, for embedding in a larger
    /// document. Batch mode uses this to put every contract pair in one file.
    ///
    /// `heading`, when given, names the contract pair. `top_level` controls
    /// whether the status uses `<h1>` or `<h2>`, so batch pairs nest correctly
    /// under the batch heading.
    pub fn html_section(&self, heading: Option<&str>, top_level: bool) -> String {
        let mut out = String::new();
        let level = if top_level { 1 } else { 2 };

        out.push_str("<section class=\"report\">\n");
        if let Some(name) = heading {
            out.push_str(&format!(
                "<h{level} class=\"pair-name\">{}</h{level}>\n",
                escape_html(name)
            ));
        }

        // ── Status banner ──────────────────────────────────────────────────
        let (status_class, status_text) = if self.is_safe {
            ("pass", self.passed_status_label())
        } else if self.strict && self.critical_count == 0 {
            ("fail", "❌ FAILED (Warnings detected in strict mode)")
        } else {
            ("fail", self.failed_status_label())
        };
        if heading.is_none() {
            out.push_str(&format!(
                "<h{level} class=\"title\">Soroban Upgrade Safety Report</h{level}>\n"
            ));
        }
        if self.strict {
            out.push_str("<p class=\"banner strict\">⚠️ STRICT MODE ACTIVE — warnings are treated as failures.</p>\n");
        }
        out.push_str(&format!(
            "<p class=\"banner {status_class}\">{}</p>\n",
            escape_html(status_text)
        ));

        // A configured verdict must be as loud here as it is in the terminal.
        if let Some(notice) = self.override_verdict_notice() {
            out.push_str(&format!(
                "<p class=\"banner override-verdict\">⚠️ {}</p>\n",
                escape_html(&notice)
            ));
        }

        // ── Scope ──────────────────────────────────────────────────────────
        out.push_str(&format!(
            "<p class=\"scope\">{}</p>\n",
            escape_html(&self.scope.summary_line())
        ));
        let storage_class = if self.scope.storage_analyzed() {
            "scope"
        } else {
            "scope gap"
        };
        out.push_str(&format!(
            "<p class=\"{storage_class}\">{}</p>\n",
            escape_html(&self.scope.storage_status_line())
        ));

        if self.scope.old_spec_section_count > 1 || self.scope.new_spec_section_count > 1 {
            out.push_str(&format!(
                "<p class=\"banner warn\">⚠️ Multi-section WASM detected: old has {} \
                 contractspecv0 section(s), new has {}.</p>\n",
                self.scope.old_spec_section_count, self.scope.new_spec_section_count,
            ));
        }
        let all_dups: Vec<String> = self
            .scope
            .old_duplicate_names
            .iter()
            .map(|n| format!("old:{n}"))
            .chain(
                self.scope
                    .new_duplicate_names
                    .iter()
                    .map(|n| format!("new:{n}")),
            )
            .collect();
        if !all_dups.is_empty() {
            out.push_str(&format!(
                "<p class=\"banner fail\">❌ Duplicate spec entries detected: {}</p>\n",
                escape_html(&all_dups.join(", "))
            ));
        }

        // ── Counts ─────────────────────────────────────────────────────────
        out.push_str("<ul class=\"stats\">\n");
        out.push_str(&stat_tile("Critical", self.critical_count, "critical"));
        out.push_str(&stat_tile("Warning", self.warning_count, "warning"));
        out.push_str(&stat_tile("Info", self.info_count, "info"));
        if self.suppressed_count > 0 {
            out.push_str(&stat_tile(
                "Suppressed",
                self.suppressed_count,
                "suppressed",
            ));
        }
        if self.filtered_count > 0 {
            out.push_str(&stat_tile("Filtered", self.filtered_count, "filtered"));
        }
        if self.severity_overridden_count > 0 {
            out.push_str(&stat_tile(
                "Severity overridden",
                self.severity_overridden_count,
                "overridden",
            ));
        }
        out.push_str("</ul>\n");

        out.push_str(&format!(
            "<p class=\"meta\">Recommended SemVer bump: <code>{}</code></p>\n",
            self.recommended_bump()
        ));
        if let Some(source) = &self.baseline_source {
            out.push_str(&format!(
                "<p class=\"meta\">Baseline source: <code>{}</code></p>\n",
                escape_html(source)
            ));
        }
        if let Some(hash) = &self.verified_code_hash {
            out.push_str(&format!(
                "<p class=\"meta\">Verified code hash: <code>{}</code></p>\n",
                escape_html(hash)
            ));
        }
        if let Some(bd) = &self.baseline_diff {
            out.push_str(&format!(
                "<p class=\"meta\">Baseline: {} new, {} persisting, {} resolved (vs. tool v{}){}</p>\n",
                bd.new_count,
                bd.persisting_count,
                bd.resolved.len(),
                escape_html(&bd.baseline_tool_version),
                if bd.fail_on_new_only {
                    " — verdict reflects new findings only"
                } else {
                    ""
                },
            ));
        }
        if self.filtered_count > 0 {
            out.push_str(
                "<p class=\"note\">Findings were hidden by --include-category/--exclude-category. \
                 The verdict reflects the remaining visible findings only.</p>\n",
            );
        }

        if self.total_findings == 0 {
            out.push_str(
                "<p class=\"empty\">No relevant changes detected. The exported interface is \
                 identical in its exports and types.</p>\n",
            );
            out.push_str(&format!(
                "<p class=\"note\">{}</p>\n",
                escape_html(STORAGE_NOT_VERIFIED_NOTE)
            ));
            self.append_metrics_html(&mut out);
            out.push_str("</section>\n");
            return out;
        }

        // ── Findings, grouped by category with counts ──────────────────────
        let categories = self.categories_sorted_by_severity();

        for category in categories {
            let mut group = self.findings_by_category.get(category).unwrap().clone();
            group.sort_by(|a, b| a.finding.message.cmp(&b.finding.message));

            // Groups that are entirely informational start collapsed so the
            // critical findings are not buried under them.
            let all_info = group
                .iter()
                .all(|r| r.finding.severity == Severity::Info || r.suppressed);
            let open = if all_info { "" } else { " open" };

            out.push_str(&format!("<details class=\"category\"{open}>\n"));
            out.push_str(&format!(
                "<summary>{} <span class=\"count\">{}</span></summary>\n",
                escape_html(category),
                group.len()
            ));
            out.push_str("<ul class=\"findings\">\n");

            for reported in &group {
                let finding = &reported.finding;
                let sev = finding.severity.label();
                let mut classes = format!("finding sev-{sev}");
                if reported.suppressed {
                    classes.push_str(" suppressed");
                }
                out.push_str(&format!("<li class=\"{classes}\">"));
                out.push_str(&format!("<span class=\"badge badge-{sev}\">{sev}</span> "));
                if reported.suppressed {
                    out.push_str("<span class=\"badge badge-suppressed\">suppressed</span> ");
                }
                if matches!(
                    reported.baseline_status,
                    Some(crate::baseline::BaselineStatus::New)
                ) {
                    out.push_str("<span class=\"badge badge-new\">new</span> ");
                }
                if let Some(original) = &reported.original_severity {
                    out.push_str(&format!(
                        "<span class=\"badge badge-overridden\">severity {} → {}</span> ",
                        original.label(),
                        sev
                    ));
                }
                // Every message is WASM-derived: type and field names come
                // straight out of an untrusted binary, so nothing reaches the
                // page unescaped.
                out.push_str(&format!(
                    "<span class=\"message\">{}</span>",
                    escape_html(&finding.message)
                ));
                if let Some(target) = &finding.target {
                    out.push_str(&format!(
                        " <code class=\"target\">{}</code>",
                        escape_html(target)
                    ));
                }
                if let Some(reason) = &reported.suppression_reason {
                    out.push_str(&format!(
                        "<div class=\"sub\">reason: {}</div>",
                        escape_html(reason)
                    ));
                }
                if let Some(remediation) = &reported.remediation {
                    out.push_str(&format!(
                        "<div class=\"sub guidance\">guidance: {}</div>",
                        escape_html(remediation)
                    ));
                }
                out.push_str("</li>\n");
            }

            out.push_str("</ul>\n</details>\n");
        }

        if let Some(bd) = &self.baseline_diff {
            if !bd.resolved.is_empty() {
                out.push_str(
                    "<details class=\"category\">\n<summary>✅ Resolved Since Baseline \
                              <span class=\"count\">",
                );
                out.push_str(&bd.resolved.len().to_string());
                out.push_str("</span></summary>\n<ul class=\"findings\">\n");
                for r in &bd.resolved {
                    out.push_str(&format!(
                        "<li class=\"finding resolved\">{}</li>\n",
                        escape_html(&r.message)
                    ));
                }
                out.push_str("</ul>\n</details>\n");
            }
        }

        if !self.is_safe {
            out.push_str(
                "<p class=\"banner fail\">⚠️ ACTION REQUIRED: the new contract version \
                          modifies existing storage layouts or function interfaces. Deploying \
                          this upgrade will result in orphaned data, serialization panics, or \
                          broken integrations.</p>\n",
            );
        }

        // ── Suppression audit log ──────────────────────────────────────────
        let mut suppressed_list = Vec::new();
        for group in self.findings_by_category.values() {
            for reported in group {
                if reported.suppressed {
                    suppressed_list.push(reported);
                }
            }
        }
        suppressed_list.sort_by(|a, b| {
            a.finding
                .category
                .cmp(&b.finding.category)
                .then_with(|| a.finding.message.cmp(&b.finding.message))
        });

        if !suppressed_list.is_empty() {
            out.push_str(
                "<details class=\"category\" open>\n<summary>🔕 Applied Suppressions \
                          Audit Log <span class=\"count\">",
            );
            out.push_str(&suppressed_list.len().to_string());
            out.push_str("</span></summary>\n");
            out.push_str(
                "<div class=\"table-scroll\"><table>\n<thead><tr>\
                          <th>Category</th><th>Target</th><th>Fingerprint</th>\
                          <th>Author</th><th>Expiry</th><th>Reason</th                          </tr></thead>\n<tbody>\n",
            );
            for reported in suppressed_list {
                let f = &reported.finding;
                out.push_str(&format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td>\
                     <td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape_html(&f.category),
                    escape_html(f.target.as_deref().unwrap_or("-")),
                    escape_html(reported.suppression_fingerprint.as_deref().unwrap_or("-")),
                    escape_html(reported.suppression_author.as_deref().unwrap_or("-")),
                    escape_html(reported.suppression_expiry.as_deref().unwrap_or("-")),
                    escape_html(reported.suppression_reason.as_deref().unwrap_or("-")),
                ));
            }
            out.push_str("</tbody>\n</table></div>\n</details>\n");
        }

        self.append_metrics_html(&mut out);
        out.push_str("</section>\n");
        out
    }

    /// Append the informational build-metrics table to HTML output.
    fn append_metrics_html(&self, out: &mut String) {
        let Some(ref m) = self.metrics else { return };
        let fmt_count = |d: i64| {
            if d >= 0 {
                format!("+{d}")
            } else {
                d.to_string()
            }
        };
        out.push_str("<details class=\"category\">\n<summary>📊 Build Metrics</summary>\n");
        out.push_str(
            "<div class=\"table-scroll\"><table>\n<thead><tr><th>Metric</th><th>Old</th>\
                      <th>New</th><th>Delta</th></tr></thead>\n<tbody>\n",
        );
        out.push_str(&format!(
            "<tr><td>WASM size</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            BuildMetrics::format_bytes(m.old_size_bytes),
            BuildMetrics::format_bytes(m.new_size_bytes),
            BuildMetrics::format_delta(m.size_delta_bytes),
        ));
        for (label, old, new) in [
            ("Functions", m.old_function_count, m.new_function_count),
            ("Structs", m.old_struct_count, m.new_struct_count),
            ("Enums", m.old_enum_count, m.new_enum_count),
            ("Unions", m.old_union_count, m.new_union_count),
            (
                "Error Enums",
                m.old_error_enum_count,
                m.new_error_enum_count,
            ),
        ] {
            out.push_str(&format!(
                "<tr><td>{label}</td><td>{old}</td><td>{new}</td><td>{}</td></tr>\n",
                fmt_count(new as i64 - old as i64)
            ));
        }
        out.push_str("</tbody>\n</table></div>\n</details>\n");
    }

    /// Apply a category filter to the report, removing findings from
    /// excluded / non-included categories. The original `total_findings`
    /// count is preserved; the difference is reported via `filtered_count`.
    /// The safety verdict is recalculated based on remaining findings.
    pub fn apply_category_filter(&mut self, filter: &CategoryFilter) {
        let mut new_categories: HashMap<String, Vec<ReportedFinding>> = HashMap::new();
        let mut filtered = 0usize;
        let mut critical = 0usize;
        let mut warning = 0usize;
        let mut info = 0usize;
        let mut failing_critical = 0usize;
        let mut failing_warning = 0usize;
        let mut engine_failing_critical = 0usize;
        let mut engine_failing_warning = 0usize;
        let mut overridden = 0usize;

        for (category, findings) in &self.findings_by_category {
            if filter.should_include(category) {
                for rf in findings {
                    match rf.finding.severity {
                        Severity::Critical => critical += 1,
                        Severity::Warning => warning += 1,
                        Severity::Info => info += 1,
                    }
                    if rf.original_severity.is_some() {
                        overridden += 1;
                    }
                    if !rf.suppressed {
                        match rf.finding.severity {
                            Severity::Critical => failing_critical += 1,
                            Severity::Warning => failing_warning += 1,
                            _ => {}
                        }
                        // What the engine would have counted, so the
                        // "verdict changed by override" claim stays accurate
                        // for the filtered subset rather than describing a set
                        // of findings this report no longer shows.
                        match rf
                            .original_severity
                            .as_ref()
                            .unwrap_or(&rf.finding.severity)
                        {
                            Severity::Critical => engine_failing_critical += 1,
                            Severity::Warning => engine_failing_warning += 1,
                            _ => {}
                        }
                    }
                }
                new_categories.insert(category.to_string(), findings.clone());
            } else {
                filtered += findings.len();
            }
        }

        self.filtered_count = filtered;
        self.critical_count = critical;
        self.warning_count = warning;
        self.info_count = info;
        self.severity_overridden_count = overridden;
        self.findings_by_category = new_categories;
        let verdict = |c: usize, w: usize| {
            if self.strict {
                c == 0 && w == 0
            } else {
                c == 0
            }
        };
        self.is_safe = verdict(failing_critical, failing_warning);
        self.verdict_changed_by_override =
            self.is_safe != verdict(engine_failing_critical, engine_failing_warning);
        self.category_filter = filter.clone();
    }
}

/// Escape text for safe interpolation into HTML element content or a quoted
/// attribute value.
///
/// Finding messages embed type, field, parameter, and function names read
/// straight out of a WASM binary the tool does not trust. Emitting those
/// unescaped would make the report an injection vector into whoever opens it,
/// so every WASM-derived string passes through here — including ones that look
/// harmless, since the guarantee has to hold without case-by-case reasoning.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape a string for use as XML text or as an attribute value.
///
/// Same five entities as [`escape_html`], plus one thing XML needs that HTML
/// does not: control characters outside the XML 1.0 legal set are dropped
/// rather than emitted. Finding messages carry type, field, and function names
/// read straight out of an untrusted WASM binary, and a stray control byte in
/// one of those would make the whole document unparseable — which in a CI
/// test-report UI shows up as a missing report, not as an error.
pub fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 => {}
            c if (0x7f..=0x9f).contains(&(c as u32)) => {}
            c => out.push(c),
        }
    }
    out
}

/// Wrap one or more rendered `<testsuite>` elements in a complete JUnit XML
/// document. Suites carry their own counts, so the root element only names the
/// run — every common CI ingester reads the per-suite attributes.
pub fn junit_document(name: &str, suites: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"{}\">\n{}</testsuites>\n",
        escape_xml(name),
        suites,
    )
}

/// One `<li>` tile in the counts row.
fn stat_tile(label: &str, value: usize, class: &str) -> String {
    format!(
        "<li class=\"stat stat-{class}\"><span class=\"stat-value\">{value}</span>\
         <span class=\"stat-label\">{}</span></li>\n",
        escape_html(label)
    )
}

/// Wrap rendered report sections in a complete, standalone HTML document.
///
/// The result is deliberately self-contained: CSS and the severity-filter
/// script are inline and there are no image, font, or script URLs of any kind.
/// These reports are served from artifact storage, which is often opened
/// offline or behind a strict content policy, so anything fetched over the
/// network would silently degrade the page for exactly the readers it targets.
pub fn html_document(title: &str, body: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #1b1f24; --muted: #57606a; --line: #d8dee4; --panel: #f6f8fa;
  --critical: #cf222e; --warning: #9a6700; --info: #0969da; --pass: #1a7f37;
  --overridden: #8250df;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #30363d; --panel: #161b22;
    --critical: #ff7b72; --warning: #d29922; --info: #79c0ff; --pass: #3fb950;
    --overridden: #d2a8ff;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 2rem 1rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}}
main {{ max-width: 60rem; margin: 0 auto; }}
h1, h2 {{ line-height: 1.25; }}
h1 {{ font-size: 1.6rem; }}
h2 {{ font-size: 1.25rem; margin-top: 2rem; }}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.875em; background: var(--panel); padding: 0.1em 0.35em;
  border-radius: 4px; overflow-wrap: anywhere;
}}
.banner {{
  padding: 0.7rem 0.9rem; border-radius: 6px; border: 1px solid var(--line);
  font-weight: 600; background: var(--panel);
}}
.banner.pass {{ color: var(--pass); border-color: var(--pass); }}
.banner.fail {{ color: var(--critical); border-color: var(--critical); }}
.banner.warn, .banner.strict {{ color: var(--warning); border-color: var(--warning); }}
.banner.override-verdict {{ color: var(--overridden); border-color: var(--overridden); }}
.scope {{ color: var(--muted); font-size: 0.9rem; margin: 0.4rem 0; }}
.scope.gap {{ color: var(--warning); }}
.note, .meta {{ color: var(--muted); font-size: 0.9rem; }}
.empty {{ color: var(--pass); font-weight: 600; }}
.stats {{ display: flex; flex-wrap: wrap; gap: 0.6rem; list-style: none; padding: 0; }}
.stat {{
  flex: 1 1 7rem; padding: 0.6rem 0.8rem; border: 1px solid var(--line);
  border-radius: 6px; background: var(--panel);
}}
.stat-value {{ display: block; font-size: 1.5rem; font-weight: 700; }}
.stat-label {{ display: block; font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
.stat-critical .stat-value {{ color: var(--critical); }}
.stat-warning .stat-value {{ color: var(--warning); }}
.stat-info .stat-value {{ color: var(--info); }}
.stat-overridden .stat-value {{ color: var(--overridden); }}
.controls {{
  position: sticky; top: 0; z-index: 1; display: flex; flex-wrap: wrap; gap: 1rem;
  padding: 0.7rem 0.9rem; margin-bottom: 1.5rem; background: var(--panel);
  border: 1px solid var(--line); border-radius: 6px; font-size: 0.9rem;
}}
.controls label {{ cursor: pointer; user-select: none; }}
details.category {{
  border: 1px solid var(--line); border-radius: 6px; margin: 0.6rem 0; background: var(--panel);
}}
details.category > summary {{
  cursor: pointer; padding: 0.6rem 0.9rem; font-weight: 600; list-style-position: inside;
}}
.count {{
  display: inline-block; min-width: 1.5rem; padding: 0 0.4rem; margin-left: 0.4rem;
  border-radius: 999px; background: var(--bg); border: 1px solid var(--line);
  font-size: 0.8rem; text-align: center; color: var(--muted);
}}
ul.findings {{ list-style: none; margin: 0; padding: 0 0.9rem 0.8rem; }}
li.finding {{
  padding: 0.5rem 0; border-top: 1px solid var(--line); overflow-wrap: anywhere;
}}
li.finding.suppressed {{ opacity: 0.65; }}
.badge {{
  display: inline-block; padding: 0.05em 0.5em; border-radius: 999px;
  font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.03em; border: 1px solid currentColor; vertical-align: middle;
}}
.badge-critical {{ color: var(--critical); }}
.badge-warning {{ color: var(--warning); }}
.badge-info {{ color: var(--info); }}
.badge-suppressed, .badge-new {{ color: var(--muted); }}
.badge-overridden {{ color: var(--overridden); }}
.sub {{ color: var(--muted); font-size: 0.86rem; margin-top: 0.25rem; }}
.sub.guidance {{ color: var(--pass); }}
.table-scroll {{ overflow-x: auto; padding: 0 0.9rem 0.9rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
th, td {{ border: 1px solid var(--line); padding: 0.4rem 0.6rem; text-align: left; }}
th {{ background: var(--bg); }}
section.report {{ margin-bottom: 2.5rem; }}
body.hide-critical li.sev-critical,
body.hide-warning li.sev-warning,
body.hide-info li.sev-info {{ display: none; }}
</style>
</head>
<body>
<main>
<div class="controls" role="group" aria-label="Filter findings by severity">
  <span>Show:</span>
  <label><input type="checkbox" class="sev-toggle" data-sev="critical" checked> Critical</label>
  <label><input type="checkbox" class="sev-toggle" data-sev="warning" checked> Warning</label>
  <label><input type="checkbox" class="sev-toggle" data-sev="info" checked> Info</label>
</div>
{body}
</main>
<script>
document.addEventListener('change', function (event) {{
  var box = event.target;
  if (!box.classList || !box.classList.contains('sev-toggle')) return;
  document.body.classList.toggle('hide-' + box.dataset.sev, !box.checked);
}});
</script>
</body>
</html>
"##,
        title = escape_html(title),
        body = body,
    )
}

/// All known finding categories used by the analysis engine.
pub const KNOWN_CATEGORIES: &[&str] = &[
    "Environment",
    "Function Removed",
    "Function Documentation Changed",
    "Function Added",
    "Function Signature Changed",
    "Parameter Renamed",
    "Parameter Reordered",
    "Parameter Type Changed",
    "Return Type Changed",
    "Event Definition Removed",
    "Struct Removed",
    "Struct Documentation Changed",
    "Struct Added",
    "Struct Field Removed",
    "Event Field Removed",
    "Struct Field Reordered",
    "Event Field Reordered",
    "Struct Field Type Changed",
    "Event Field Type Changed",
    "Struct Field Added",
    "Event Enum Removed",
    "Enum Removed",
    "Enum Documentation Changed",
    "Enum Added",
    "Enum Case Removed",
    "Event Enum Case Removed",
    "Enum Case Value Changed",
    "Event Enum Case Value Changed",
    "Enum Case Added",
    "Event Enum Case Added",
    "Union Removed",
    "Union Added",
    "Union Case Removed",
    "Union Case Reordered",
    "Union Case Type Changed",
    "Union Case Added",
    "Error Enum Removed",
    "Error Enum Added",
    "Error Enum Case Removed",
    "Error Enum Case Value Changed",
    "Error Enum Case Added",
    "Cascading Layout Break",
];

/// Validate that the given category name is a known category.
/// Returns an error message listing unknown categories if any are invalid.
pub fn validate_categories(categories: &[String]) -> Result<(), Vec<String>> {
    let known: HashSet<&str> = KNOWN_CATEGORIES.iter().copied().collect();
    let unknown: Vec<String> = categories
        .iter()
        .filter(|c| !known.contains(c.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(unknown)
    }
}

/// A filter that restricts which finding categories are included in the report.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct CategoryFilter {
    /// Only include these categories (empty = no inclusion restriction).
    pub include: Option<HashSet<String>>,
    /// Exclude these categories.
    pub exclude: HashSet<String>,
}

impl CategoryFilter {
    /// Returns `true` if the category should be included in the report output.
    pub fn should_include(&self, category: &str) -> bool {
        if self.exclude.contains(category) {
            return false;
        }
        if let Some(ref include) = self.include {
            return include.contains(category);
        }
        true
    }
}

/// Returns remediation/explanation guidance for a given stable rule id.
pub fn get_remediation_guidance(rule_id: &str) -> Option<&'static str> {
    guidance_for_rule_id(rule_id)
        .or_else(|| canonical_rule_id(rule_id).and_then(guidance_for_rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{all_rules, display_label_for_rule_id, rule_by_id};

    #[test]
    fn every_registered_rule_has_unique_id_and_guidance() {
        let mut ids = std::collections::HashSet::new();

        for rule in all_rules() {
            assert!(ids.insert(rule.id), "duplicate rule id: {}", rule.id);
            assert_eq!(rule.label, display_label_for_rule_id(rule.id).unwrap());
            assert_eq!(rule.guidance, guidance_for_rule_id(rule.id).unwrap());
            assert_eq!(rule.severity, rule_by_id(rule.id).unwrap().severity);
        }
    }

    #[test]
    fn every_category_in_the_inventory_has_guidance() {
        for cat in crate::diff::ALL_CATEGORIES {
            assert!(
                get_remediation_guidance(cat).is_some(),
                "Category '{cat}' does not have remediation guidance!"
            );
        }
    }

    #[test]
    fn no_category_is_event_flavored() {
        // Event-ness must live in `classification`, never in the suppression
        // key, so that reclassifying a type cannot move a finding out from
        // under an existing suppression rule.
        for cat in crate::diff::ALL_CATEGORIES {
            assert!(
                !cat.contains("Event") || cat.starts_with("Error Enum"),
                "Category '{cat}' encodes classification in the suppression key"
            );
        }
    }

    /// The inventory is only trustworthy if it actually covers what `diff.rs`
    /// emits, so scan the source for category literals and require each one to
    /// be listed. This catches a new category added without guidance.
    #[test]
    fn every_emitted_category_is_in_the_inventory() {
        let diff_rs_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("diff.rs");
        let content = std::fs::read_to_string(diff_rs_path).expect("Failed to read src/diff.rs");

        let mut checked_categories = std::collections::HashSet::new();

        for line in content.lines() {
            if line.contains("category:") {
                // If it is ENVIRONMENT_CATEGORY
                if line.contains("ENVIRONMENT_CATEGORY") {
                    checked_categories.insert("Environment".to_string());
                    continue;
                }
                // Constant-referenced duplicate/conflict categories
                if line.contains("SPEC_CONFLICT_CATEGORY") {
                    checked_categories.insert("Spec Entry Conflict".to_string());
                    continue;
                }
                if line.contains("SPEC_DUPLICATE_CATEGORY") {
                    checked_categories.insert("Spec Entry Duplicate".to_string());
                    continue;
                }

                // Find all string literals in the line and check each one.
                let mut chars = line.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        let mut literal = String::new();
                        while let Some(&nc) = chars.peek() {
                            if nc == '"' {
                                chars.next();
                                break;
                            }
                            literal.push(chars.next().unwrap());
                        }
                        if literal.is_empty() {
                            continue;
                        }

                        // A literal that *looks* like a category (Title Case
                        // words, no punctuation) but is not in the inventory is
                        // a bug.
                        let looks_like_category = literal.len() > 3
                            && literal.split(' ').count() >= 2
                            && literal
                                .split(' ')
                                .all(|w| w.chars().next().is_some_and(|c| c.is_ascii_uppercase()));
                        assert!(
                            !looks_like_category
                                || crate::diff::ALL_CATEGORIES.contains(&literal.as_str())
                                || literal == "TOTALLY CUSTOM CATEGORY",
                            "'{literal}' looks like a category but is not in diff::ALL_CATEGORIES"
                        );

                        // If it's a format string like "{} Removed", expand it
                        // into the concrete categories the code can emit.
                        if literal.contains("{}") {
                            let suffixes = vec![
                                "Removed",
                                "Reordered",
                                "Type Changed",
                                "Value Changed",
                                "Added",
                            ];
                            for suffix in suffixes {
                                if literal == format!("{{}} {}", suffix) {
                                    let prefixes = match suffix {
                                        "Reordered" | "Type Changed" => {
                                            vec!["Struct Field", "Event Field"]
                                        }
                                        "Value Changed" => {
                                            vec!["Enum Case", "Event Enum Case"]
                                        }
                                        "Added" => vec![
                                            "Struct Field",
                                            "Event Schema",
                                            "Enum Case",
                                            "Event Enum Case",
                                        ],
                                        "Removed" => vec![
                                            "Struct Field",
                                            "Event Field",
                                            "Enum Case",
                                            "Event Enum Case",
                                        ],
                                        _ => unreachable!(),
                                    };
                                    for prefix in prefixes {
                                        checked_categories.insert(format!("{} {}", prefix, suffix));
                                    }
                                }
                            }
                        } else {
                            checked_categories.insert(literal);
                        }
                    }
                }
            }
        }

        assert!(
            checked_categories.len() > 20,
            "sanity check: expected to find most categories in the source, found {}",
            checked_categories.len()
        );
    }

    #[test]
    fn test_recommended_semver_bump() {
        let mut report = SafetyReport {
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            filtered_count: 0,
            severity_overridden_count: 0,
            verdict_changed_by_override: false,
            suppressed_critical_count: 0,
            total_findings: 0,
            is_safe: true,
            findings_by_category: std::collections::HashMap::new(),
            strict: false,
            baseline_source: None,
            verified_code_hash: None,
            category_filter: CategoryFilter::default(),
            scope: AnalysisScope::default(),
            old_spec_summary: None,
            new_spec_summary: None,
            metrics: None,
            settings: ReportSettings {
                strict: false,
                explain: false,
                max_suppressions: None,
                allow_targetless: None,
                max_xdr_depth: 0,
                max_xdr_len: 0,
                max_entries: 0,
                max_walk_depth: 0,
            },
            unmatched_suppressions: Vec::new(),
            baseline_diff: None,
            diff_types: false,
            use_color: false,
        };

        // Identical upgrade -> patch
        assert_eq!(report.recommended_bump(), "patch");

        // Info findings -> minor
        report.info_count = 1;
        assert_eq!(report.recommended_bump(), "minor");

        // Warning findings -> minor
        report.info_count = 0;
        report.warning_count = 1;
        assert_eq!(report.recommended_bump(), "minor");

        // Critical findings -> major (even if other findings are present)
        report.critical_count = 1;
        assert_eq!(report.recommended_bump(), "major");
    }

    #[test]
    fn categories_are_sorted_by_severity_then_name() {
        let report = SafetyReport::new(&DiffReport {
            findings: vec![
                Finding {
                    severity: Severity::Info,
                    category: "Environment".to_string(),
                    message: "Environment metadata changed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Warning,
                    category: "Function Renamed".to_string(),
                    message: "Function renamed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Critical,
                    category: "Struct Removed".to_string(),
                    message: "Struct removed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Info,
                    category: "Enum Added".to_string(),
                    message: "Enum added".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
            ],
        });

        let sorted: Vec<&str> = report
            .categories_sorted_by_severity()
            .iter()
            .map(|s| s.as_str())
            .collect();

        assert_eq!(
            sorted,
            vec![
                "Struct Removed",
                "Function Renamed",
                "Enum Added",
                "Environment"
            ]
        );
    }

    #[test]
    fn severity_order_applies_in_text_and_markdown_output() {
        let report = SafetyReport::new(&DiffReport {
            findings: vec![
                Finding {
                    severity: Severity::Info,
                    category: "Environment".to_string(),
                    message: "Environment metadata changed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Warning,
                    category: "Function Renamed".to_string(),
                    message: "Function renamed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Critical,
                    category: "Struct Removed".to_string(),
                    message: "Struct removed".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
                Finding {
                    severity: Severity::Info,
                    category: "Enum Added".to_string(),
                    message: "Enum added".to_string(),
                    type_name: None,
                    target: None,
                    classification: None,
                },
            ],
        });

        let text = report.generate_summary_text(false);
        let struct_pos = text.find("--- [STRUCT REMOVED] ---").unwrap();
        let function_pos = text.find("--- [FUNCTION RENAMED] ---").unwrap();
        let enum_pos = text.find("--- [ENUM ADDED] ---").unwrap();
        let env_pos = text.find("--- [ENVIRONMENT] ---").unwrap();
        assert!(struct_pos < function_pos && function_pos < enum_pos && enum_pos < env_pos);

        let markdown = report.generate_summary_markdown();
        let struct_pos = markdown.find("### Struct Removed").unwrap();
        let function_pos = markdown.find("### Function Renamed").unwrap();
        let enum_pos = markdown.find("### Enum Added").unwrap();
        let env_pos = markdown.find("### Environment").unwrap();
        assert!(struct_pos < function_pos && function_pos < enum_pos && enum_pos < env_pos);
    }
}
