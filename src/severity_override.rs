//! Per-category severity overrides, so a team can tune the gate to its own
//! risk model.
//!
//! The diff layer assigns one fixed severity per category: a parameter rename is
//! always a `Warning`, an appended struct field is always a `Warning`, a
//! documentation change is always `Info`. Those defaults are reasonable but not
//! universal. A project with no named-argument RPC clients has good reason to
//! treat a parameter rename as informational; a project with strict downstream
//! event indexing may want an appended field to fail the build outright.
//!
//! Until now the only levers were `--strict`, which promotes *every* warning at
//! once, and the suppression config, which requires naming each finding
//! individually and only ever suppresses.
//!
//! ## File format (`.safeguard.toml`)
//!
//! ```toml
//! [severity]
//! "Parameter Renamed"  = "info"      # no named-argument clients here
//! "Struct Field Added" = "critical"  # downstream indexers are strict
//! ```
//!
//! Keys accept either the display label (`"Parameter Renamed"`) or the stable
//! rule id (`"parameter_renamed"`), and the pre-1.0 event-flavored aliases keep
//! working through [`crate::suppression::stable_category`]. Values are
//! `"critical"`, `"warning"`, or `"info"`.
//!
//! ## Why unknown names are rejected
//!
//! A misspelled category would otherwise load cleanly and simply never match,
//! leaving the user believing a policy is in effect when it is not. Names are
//! therefore validated when the config is loaded, and near matches are suggested
//! so the mistake is correctable rather than merely fatal.
//!
//! ## Why the report announces overrides
//!
//! Demoting a `Critical` finding to a `Warning` can turn a failing gate green.
//! A safety tool that can be quietly reconfigured into always passing is worse
//! than no tool at all, so every overridden finding is marked as such in the
//! report, and a verdict that only passed *because* of an override says so
//! prominently. The output is the sole defence against a silent opt-out.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::diff::Severity;
use crate::rules::{lookup_rule_lenient, suggest_categories};
use crate::suppression::stable_category;

/// The `[severity]` table: a mapping from finding category to the severity this
/// project wants it reported at.
///
/// Applied in the report layer, where suppression is already applied, so the
/// diff layer stays a pure description of what changed and all policy lives in
/// one place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SeverityOverrides {
    /// Keyed by the category name exactly as the user wrote it, so error
    /// messages can quote it back verbatim.
    entries: BTreeMap<String, Severity>,
}

impl SeverityOverrides {
    /// Build from an iterator of `(category, severity)` pairs. Intended for
    /// library callers and tests; the CLI loads these from `.safeguard.toml`.
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, Severity)>,
        S: Into<String>,
    {
        Self {
            entries: pairs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every override as `(category as written, severity)`, sorted by key.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Severity)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Reject unknown or misspelled category names.
    ///
    /// Called at config-load time rather than at match time: a typo that only
    /// showed up as "this override never fired" would leave the user trusting a
    /// policy that is not actually in effect.
    pub fn validate(&self) -> Result<()> {
        for name in self.entries.keys() {
            if lookup_rule_lenient(stable_category(name)).is_some() {
                continue;
            }
            let suggestions = suggest_categories(name);
            let hint = if suggestions.is_empty() {
                "Run `soroban-upgrade-safeguard explain` to list every known category.".to_string()
            } else {
                format!(
                    "Did you mean: {}? Run `soroban-upgrade-safeguard explain` to list every \
                     known category.",
                    suggestions
                        .iter()
                        .map(|s| format!("\"{s}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            bail!("Unknown category \"{name}\" in the [severity] table. {hint}");
        }
        Ok(())
    }

    /// The severity this project wants `category` reported at, if it overrode it.
    ///
    /// Resolution goes through the canonical rule so a config keyed by rule id,
    /// display label, or a legacy event-flavored alias all match the same
    /// finding — the same equivalence the suppression matcher uses.
    pub fn severity_for(&self, category: &str) -> Option<Severity> {
        let target = lookup_rule_lenient(stable_category(category))?.id;
        self.entries.iter().find_map(|(name, severity)| {
            let matches =
                lookup_rule_lenient(stable_category(name)).is_some_and(|rule| rule.id == target);
            matches.then(|| severity.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> Result<SeverityOverrides> {
        let overrides: SeverityOverrides = toml::from_str(toml_str)?;
        overrides.validate()?;
        Ok(overrides)
    }

    #[test]
    fn resolves_by_label_rule_id_and_legacy_alias() {
        let overrides = parse(
            r#"
            "Parameter Renamed" = "info"
            struct_field_added = "critical"
            "Event Field Removed" = "warning"
            "#,
        )
        .unwrap();

        assert_eq!(
            overrides.severity_for("Parameter Renamed"),
            Some(Severity::Info)
        );
        // Keyed by rule id, looked up by the display label the diff emits.
        assert_eq!(
            overrides.severity_for("Struct Field Added"),
            Some(Severity::Critical)
        );
        // A legacy event-flavored key still governs its structural replacement.
        assert_eq!(
            overrides.severity_for("Struct Field Removed"),
            Some(Severity::Warning)
        );
        assert_eq!(overrides.severity_for("Function Removed"), None);
    }

    #[test]
    fn unknown_category_is_rejected_with_suggestions() {
        let err = parse(r#""Union Case Reorderd" = "info""#)
            .expect_err("a misspelled category must be rejected at load time");
        let message = format!("{err:#}");
        assert!(message.contains("Union Case Reorderd"), "{message}");
        assert!(message.contains("Union Case Reordered"), "{message}");
    }

    #[test]
    fn invalid_severity_value_is_rejected() {
        assert!(parse(r#""Parameter Renamed" = "blocker""#).is_err());
    }
}
