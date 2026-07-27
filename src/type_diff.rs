//! Aligned, highlighted diff view for a pair of type-signature strings.
//!
//! The primary entry point is [`render_type_diff`]. It locates the longest
//! common prefix and suffix shared by the old and new signatures and
//! highlights only the portion that actually changed, keeping the unchanged
//! flanks visually stable so the reader's eye goes straight to the delta.
//!
//! # Output format
//!
//! ```text
//! - Map<String, u32>       ← old, changed span red
//! + Map<String, u64>       ← new, changed span green
//! ```
//!
//! When color is disabled the changed span is wrapped in square brackets
//! instead:
//!
//! ```text
//! - Map<String, [u32]>
//! + Map<String, [u64]>
//! ```
//!
//! # Integration
//!
//! Called from [`crate::report::SafetyReport::generate_summary_text`] when
//! `--diff-types` is passed.  The rendering deliberately does not affect
//! `--format json` or `--format markdown` — those are consumed by machines
//! and PR bots that already have the raw type strings.

use colored::Colorize;

/// Render an aligned, highlighted two-line diff of `old_ty` and `new_ty`.
///
/// Returns a `String` of the form:
///
/// ```text
///     - <old with changed span highlighted>
///     + <new with changed span highlighted>
/// ```
///
/// The four-space indent matches the `↳ guidance:` block so the diff sits
/// visually underneath its finding.
///
/// When `use_color` is `false` the changed span is wrapped in `[…]` instead
/// of ANSI codes, making the output deterministic and grep-friendly.
pub fn render_type_diff(old_ty: &str, new_ty: &str, use_color: bool) -> String {
    let (prefix_len, suffix_len) = common_span(old_ty, new_ty);

    let old_mid = &old_ty[prefix_len..old_ty.len() - suffix_len];
    let new_mid = &new_ty[prefix_len..new_ty.len() - suffix_len];

    let prefix = &old_ty[..prefix_len];
    let suffix = &old_ty[old_ty.len() - suffix_len..];

    let (old_line, new_line) = if use_color {
        (
            format!("{}{}{}", prefix, old_mid.red().bold(), suffix),
            format!("{}{}{}", prefix, new_mid.green().bold(), suffix),
        )
    } else {
        (
            format!("{}[{}]{}", prefix, old_mid, suffix),
            format!("{}[{}]{}", prefix, new_mid, suffix),
        )
    };

    if use_color {
        format!(
            "    {} {}\n    {} {}\n",
            "-".red().bold(),
            old_line,
            "+".green().bold(),
            new_line,
        )
    } else {
        format!("    - {}\n    + {}\n", old_line, new_line)
    }
}

/// Compute `(prefix_len, suffix_len)` in bytes: the number of leading bytes
/// shared by `a` and `b`, and the number of trailing bytes shared by `a` and
/// `b`, with the constraint that `prefix_len + suffix_len <= min(a.len(), b.len())`.
///
/// Works on UTF-8 character boundaries so the result can safely be used as a
/// slice index.
fn common_span(a: &str, b: &str) -> (usize, usize) {
    // Collect char boundary positions for both strings.
    let a_chars: Vec<(usize, char)> = a.char_indices().collect();
    let b_chars: Vec<(usize, char)> = b.char_indices().collect();

    // Longest common prefix (by character, not byte).
    let prefix_chars = a_chars
        .iter()
        .zip(b_chars.iter())
        .take_while(|((_, ca), (_, cb))| ca == cb)
        .count();

    // Longest common suffix, bounded so it does not overlap the prefix.
    let a_rev: Vec<char> = a.chars().rev().collect();
    let b_rev: Vec<char> = b.chars().rev().collect();

    let max_suffix = a_chars.len().min(b_chars.len()) - prefix_chars;
    let suffix_chars = a_rev
        .iter()
        .zip(b_rev.iter())
        .take(max_suffix)
        .take_while(|(ca, cb)| ca == cb)
        .count();

    // Convert character counts back to byte offsets.
    let prefix_len = if prefix_chars == 0 {
        0
    } else {
        // Byte offset of the first character *after* the shared prefix in `a`.
        a_chars
            .get(prefix_chars)
            .map(|&(off, _)| off)
            .unwrap_or(a.len())
    };

    let suffix_len = if suffix_chars == 0 {
        0
    } else {
        // Byte length of the shared suffix in `a`.
        let suffix_start_idx = a_chars.len() - suffix_chars;
        let suffix_byte_start = a_chars[suffix_start_idx].0;
        a.len() - suffix_byte_start
    };

    (prefix_len, suffix_len)
}

/// Extract the old and new type strings from a type-change finding message.
///
/// The diff engine always writes type-change messages in one of these forms:
///
/// ```text
/// … type changed from `OldType` to `NewType`.
/// … type changed from `OldType` to `NewType`. Detail sentence.
/// ```
///
/// Returns `Some((old, new))` when both backtick-quoted tokens are found,
/// `None` otherwise (so callers degrade silently for non-type-change findings).
pub fn extract_type_pair(message: &str) -> Option<(String, String)> {
    // Find the pattern "from `...` to `...`".
    let from_idx = message.find("from `")?;
    let after_from = &message[from_idx + 6..]; // skip "from `"
    let old_end = after_from.find('`')?;
    let old_ty = &after_from[..old_end];

    let to_idx = after_from[old_end + 1..].find("to `")?;
    let after_to = &after_from[old_end + 1 + to_idx + 4..]; // skip "to `"
    let new_end = after_to.find('`')?;
    let new_ty = &after_to[..new_end];

    if old_ty.is_empty() || new_ty.is_empty() {
        return None;
    }

    Some((old_ty.to_string(), new_ty.to_string()))
}

/// Return `true` when `category` is a type-change category whose message
/// carries an old/new type pair in the `from \`…\` to \`…\`` format.
pub fn is_type_change_category(category: &str) -> bool {
    matches!(
        category,
        "Parameter Type Changed"
            | "Parameter Type Widened"
            | "Parameter Type Narrowed"
            | "Parameter Type Signedness Changed"
            | "Return Type Changed"
            | "Return Type Widened"
            | "Return Type Narrowed"
            | "Return Type Signedness Changed"
            | "Struct Field Type Changed"
            | "Struct Field Type Widened"
            | "Struct Field Type Narrowed"
            | "Struct Field Type Signedness Changed"
            | "Union Case Type Changed"
            | "Union Case Type Widened"
            | "Union Case Type Narrowed"
            | "Union Case Type Signedness Changed"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_type_pair ────────────────────────────────────────────────────

    #[test]
    fn extracts_simple_types() {
        let msg = "Function 'f': parameter 0 ('x') type changed from `u32` to `u64`.";
        let pair = extract_type_pair(msg).expect("should extract");
        assert_eq!(pair.0, "u32");
        assert_eq!(pair.1, "u64");
    }

    #[test]
    fn extracts_generic_types() {
        let msg =
            "Struct 'S': field 'v' type changed from `Map<String, u32>` to `Map<String, u64>`.";
        let pair = extract_type_pair(msg).expect("should extract");
        assert_eq!(pair.0, "Map<String, u32>");
        assert_eq!(pair.1, "Map<String, u64>");
    }

    #[test]
    fn extracts_with_trailing_detail_sentence() {
        let msg = "… type changed from `i32` to `i64`. This is a widening numeric conversion: …";
        let pair = extract_type_pair(msg).expect("should extract");
        assert_eq!(pair.0, "i32");
        assert_eq!(pair.1, "i64");
    }

    #[test]
    fn returns_none_for_non_type_change_message() {
        let msg = "Function 'transfer' was removed. Existing callers will break.";
        assert!(extract_type_pair(msg).is_none());
    }

    // ── common_span ──────────────────────────────────────────────────────────

    #[test]
    fn common_span_identical_strings() {
        let (p, s) = common_span("u32", "u32");
        // Whole string is the prefix; suffix must not overlap.
        assert_eq!(p + s, "u32".len());
    }

    #[test]
    fn common_span_completely_different() {
        let (p, s) = common_span("bool", "Address");
        assert_eq!(p, 0);
        assert_eq!(s, 0);
    }

    #[test]
    fn common_span_shared_wrapper() {
        // "Map<String, u32>" vs "Map<String, u64>"
        // prefix = "Map<String, "  suffix = ">"
        let a = "Map<String, u32>";
        let b = "Map<String, u64>";
        let (p, s) = common_span(a, b);

        let prefix = &a[..p];
        let suffix = &a[a.len() - s..];
        let old_mid = &a[p..a.len() - s];
        let new_mid = &b[p..b.len() - s];

        assert_eq!(prefix, "Map<String, ");
        assert_eq!(old_mid, "u32");
        assert_eq!(new_mid, "u64");
        assert_eq!(suffix, ">");
    }

    #[test]
    fn common_span_prefix_only() {
        let a = "Option<u32>";
        let b = "Option<bool>";
        let (p, s) = common_span(a, b);
        assert_eq!(&a[..p], "Option<");
        assert_eq!(s, 0, "no common suffix");
    }

    #[test]
    fn common_span_suffix_only() {
        let a = "u32>";
        let b = "u64>";
        let (p, s) = common_span(a, b);
        assert_eq!(p, 0, "no common prefix");
        assert_eq!(&a[a.len() - s..], ">");
    }

    // ── render_type_diff (color OFF for determinism) ─────────────────────────

    #[test]
    fn render_marks_changed_span_with_brackets_no_color() {
        let out = render_type_diff("u32", "u64", false);
        assert!(out.contains("- [u32]"), "old line missing: {out}");
        assert!(out.contains("+ [u64]"), "new line missing: {out}");
    }

    #[test]
    fn render_preserves_common_wrapper_no_color() {
        let out = render_type_diff("Map<String, u32>", "Map<String, u64>", false);
        // Unchanged flanks must appear outside the brackets on both lines.
        assert!(
            out.contains("- Map<String, [u32]>"),
            "old wrapper not preserved: {out}"
        );
        assert!(
            out.contains("+ Map<String, [u64]>"),
            "new wrapper not preserved: {out}"
        );
    }

    #[test]
    fn render_indented_four_spaces_no_color() {
        let out = render_type_diff("u32", "u64", false);
        for line in out.lines() {
            assert!(
                line.starts_with("    "),
                "every line must be indented 4 spaces: {line:?}"
            );
        }
    }

    #[test]
    fn render_no_color_contains_no_ansi_escapes() {
        let out = render_type_diff("Map<String, u32>", "Map<String, u64>", false);
        assert!(
            !out.contains('\u{1b}'),
            "color=false must not emit ANSI codes: {out:?}"
        );
    }

    #[test]
    fn render_completely_different_types_no_color() {
        // When there is no common span, the entire string is bracketed.
        let out = render_type_diff("bool", "Address", false);
        assert!(out.contains("- [bool]"), "old: {out}");
        assert!(out.contains("+ [Address]"), "new: {out}");
    }

    #[test]
    fn render_option_wrapper_no_color() {
        let out = render_type_diff("Option<u32>", "Option<u64>", false);
        assert!(out.contains("- Option<[u32]>"), "old: {out}");
        assert!(out.contains("+ Option<[u64]>"), "new: {out}");
    }

    // ── is_type_change_category ──────────────────────────────────────────────

    #[test]
    fn type_change_categories_all_recognised() {
        let cats = [
            "Parameter Type Changed",
            "Parameter Type Widened",
            "Parameter Type Narrowed",
            "Parameter Type Signedness Changed",
            "Return Type Changed",
            "Return Type Widened",
            "Return Type Narrowed",
            "Return Type Signedness Changed",
            "Struct Field Type Changed",
            "Struct Field Type Widened",
            "Struct Field Type Narrowed",
            "Struct Field Type Signedness Changed",
            "Union Case Type Changed",
            "Union Case Type Widened",
            "Union Case Type Narrowed",
            "Union Case Type Signedness Changed",
        ];
        for cat in cats {
            assert!(is_type_change_category(cat), "not recognised: {cat}");
        }
    }

    #[test]
    fn non_type_change_categories_not_recognised() {
        assert!(!is_type_change_category("Function Removed"));
        assert!(!is_type_change_category("Struct Field Removed"));
        assert!(!is_type_change_category("Enum Case Added"));
    }
}
