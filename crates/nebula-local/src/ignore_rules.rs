use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobMatcher};
use std::path::Path;

/// Repository-relative paths that are always excluded from scans, regardless
/// of user configuration. These protect Nebula's own metadata and the most
/// common build/tooling directories from ever being tracked.
pub const DEFAULT_PATTERNS: &[&str] = &[
    ".nebula",
    ".git",
    ".agents",
    ".cursor",
    ".mastra",
    "target",
    "node_modules",
    ".next",
    ".turbo",
    ".DS_Store",
    "tsconfig.tsbuildinfo",
    "zero.db",
    "zero.db-shm",
    "zero.db-wal",
    "zero.db-wal2",
];

/// The name of the optional per-repository ignore file, using gitignore-style
/// pattern syntax.
pub const IGNORE_FILE_NAME: &str = ".nebignore";

struct IgnoreRule {
    matcher: GlobMatcher,
    negate: bool,
    dir_only: bool,
}

/// Gitignore-style matcher built from Nebula's built-in defaults, the
/// `ignore` array in `.nebula/config.json`, and an optional root `.nebignore`
/// file. Rules are evaluated in order and the last matching rule wins, which
/// lets later sources (config, then `.nebignore`) override earlier ones,
/// including un-ignoring a default via a leading `!`.
pub struct IgnoreMatcher {
    rules: Vec<IgnoreRule>,
}

impl IgnoreMatcher {
    pub fn build<'a>(sources: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let mut rules = Vec::new();
        for source in sources {
            for line in source.lines() {
                if let Some(rule) = parse_rule(line)? {
                    rules.push(rule);
                }
            }
        }
        Ok(Self { rules })
    }

    /// Returns true if `relative` (a path relative to the repository root)
    /// should be excluded from scans. `is_dir` gates directory-only patterns
    /// (those ending in `/`).
    pub fn is_ignored(&self, relative: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            if rule.matcher.is_match(relative) {
                ignored = !rule.negate;
            }
        }
        ignored
    }
}

fn parse_rule(line: &str) -> Result<Option<IgnoreRule>> {
    let line = line.trim_end();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let negate = trimmed.starts_with('!');
    let pattern = if negate { &trimmed[1..] } else { trimmed };

    let dir_only = pattern.ends_with('/') && pattern.len() > 1;
    let pattern = pattern.trim_end_matches('/');
    // Gitignore semantics: a pattern anchors to the ignore file's directory
    // if it contains a `/` ANYWHERE other than a single trailing slash
    // already stripped above — including a lone leading slash ("/conductor"
    // anchors to root just like "services/conductor" anchors relative to
    // its own path). Checking `contains('/')` only *after* stripping the
    // leading slash missed the leading-slash-only case, silently turning
    // "/conductor" into an unanchored "**/conductor" that matched
    // `services/conductor` anywhere in the tree instead of only a
    // root-level `conductor`.
    let anchored = pattern.starts_with('/') || pattern.trim_start_matches('/').contains('/');
    let pattern = pattern.trim_start_matches('/');

    let glob_str = if anchored {
        pattern.to_string()
    } else {
        format!("**/{pattern}")
    };

    // literal_separator(true) keeps a bare `*` from crossing a `/`, matching
    // standard gitignore semantics (only `**` spans directory boundaries).
    // Without it, globset's default lets `*` match `/` too, so a pattern
    // like "services/*/conductor" would also match a totally different,
    // deeper path such as "services/conductor/internal/conductor" — the
    // `*` silently absorbing "conductor/internal" instead of exactly one
    // path segment.
    let matcher = GlobBuilder::new(&glob_str)
        .literal_separator(true)
        .build()
        .with_context(|| format!("invalid ignore pattern: {line}"))?
        .compile_matcher();

    Ok(Some(IgnoreRule {
        matcher,
        negate,
        dir_only,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_slash_pattern_anchors_to_root_only() {
        let matcher = IgnoreMatcher::build(["/conductor"]).unwrap();
        assert!(matcher.is_ignored(Path::new("conductor"), true));
        assert!(!matcher.is_ignored(Path::new("services/conductor"), true));
        assert!(!matcher.is_ignored(Path::new("services/conductor/main.go"), false));
    }

    #[test]
    fn unanchored_pattern_matches_at_any_depth() {
        let matcher = IgnoreMatcher::build(["conductor"]).unwrap();
        assert!(matcher.is_ignored(Path::new("conductor"), true));
        assert!(matcher.is_ignored(Path::new("services/conductor"), true));
    }

    #[test]
    fn mid_path_slash_pattern_anchors_to_that_exact_path() {
        let matcher = IgnoreMatcher::build(["services/conductor"]).unwrap();
        assert!(matcher.is_ignored(Path::new("services/conductor"), true));
        assert!(!matcher.is_ignored(Path::new("apps/services/conductor"), true));
        assert!(!matcher.is_ignored(Path::new("conductor"), true));
    }

    #[test]
    fn single_wildcard_does_not_cross_path_separators() {
        let matcher = IgnoreMatcher::build(["services/*/conductor"]).unwrap();
        assert!(matcher.is_ignored(Path::new("services/builder/conductor"), true));
        assert!(!matcher.is_ignored(Path::new("services/conductor/internal/conductor"), true));
    }
}
