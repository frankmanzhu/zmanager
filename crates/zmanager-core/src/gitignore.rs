//! `.gitignore` rule parsing and matching (CR-140).
//!
//! Extracted from the manifest planner so the gitignore engine has its own
//! home; the planner consumes it via the public items below.

use crate::manifest::{ManifestFileType, ManifestWarning};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct GitignoreRule {
    base_archive_path: String,
    pattern: String,
    polarity: GitignorePolarity,
    scope: GitignoreScope,
    anchor: GitignoreAnchor,
}

impl GitignoreRule {
    fn matches(&self, archive_path: &str, file_type: ManifestFileType) -> bool {
        let Some(relative_path) = relative_archive_path(&self.base_archive_path, archive_path) else {
            return false;
        };
        if relative_path.is_empty() {
            return false;
        }

        if self.scope == GitignoreScope::Directory {
            return self.matches_directory(relative_path);
        }

        if self.is_anchored_or_path_pattern() {
            path_pattern_matches_or_contains_descendant(relative_path, &self.pattern)
        } else {
            relative_path.split('/').any(|segment| segment_pattern_matches(segment, &self.pattern)) || file_type == ManifestFileType::Directory && segment_pattern_matches(relative_path, &self.pattern)
        }
    }

    fn matches_directory(&self, relative_path: &str) -> bool {
        if self.is_anchored_or_path_pattern() {
            return path_pattern_matches_or_contains_descendant(relative_path, &self.pattern);
        }

        relative_path.split('/').any(|segment| segment_pattern_matches(segment, &self.pattern))
    }

    fn could_include_below(&self, archive_path: &str) -> bool {
        if self.polarity != GitignorePolarity::Include {
            return false;
        }

        let Some(relative_path) = relative_archive_path(&self.base_archive_path, archive_path) else {
            return false;
        };

        if relative_path.is_empty() || !self.is_anchored_or_path_pattern() {
            return true;
        }

        self.pattern.starts_with(&format!("{relative_path}/"))
    }

    fn is_anchored_or_path_pattern(&self) -> bool {
        self.anchor == GitignoreAnchor::Anchored || self.pattern.contains('/')
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GitignorePolarity {
    Ignore,
    Include,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GitignoreScope {
    Any,
    Directory,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GitignoreAnchor {
    Anywhere,
    Anchored,
}

pub(crate) fn read_gitignore_rules(directory: &Path, base_archive_path: &str, warnings: &mut Vec<ManifestWarning>) -> Vec<GitignoreRule> {
    let gitignore_path = directory.join(".gitignore");
    let contents = match fs::read_to_string(&gitignore_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            warnings.push(ManifestWarning { source_path: gitignore_path, message: format!("failed to read .gitignore: {error}") });
            return Vec::new();
        }
    };

    contents.lines().filter_map(|line| parse_gitignore_rule(line, base_archive_path)).collect()
}

pub(crate) fn parse_gitignore_rule(line: &str, base_archive_path: &str) -> Option<GitignoreRule> {
    let mut pattern = line.trim();
    if pattern.is_empty() || pattern.starts_with('#') {
        return None;
    }

    let polarity = if pattern.starts_with('!') {
        pattern = pattern[1..].trim_start();
        GitignorePolarity::Include
    } else {
        GitignorePolarity::Ignore
    };
    if pattern.is_empty() {
        return None;
    }

    let scope = if pattern.ends_with('/') { GitignoreScope::Directory } else { GitignoreScope::Any };
    pattern = pattern.trim_end_matches('/');
    let anchor = if pattern.starts_with('/') { GitignoreAnchor::Anchored } else { GitignoreAnchor::Anywhere };
    pattern = pattern.trim_start_matches('/');

    if pattern.is_empty() {
        return None;
    }

    Some(GitignoreRule { base_archive_path: base_archive_path.to_owned(), pattern: pattern.to_owned(), polarity, scope, anchor })
}

pub(crate) fn gitignore_decision(archive_path: &str, file_type: ManifestFileType, rules: &[GitignoreRule]) -> Option<(bool, usize)> {
    rules.iter().enumerate().filter(|(_, rule)| rule.matches(archive_path, file_type)).map(|(index, rule)| (rule.polarity == GitignorePolarity::Ignore, index)).next_back()
}

pub(crate) fn gitignore_has_later_negated_descendant(archive_path: &str, rules: &[GitignoreRule], rule_index: usize) -> bool {
    rules.iter().skip(rule_index.saturating_add(1)).any(|rule| rule.could_include_below(archive_path))
}

fn relative_archive_path<'a>(base_archive_path: &str, archive_path: &'a str) -> Option<&'a str> {
    if archive_path == base_archive_path {
        return Some("");
    }

    archive_path.strip_prefix(base_archive_path).and_then(|rest| rest.strip_prefix('/'))
}

fn path_pattern_matches_or_contains_descendant(path: &str, pattern: &str) -> bool {
    path_pattern_matches(path, pattern) || path.strip_prefix(pattern).is_some_and(|rest| rest.starts_with('/'))
}

fn path_pattern_matches(path: &str, pattern: &str) -> bool {
    let path_segments = split_path_segments(path);
    let pattern_segments = split_path_segments(pattern);
    path_segments_match(&pattern_segments, &path_segments)
}

fn split_path_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|segment| !segment.is_empty()).collect()
}

fn path_segments_match(pattern: &[&str], path: &[&str]) -> bool {
    let Some((head, tail)) = pattern.split_first() else {
        return path.is_empty();
    };

    if *head == "**" {
        return (0..=path.len()).any(|index| path_segments_match(tail, &path[index..]));
    }

    let Some((path_head, path_tail)) = path.split_first() else {
        return false;
    };

    segment_pattern_matches(path_head, head) && path_segments_match(tail, path_tail)
}

fn segment_pattern_matches(value: &str, pattern: &str) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    segment_pattern_matches_bytes(value, pattern)
}

fn segment_pattern_matches_bytes(value: &[u8], pattern: &[u8]) -> bool {
    let Some((&pattern_head, pattern_tail)) = pattern.split_first() else {
        return value.is_empty();
    };

    match pattern_head {
        b'*' => segment_pattern_matches_bytes(value, pattern_tail) || !value.is_empty() && segment_pattern_matches_bytes(&value[1..], pattern),
        b'?' => !value.is_empty() && segment_pattern_matches_bytes(&value[1..], pattern_tail),
        expected => value.split_first().is_some_and(|(&actual, value_tail)| actual == expected && segment_pattern_matches_bytes(value_tail, pattern_tail)),
    }
}
