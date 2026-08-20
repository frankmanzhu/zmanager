//! Shared non-backtracking iterative wildcard matcher (CR-178, CR-179).
//!
//! Provides a consolidated greedy two-pointer matcher for both byte slices
//! (`*` / `?`) and path segment slices (`**`), eliminating exponential
//! recursion and remote `DoS` vulnerabilities from hostile patterns.

/// Generic greedy two-pointer wildcard matcher over token slices.
///
/// Runs in `O(pattern_len * value_len)` worst-case time and `O(1)` space,
/// with no recursive stack allocation.
pub(crate) fn wildcard_matches_custom<P, T, M, S>(pattern: &[P], value: &[T], is_multi_wildcard: M, matches_single: S) -> bool
where
    M: Fn(&P) -> bool,
    S: Fn(&P, &T) -> bool,
{
    let mut pattern_index = 0;
    let mut value_index = 0;
    let mut last_star = None;
    let mut star_value_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len() && is_multi_wildcard(&pattern[pattern_index]) {
            last_star = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if pattern_index < pattern.len() && matches_single(&pattern[pattern_index], &value[value_index]) {
            pattern_index += 1;
            value_index += 1;
        } else if let Some(star_index) = last_star {
            pattern_index = star_index + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && is_multi_wildcard(&pattern[pattern_index]) {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

/// Matches a byte pattern against a byte value using `*` (any sequence) and
/// `?` (any single byte).
pub(crate) fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    wildcard_matches_custom(pattern, value, |&p| p == b'*', |&p, &v| p == b'?' || p == v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn basic_wildcard_matching() {
        assert!(wildcard_matches(b"*.rs", b"main.rs"));
        assert!(wildcard_matches(b"test_?.rs", b"test_1.rs"));
        assert!(!wildcard_matches(b"test_?.rs", b"test_12.rs"));
        assert!(wildcard_matches(b"*a*b*c*", b"xxaxxbxxcxx"));
        assert!(!wildcard_matches(b"*a*b*c", b"xxaxxbxxcxx"));
        assert!(wildcard_matches(b"", b""));
        assert!(!wildcard_matches(b"a", b""));
        assert!(wildcard_matches(b"*", b""));
        assert!(wildcard_matches(b"***", b""));
        assert!(wildcard_matches(b"***", b"anything"));
    }

    #[test]
    fn cr178_pathological_byte_wildcard_no_blowup() {
        // *a x 20 + *b against a non-matching 64-byte value
        let pattern_str = format!("{}*b", "*a".repeat(20));
        let value_str = "a".repeat(60) + "c";

        let start = Instant::now();
        let matched = wildcard_matches(pattern_str.as_bytes(), value_str.as_bytes());
        let elapsed = start.elapsed();

        assert!(!matched);
        assert!(elapsed.as_millis() < 1, "CR-178 pathological matching took too long: {elapsed:?}");
    }

    #[test]
    fn cr179_pathological_segment_wildcard_no_blowup() {
        // **/a x 8 + **/b against a 32-segment non-matching path
        let pattern_segments: Vec<&str> = vec!["**", "a", "**", "a", "**", "a", "**", "a", "**", "a", "**", "a", "**", "a", "**", "a", "**", "b"];
        let path_segments: Vec<&str> = (0..32).map(|_| "a").chain(std::iter::once("c")).collect();

        let start = Instant::now();
        let matched = wildcard_matches_custom(&pattern_segments, &path_segments, |&p| p == "**", |&p, &v| p == v);
        let elapsed = start.elapsed();

        assert!(!matched);
        assert!(elapsed.as_millis() < 1, "CR-179 pathological matching took too long: {elapsed:?}");
    }
}
